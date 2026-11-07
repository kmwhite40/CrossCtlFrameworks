"""The derived-view consumers: assurance_graph, capability_derive, fedramp20x, cr26_documents.

Each consumer recomputes a view from CURRENT records and never decides
anything a human gate owns (spec section 4). Their trigger sets are read off
the emit sites, and :func:`test_every_trigger_has_an_emitting_writer` keeps
them honest: a trigger nothing emits is a consumer that silently never runs.

Draining: the test DB is shared, and other modules leave pending jobs for these
consumers behind (every ``bus.emit`` anywhere now queues them). ``_drain`` moves
THIS test's jobs to the front of the queue and claims exactly one job per scope
of its own, so a leftover never takes this test's slot.
"""

from __future__ import annotations

import ast
import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, func, select, update

import ccf
from ccf.api.auth_deps import get_principal
from ccf.api.main import create_app
from ccf.assessment.engine import service as engine
from ccf.assurance.builder import rebuild_org
from ccf.auth import Principal
from ccf.cr26.store import put_document
from ccf.cr26.ver import seed_avi, seed_vdr, seed_ver_history
from ccf.db import session_scope
from ccf.events import consumers, derived, worker
from ccf.fedramp20x import catalog, monitoring, validation
from ccf.governance import bus, control_tests
from ccf.models import (
    KSI,
    POAM,
    Approval,
    Assessment,
    AssessmentControlResult,
    AuditLog,
    Control,
    ControlImplementation,
    Event,
    FedRAMP20xProfile,
    KSIAssessorReview,
    KSIException,
    KSIState,
    Notification,
    Organization,
    Risk,
    SSPProject,
    System,
    SystemComponent,
    Webhook,
)
from ccf.models_assurance import AssuranceNode
from ccf.models_ato import PoamExtension
from ccf.models_capability import Capability, CapabilityComponent, CapabilityControl
from ccf.models_cr26 import CertificationSnapshotFiling, Cr26Document
from ccf.models_grc import ControlTest
from ccf.models_outbox import OutboxJob

pytestmark = pytest.mark.usefixtures("fresh_engine")

PAST = datetime(2000, 1, 1, tzinfo=UTC)
DERIVED = ("assurance_graph", "capability_derive", "fedramp20x", "cr26_documents")

#: A period nobody would pick by default, so "kept the stored period" cannot
#: pass by coincidence with a computed one.
P_FROM = datetime.combine(date.today() - timedelta(days=37), datetime.min.time(), UTC)
P_TO = datetime.combine(date.today() + timedelta(days=23), datetime.min.time(), UTC)


@pytest.fixture(autouse=True)
async def _no_live_jobs_left_behind() -> AsyncIterator[None]:
    """Delete every pending/claimed job this test created (see test_event_worker)."""
    async with session_scope() as s:
        mark = (await s.execute(select(func.coalesce(func.max(OutboxJob.id), 0)))).scalar_one()
    yield
    async with session_scope() as s:
        await s.execute(
            delete(OutboxJob).where(
                OutboxJob.id > mark, OutboxJob.status.in_(("pending", "claimed"))
            )
        )


async def _mark() -> int:
    async with session_scope() as s:
        return int((await s.execute(select(func.coalesce(func.max(OutboxJob.id), 0)))).scalar_one())


async def _jobs_since(mark: int) -> list[OutboxJob]:
    async with session_scope() as s:
        return list(
            (
                await s.execute(select(OutboxJob).where(OutboxJob.id > mark).order_by(OutboxJob.id))
            ).scalars()
        )


async def _drain(mark: int) -> dict[str, int]:
    """One drain of this test's own derived jobs, with the settle delay passed."""
    async with session_scope() as s:
        mine = (
            await s.execute(
                select(OutboxJob.consumer, OutboxJob.scope_key)
                .where(
                    OutboxJob.id > mark,
                    OutboxJob.status == "pending",
                    OutboxJob.consumer.in_(DERIVED),
                )
                .distinct()
            )
        ).all()
        await s.execute(
            update(OutboxJob)
            .where(
                OutboxJob.id > mark,
                OutboxJob.status == "pending",
                OutboxJob.consumer.in_(DERIVED),
            )
            .values(next_attempt_at=PAST)
        )
    return await worker.drain_once(
        worker="t-derived",
        limit=len(mine),
        now=datetime.now(UTC) + timedelta(seconds=30),
    )


async def _system(name: str, *, twentyx: bool = False) -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=f"{name} org")
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name=name, baseline="moderate")
        s.add(system)
        await s.flush()
        if twentyx:
            s.add(FedRAMP20xProfile(system_id=system.id, service_name=name))
        return org.id, system.id


async def _poam(system_id: int, **kw: Any) -> int:
    async with session_scope() as s:
        row = POAM(
            system_id=system_id,
            title=kw.get("title", "Outdated OpenSSL"),
            severity=kw.get("severity", "high"),
            status=kw.get("status", "open"),
            identified_on=kw.get("identified_on", date.today() - timedelta(days=10)),
            due_on=kw.get("due_on"),
            scanner=kw.get("scanner", "nessus"),
            source=kw.get("source", "scan"),
            acceptance_rationale=kw.get("acceptance_rationale"),
        )
        s.add(row)
        await s.flush()
        return row.id


class _Client:
    def __init__(self, org_id: int) -> None:
        self.app = create_app()
        self.app.dependency_overrides[get_principal] = lambda: Principal(
            user_id=1, email="isso@acme.gov", org_id=org_id, role="admin"
        )

    def __call__(self) -> AsyncClient:
        return AsyncClient(transport=ASGITransport(app=self.app), base_url="http://test")


async def _document(system_id: int, kind: str) -> Cr26Document | None:
    async with session_scope() as s:
        return (
            (
                await s.execute(
                    select(Cr26Document).where(
                        Cr26Document.system_id == system_id,
                        Cr26Document.kind == kind,
                        Cr26Document.document_key.is_(None),
                    )
                )
            )
            .scalars()
            .first()
        )


# ── the trigger sets ─────────────────────────────────────────────────────────

_SRC = Path(ccf.__file__).parent

#: Emitters whose ``entity_type`` or ``verb`` is not a literal (ruling R5), by
#: the file that emits them. Each entry is re-checked: the file must still
#: carry an emit of that entity type with a computed verb.
NON_LITERAL_EMITTERS: dict[tuple[str, str], str] = {
    ("risk", "created"): "api/routes/risks.py",
    ("risk", "updated"): "api/routes/risks.py",
    ("fedramp_dependency", "linked"): "fedramp20x/marketplace.py",
    ("fedramp_dependency", "unlinked"): "fedramp20x/marketplace.py",
}


def _emit_calls() -> list[tuple[str, ast.Call]]:
    out: list[tuple[str, ast.Call]] = []
    for path in sorted(_SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
            if name == "emit":
                out.append((str(path.relative_to(_SRC)), node))
    return out


def _kw(call: ast.Call, name: str) -> ast.expr | None:
    return next((k.value for k in call.keywords if k.arg == name), None)


def _literal(node: ast.expr | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _literal_pairs() -> dict[tuple[str, str], list[tuple[str, ast.Call]]]:
    pairs: dict[tuple[str, str], list[tuple[str, ast.Call]]] = {}
    for path, call in _emit_calls():
        et, verb = _literal(_kw(call, "entity_type")), _literal(_kw(call, "verb"))
        if et is not None and verb is not None:
            pairs.setdefault((et, verb), []).append((path, call))
    return pairs


def test_each_trigger_set_is_pinned() -> None:
    """Changing a trigger set is a decision; this test makes it a visible one."""
    assert (
        frozenset(
            {
                ("system", "created"),
                ("system", "deleted"),
                ("system", "authorized"),
                ("system", "validated"),
                ("system", "drift"),
                ("system", "derived"),
                ("system", "implementations_imported"),
                ("system", "ksi_rescored"),
                ("control_implementation", "updated"),
                ("poam", "created"),
                ("poam", "updated"),
                ("poam", "closed"),
                ("poam", "extension_decided"),
                ("risk", "created"),
                ("risk", "updated"),
                ("vendor", "created"),
                ("connector_config", "synced"),
                ("scan_ingestion", "ingested"),
                ("monitoring_run", "scanned"),
                ("control_test", "tested"),
                ("ai_agent", "created"),
                ("ksi_assessor_review", "reviewed"),
                ("ksi_assessor_review", "updated"),
                ("capability", "created"),
                ("capability", "updated"),
                ("capability", "deleted"),
                ("capability", "controls_set"),
                ("capability", "components_set"),
                ("capability", "risks_set"),
                ("capability", "ksis_set"),
            }
        )
        == derived.ASSURANCE_GRAPH_TRIGGERS
    )
    assert (
        frozenset(
            {
                ("control_implementation", "updated"),
                ("system", "implementations_imported"),
                ("system", "derived"),
            }
        )
        == derived.CAPABILITY_SYSTEM_TRIGGERS
    )
    assert (
        frozenset(
            {
                ("capability", "updated"),
                ("capability", "deleted"),
                ("capability", "controls_set"),
                ("capability", "components_set"),
            }
        )
        == derived.CAPABILITY_ORG_TRIGGERS
    )
    assert (
        frozenset(
            {
                ("control_implementation", "updated"),
                ("system", "implementations_imported"),
                ("control_test", "tested"),
                ("evidence", "captured"),
                ("fedramp20x_profile", "updated"),
                ("fedramp_dependency", "created"),
                ("fedramp_dependency", "linked"),
                ("fedramp_dependency", "unlinked"),
                ("ksi_assessor_review", "reviewed"),
                ("ksi_assessor_review", "updated"),
                ("ksi_exception", "created"),
                ("ksi_exception", "updated"),
                ("system", "derived"),
            }
        )
        == derived.FEDRAMP20X_TRIGGERS
    )
    assert (
        frozenset(
            {
                ("poam", "created"),
                ("poam", "updated"),
                ("poam", "closed"),
                ("poam", "extension_decided"),
                ("vdr_evaluation", "recorded"),
                ("vdr_evaluation", "confirmed"),
                ("scan_ingestion", "ingested"),
                ("system", "vdr_due_tightened"),
                ("system", "derived"),
                ("ksi_assessor_review", "reviewed"),
                ("ksi_assessor_review", "updated"),
            }
        )
        == derived.CR26_TRIGGERS
    )


def test_every_trigger_has_an_emitting_writer() -> None:
    """Every trigger pair is emitted somewhere, with literals or by an allowlisted file."""
    literal = _literal_pairs()
    sets = {
        "assurance_graph": derived.ASSURANCE_GRAPH_TRIGGERS,
        "capability_derive": derived.CAPABILITY_SYSTEM_TRIGGERS | derived.CAPABILITY_ORG_TRIGGERS,
        "fedramp20x": derived.FEDRAMP20X_TRIGGERS,
        "cr26_documents": derived.CR26_TRIGGERS,
    }
    missing = {
        (name, pair)
        for name, triggers in sets.items()
        for pair in triggers
        if pair not in literal and pair not in NON_LITERAL_EMITTERS
    }
    assert not missing, f"triggers nothing emits: {sorted(missing)}"

    # The allowlist cannot rot: each named file still emits that entity type
    # with a computed verb.
    calls = _emit_calls()
    for (et, _verb), path in NON_LITERAL_EMITTERS.items():
        assert any(
            p == path and _literal(_kw(c, "entity_type")) == et and _literal(_kw(c, "verb")) is None
            for p, c in calls
        ), f"{path} no longer emits {et} with a computed verb"


def _names_system(et: str, call: ast.Call) -> bool:
    if et in derived.SYSTEM_ENTITY_TYPES:
        return True
    payload = _kw(call, "payload")
    return isinstance(payload, ast.Dict) and any(
        _literal(k) == "system_id" for k in payload.keys if k is not None
    )


def test_every_system_scoped_trigger_names_its_system() -> None:
    """A system-scoped consumer reads the system off the event; an emit that
    does not name it queues nothing, which is the same silent gap."""
    literal = _literal_pairs()
    system_scoped = (
        derived.CAPABILITY_SYSTEM_TRIGGERS | derived.FEDRAMP20X_TRIGGERS | derived.CR26_TRIGGERS
    )
    unnamed = sorted(
        f"{path}:{call.lineno} {pair}"
        for pair in system_scoped
        for path, call in literal.get(pair, [])
        if not _names_system(pair[0], call)
    )
    calls = _emit_calls()
    unnamed += sorted(
        f"{path}:{c.lineno} {pair}"
        for pair, path in NON_LITERAL_EMITTERS.items()
        if pair in system_scoped
        for p, c in calls
        if p == path
        and _literal(_kw(c, "entity_type")) == pair[0]
        and not _names_system(pair[0], c)
    )
    assert not unnamed, f"emits that do not name their system: {unnamed}"
    # Positive control: the scan really looks at payloads.
    poam_calls = literal[("poam", "updated")]
    assert poam_calls and all(_names_system("poam", c) for _p, c in poam_calls)


def test_scope_reads_the_system_off_the_event() -> None:
    def ev(et: str, verb: str, eid: str | None, payload: dict[str, Any]) -> Event:
        return Event(organization_id=7, verb=verb, entity_type=et, entity_id=eid, payload=payload)

    cr26 = consumers.REGISTRY["cr26_documents"]
    assert cr26.scope(ev("poam", "updated", "5", {"system_id": 40})) == "system:40"
    assert cr26.scope(ev("poam", "updated", "5", {})) is None  # never the POA&M id
    assert cr26.scope(ev("poam", "updated", "5", {"system_id": True})) is None
    assert cr26.scope(ev("system", "derived", "41", {})) == "system:41"
    cap = consumers.REGISTRY["capability_derive"]
    assert cap.scope(ev("capability", "updated", "3", {})) == "org:7"
    assert cap.scope(ev("control_implementation", "updated", "9", {"system_id": 2})) == ("system:2")
    graph = consumers.REGISTRY["assurance_graph"]
    assert graph.scope(ev("poam", "updated", "5", {"system_id": 40})) == "org:7"
    assert not graph.matches("task", "created")
    assert graph.matches("poam", "updated")


# ── behaviour ────────────────────────────────────────────────────────────────


async def test_a_poam_change_rebuilds_the_graph_within_one_drain() -> None:
    org_id, system_id = await _system("graph-one")
    mark = await _mark()
    async with _Client(org_id)() as c:
        r = await c.post(
            "/api/poams",
            json={"system_id": system_id, "title": "Weak TLS", "source": "assessment"},
        )
    assert r.status_code == 201, r.text
    poam_id = r.json()["id"]

    async def poam_nodes() -> list[str]:
        async with session_scope() as s:
            return list(
                (
                    await s.execute(
                        select(AssuranceNode.entity_id).where(
                            AssuranceNode.organization_id == org_id,
                            AssuranceNode.entity_type == "poam",
                        )
                    )
                ).scalars()
            )

    assert str(poam_id) not in await poam_nodes()  # nothing rebuilt in the request
    jobs = [j for j in await _jobs_since(mark) if j.consumer == "assurance_graph"]
    assert [j.scope_key for j in jobs] == [f"org:{org_id}"]
    out = await _drain(mark)
    assert out["failed"] == 0 and out["retried"] == 0, out
    assert str(poam_id) in await poam_nodes()
    done = {j.consumer: j for j in await _jobs_since(mark) if j.consumer == "assurance_graph"}
    assert done["assurance_graph"].status == "done"


async def _seed_vdr(system_id: int) -> None:
    async with session_scope() as s:
        await seed_vdr(s, system_id=system_id, period_from=P_FROM, period_to=P_TO)


async def test_a_poam_change_regenerates_the_existing_vdr_with_its_period() -> None:
    org_id, system_id = await _system("vdr-regen")
    await _seed_vdr(system_id)  # stored while the system had no flaws
    before = await _document(system_id, "vdr")
    assert before is not None and before.document["vulnerabilities"] == []
    stored_period = dict(before.document["reportPeriod"])
    poam_id = await _poam(system_id)

    mark = await _mark()
    async with _Client(org_id)() as c:
        r = await c.patch(f"/api/poams/{poam_id}", json={"title": "Outdated OpenSSL 1.0"})
    assert r.status_code == 200, r.text
    cr26 = [j for j in await _jobs_since(mark) if j.consumer == "cr26_documents"]
    assert [j.scope_key for j in cr26] == [f"system:{system_id}"]
    out = await _drain(mark)
    assert out["failed"] == 0 and out["retried"] == 0, out

    after = await _document(system_id, "vdr")
    assert after is not None
    ids = [v.get("providerTrackingId") for v in after.document["vulnerabilities"]]
    assert ids == [str(poam_id)]  # regenerated from current records
    assert after.document["reportPeriod"] == stored_period  # the document's own period
    assert stored_period == {
        "from": P_FROM.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "to": P_TO.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


async def test_no_vdr_is_created_where_none_existed() -> None:
    org_id, system_id = await _system("vdr-none")
    # Positive control in the same system: a stored ver_history IS regenerated.
    async with session_scope() as s:
        await seed_ver_history(s, system_id=system_id)
    vh_before = await _document(system_id, "ver_history")
    assert vh_before is not None and vh_before.document["activeVulnerabilities"] == []
    poam_id = await _poam(system_id)

    mark = await _mark()
    async with session_scope() as s:
        await bus.emit(
            s,
            verb="updated",
            entity_type="poam",
            entity_id=poam_id,
            summary="t",
            org_id=org_id,
            payload={"system_id": system_id},
        )
    out = await _drain(mark)
    assert out["failed"] == 0, out

    assert await _document(system_id, "vdr") is None
    assert await _document(system_id, "avi") is None
    vh = await _document(system_id, "ver_history")
    assert vh is not None
    assert [v.get("providerTrackingId") for v in vh.document["activeVulnerabilities"]] == [
        str(poam_id)
    ]
    job = next(j for j in await _jobs_since(mark) if j.consumer == "cr26_documents")
    assert job.status == "done"
    assert job.result["vdr"] == "absent" and job.result["avi"] == "absent"


async def test_a_stored_vdr_without_a_usable_period_is_left_alone() -> None:
    org_id, system_id = await _system("vdr-noperiod")
    async with session_scope() as s:
        await put_document(s, system_id=system_id, kind="vdr", document={"vulnerabilities": []})
    await _poam(system_id)
    mark = await _mark()
    async with session_scope() as s:
        await bus.emit(
            s,
            verb="created",
            entity_type="poam",
            summary="t",
            org_id=org_id,
            payload={"system_id": system_id},
        )
    await _drain(mark)
    doc = await _document(system_id, "vdr")
    assert doc is not None and doc.document == {"vulnerabilities": []}  # no invented period
    job = next(j for j in await _jobs_since(mark) if j.consumer == "cr26_documents")
    assert job.status == "done" and job.result["vdr"] == "no stored period"
    # ver_history is re-seeded only where one is stored, too.
    assert await _document(system_id, "ver_history") is None
    assert job.result["ver_history"] == "absent"


async def test_an_ocr_is_never_filed_by_a_consumer() -> None:
    org_id, system_id = await _system("ocr-never")
    await _seed_vdr(system_id)
    async with session_scope() as s:
        for kind in ("ocr", "sdr", "cpo"):
            await put_document(s, system_id=system_id, kind=kind, document={})
    others = {
        kind: (await _document(system_id, kind)).id  # type: ignore[union-attr]
        for kind in ("ocr", "sdr", "cpo")
    }
    vdr_id = (await _document(system_id, "vdr")).id  # type: ignore[union-attr]

    async def filings() -> int:
        async with session_scope() as s:
            return int(
                (
                    await s.execute(
                        select(func.count(CertificationSnapshotFiling.id)).where(
                            CertificationSnapshotFiling.organization_id == org_id
                        )
                    )
                ).scalar_one()
            )

    async def writes(doc_id: int) -> int:
        async with session_scope() as s:
            return int(
                (
                    await s.execute(
                        select(func.count(AuditLog.id)).where(
                            AuditLog.entity_type == "cr26_document",
                            AuditLog.entity_id == str(doc_id),
                        )
                    )
                ).scalar_one()
            )

    filed = await filings()
    before = {k: await writes(i) for k, i in others.items()}
    vdr_writes = await writes(vdr_id)
    poam_id = await _poam(system_id)
    mark = await _mark()
    async with _Client(org_id)() as c:
        r = await c.patch(f"/api/poams/{poam_id}", json={"severity": "critical"})
    assert r.status_code == 200, r.text
    await _drain(mark)

    assert await writes(vdr_id) == vdr_writes + 1  # positive control: the consumer ran
    assert {k: await writes(i) for k, i in others.items()} == before
    assert await filings() == filed


async def _gated(org_id: int, system_id: int) -> dict[str, Any]:
    """Every status a person or a gate owns, for one system and its org.

    Derived columns (``derived_status``, ``KSIState.status``) are deliberately
    absent: writing those is the consumers' job. ``readiness_status`` is
    present at a human-parked value (``submitted``); see the test.
    """
    async with session_scope() as s:

        async def rows(stmt: Any) -> list[Any]:
            return list((await s.execute(stmt)).scalars())

        poams = await rows(select(POAM).where(POAM.system_id == system_id))
        poam_ids = [p.id for p in poams]
        system = await s.get(System, system_id)
        assert system is not None
        profile = (
            await s.execute(
                select(FedRAMP20xProfile).where(FedRAMP20xProfile.system_id == system_id)
            )
        ).scalar_one_or_none()
        return {
            "poams": {
                p.id: (p.status, p.due_on, p.closed_on, p.acceptance_rationale) for p in poams
            },
            "extensions": {
                e.id: (e.status, e.requested_due_on, e.decided_by)
                for e in await rows(
                    select(PoamExtension).where(PoamExtension.poam_id.in_(poam_ids))
                )
            },
            "risks": {
                r.id: r.status for r in await rows(select(Risk).where(Risk.system_id == system_id))
            },
            "approvals": {
                a.id: a.state
                for a in await rows(select(Approval).where(Approval.organization_id == org_id))
            },
            "ssps": {
                p.id: p.status
                for p in await rows(select(SSPProject).where(SSPProject.system_id == system_id))
            },
            "implementations": {
                i.id: i.status
                for i in await rows(
                    select(ControlImplementation).where(
                        ControlImplementation.system_id == system_id
                    )
                )
            },
            "reviews": {
                r.id: r.status
                for r in await rows(
                    select(KSIAssessorReview).where(KSIAssessorReview.system_id == system_id)
                )
            },
            "exceptions": {
                e.id: e.status
                for e in await rows(select(KSIException).where(KSIException.system_id == system_id))
            },
            "assessor_status": {
                k.id: k.assessor_status
                for k in await rows(select(KSIState).where(KSIState.system_id == system_id))
            },
            "readiness_status": profile.readiness_status if profile else None,
            "system": (
                system.ato_status,
                system.ato_expires_on,
                system.pipeline_stage,
                system.deleted_at,
            ),
            "capabilities": {
                c.id: c.status
                for c in await rows(select(Capability).where(Capability.organization_id == org_id))
            },
        }


async def test_a_derived_consumer_never_changes_a_gated_status() -> None:
    org_id, system_id = await _system("gated", twentyx=True)
    open_id = await _poam(system_id, due_on=date.today() + timedelta(days=90), severity="critical")
    accepted_id = await _poam(
        system_id,
        status="risk_accepted",
        due_on=date.today() + timedelta(days=30),
        acceptance_rationale="compensating control in place",
    )
    closed_id = await _poam(system_id, status="closed", title="old")
    await _poam(system_id, source="assessment", title="deficiency")
    async with session_scope() as s:
        await s.execute(update(POAM).where(POAM.id == closed_id).values(closed_on=date.today()))
        system = await s.get(System, system_id)
        assert system is not None
        system.ato_status = "authorized"
        system.ato_expires_on = date.today() + timedelta(days=365)
        await s.execute(
            update(FedRAMP20xProfile)
            .where(FedRAMP20xProfile.system_id == system_id)
            .values(readiness_status="submitted")
        )
        s.add(Risk(system_id=system_id, title="r1", status="accepted"))
        s.add(Risk(system_id=system_id, title="r2", status="open"))
        for poam_id, status in ((open_id, "requested"), (accepted_id, "approved")):
            s.add(
                PoamExtension(
                    organization_id=org_id,
                    poam_id=poam_id,
                    requested_due_on=date.today() + timedelta(days=200),
                    reason="vendor patch",
                    status=status,
                    requested_by="a@x",
                    decided_by="b@x" if status == "approved" else None,
                )
            )
        s.add(
            Approval(
                organization_id=org_id,
                entity_type="poam",
                entity_id=str(accepted_id),
                state="submitted",
                submitted_by="a@x",
            )
        )
        s.add(
            Approval(
                organization_id=org_id,
                entity_type="poam",
                entity_id=str(open_id),
                state="approved",
                submitted_by="a@x",
                reviewed_by="b@x",
            )
        )
        s.add(
            SSPProject(
                organization_id=org_id, system_id=system_id, customer_name="c", status="draft"
            )
        )
        # A KSI with an assessor review, an exception and a KSI state.
        ksi = KSI(identifier=f"KSI-GTD-{system_id}", category="GTD", name="test-only")
        s.add(ksi)
        await s.flush()
        ksi_id = ksi.id
        s.add(KSIState(system_id=system_id, ksi_id=ksi.id, assessor_status="accepted"))
        s.add(KSIAssessorReview(system_id=system_id, ksi_id=ksi.id, status="accepted"))
        s.add(KSIException(system_id=system_id, ksi_id=ksi.id, rationale="r", status="accepted"))
        # A capability bound through a component to an implemented control.
        ctrl = (
            await s.execute(select(Control).where(Control.identifier == "AC-2"))
        ).scalar_one_or_none()
        if ctrl is None:
            ctrl = Control(identifier="AC-2", control_name="Account Management")
            s.add(ctrl)
            await s.flush()
        s.add(ControlImplementation(system_id=system_id, control_id=ctrl.id, status="planned"))
        comp = SystemComponent(
            organization_id=org_id, system_id=system_id, type="software", title="IdP"
        )
        cap = Capability(
            organization_id=org_id, key=f"idp-{system_id}", title="IdP", status="implemented"
        )
        s.add_all([comp, cap])
        await s.flush()
        s.add(
            CapabilityComponent(organization_id=org_id, capability_id=cap.id, component_id=comp.id)
        )
        s.add(CapabilityControl(organization_id=org_id, capability_id=cap.id, control_id="AC-2"))
        cap_id = cap.id
    async with session_scope() as s:
        await seed_vdr(s, system_id=system_id, period_from=P_FROM, period_to=P_TO)
        await seed_avi(s, system_id=system_id, period_from=P_FROM, period_to=P_TO)
        await seed_ver_history(s, system_id=system_id)

    try:
        before = await _gated(org_id, system_id)
        assert len(before["poams"]) == 4 and before["extensions"] and before["reviews"]
        mark = await _mark()
        async with session_scope() as s:
            # Events every derived consumer triggers on, the org-scoped
            # capability one included (derive_for_org).
            await bus.emit(
                s,
                verb="derived",
                entity_type="system",
                entity_id=system_id,
                summary="t",
                org_id=org_id,
            )
            await bus.emit(
                s,
                verb="updated",
                entity_type="poam",
                entity_id=open_id,
                summary="t",
                org_id=org_id,
                payload={"system_id": system_id},
            )
            await bus.emit(
                s,
                verb="updated",
                entity_type="capability",
                entity_id=cap_id,
                summary="t",
                org_id=org_id,
            )
        queued = {(j.consumer, j.scope_key) for j in await _jobs_since(mark)}
        assert ("capability_derive", f"org:{org_id}") in queued
        assert ("capability_derive", f"system:{system_id}") in queued
        out = await _drain(mark)
        assert out["failed"] == 0 and out["retried"] == 0, out
        ran = {
            (j.consumer, j.scope_key)
            for j in await _jobs_since(mark)
            if j.consumer in DERIVED and j.status == "done" and "skipped" not in (j.result or {})
        }
        # Positive control: each consumer ran, capability_derive at both scopes.
        assert {c for c, _k in ran} == set(DERIVED)
        assert ("capability_derive", f"org:{org_id}") in ran
        async with session_scope() as s:
            impl = (
                await s.execute(
                    select(ControlImplementation).where(
                        ControlImplementation.system_id == system_id
                    )
                )
            ).scalar_one()
            assert impl.derived_status == "implemented"  # it really derived
        assert await _gated(org_id, system_id) == before
    finally:
        async with session_scope() as s:
            await s.execute(delete(KSI).where(KSI.id == ksi_id))


async def test_fedramp20x_is_a_noop_for_a_system_with_no_20x_footprint() -> None:
    org_id, system_id = await _system("not-20x")
    mark = await _mark()
    async with session_scope() as s:
        await bus.emit(
            s,
            verb="updated",
            entity_type="fedramp20x_profile",
            entity_id=system_id,
            summary="t",
            org_id=org_id,
        )
    await _drain(mark)
    job = next(j for j in await _jobs_since(mark) if j.consumer == "fedramp20x")
    assert job.status == "done" and job.result.get("skipped") == "no 20x footprint"

    org2, sys2 = await _system("is-20x", twentyx=True)
    mark = await _mark()
    async with session_scope() as s:
        await bus.emit(
            s,
            verb="updated",
            entity_type="fedramp20x_profile",
            entity_id=sys2,
            summary="t",
            org_id=org2,
        )
    await _drain(mark)
    job = next(j for j in await _jobs_since(mark) if j.consumer == "fedramp20x")
    assert job.status == "done" and job.result.get("system_id") == sys2
    assert "skipped" not in job.result


async def test_scan_system_matches_the_sweep() -> None:
    """``scan``'s row for a system is exactly ``scan_system``'s for it."""
    _org, sid = await _system("parity", twentyx=True)
    _org2, plain = await _system("parity-plain")
    async with session_scope() as s:
        one = await monitoring.scan_system(s, system_id=sid)
    async with session_scope() as s:
        sweep = await monitoring.scan(s)
    row = next(r for r in sweep["systems"] if r["system_id"] == sid)
    assert row == one
    assert all(r["system_id"] != plain for r in sweep["systems"])
    async with session_scope() as s:
        assert await monitoring.is_20x_system(s, sid)
        assert not await monitoring.is_20x_system(s, plain)

    # KSI state alone is a 20x footprint, as it is for the sweep.
    _org3, state_only = await _system("parity-state")
    async with session_scope() as s:
        ksi = KSI(identifier=f"KSI-TST-{state_only}", category="TST", name="test-only")
        s.add(ksi)
        await s.flush()
        s.add(KSIState(system_id=state_only, ksi_id=ksi.id))
        ksi_id = ksi.id
    try:
        async with session_scope() as s:
            assert await monitoring.is_20x_system(s, state_only)
            swept = {r["system_id"] for r in (await monitoring.scan(s))["systems"]}
        assert state_only in swept
    finally:
        async with session_scope() as s:
            await s.execute(delete(KSI).where(KSI.id == ksi_id))  # its state cascades


# ── fix round 1 ──────────────────────────────────────────────────────────────


async def _events_since(event_mark: int, **where: Any) -> list[Event]:
    async with session_scope() as s:
        stmt = select(Event).where(Event.id > event_mark)
        for k, v in where.items():
            stmt = stmt.where(getattr(Event, k) == v)
        return list((await s.execute(stmt.order_by(Event.id))).scalars())


async def _event_mark() -> int:
    async with session_scope() as s:
        return int((await s.execute(select(func.coalesce(func.max(Event.id), 0)))).scalar_one())


def _funcs_constructing(name: str) -> list[tuple[str, ast.AST]]:
    out: list[tuple[str, ast.AST]] = []
    for path in sorted(_SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for fn in ast.walk(tree):
            if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            if any(
                isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == name
                for n in ast.walk(fn)
            ):
                out.append((f"{path.relative_to(_SRC)}::{fn.name}", fn))
    return out


#: POA&M constructors whose function emits nothing itself, and the event that
#: covers the write (emitted by the caller, in the same transaction).
POAM_WRITERS_COVERED_BY_CALLER: dict[str, str] = {
    "ingest/scanners.py::reconcile_findings": "scan_ingestion ingested (api/routes/scans.py)",
    "governance/conmon.py::_upsert_poam": "monitoring_run scanned (governance/conmon.py:202)",
    "governance/automation.py::_seed_gap_poams": "system derived (governance/automation.py:360)",
    "fedramp20x/records.py::maybe_open_finding_poam": "ksi_assessor_review reviewed/updated",
}


def test_every_poam_constructor_emits_or_is_covered() -> None:
    """A POA&M written with no event is invisible to the graph and the VER
    deliverables (spec 5.1: a gap to add an emit for)."""
    silent = [
        where
        for where, fn in _funcs_constructing("POAM")
        if not any(
            isinstance(n, ast.Call)
            and (n.func.attr if isinstance(n.func, ast.Attribute) else None) == "emit"
            for n in ast.walk(fn)
        )
        and where not in POAM_WRITERS_COVERED_BY_CALLER
    ]
    assert not silent, f"POA&M writers that emit nothing: {silent}"
    found = {w for w, _fn in _funcs_constructing("POAM")}
    stale = set(POAM_WRITERS_COVERED_BY_CALLER) - found
    assert not stale, f"allowlisted writers that no longer exist: {stale}"


async def _assessment(system_id: int) -> tuple[int, int]:
    async with session_scope() as s:
        a = Assessment(system_id=system_id, name="CMMC L2", kind="self")
        s.add(a)
        await s.flush()
        r = AssessmentControlResult(
            assessment_id=a.id,
            control_id="AC.L2-3.1.1",
            nist_id="AC-2",
            title="Authorized access",
            finding="other_than_satisfied",
        )
        s.add(r)
        await s.flush()
        return a.id, r.id


async def test_the_assessment_route_emits_each_poam_it_opens() -> None:
    org_id, system_id = await _system("assess-route")
    aid, _rid = await _assessment(system_id)
    ev_mark, mark = await _event_mark(), await _mark()
    async with _Client(org_id)() as c:
        r = await c.post(f"/api/assessments/{aid}/poams-from-findings")
    assert r.status_code == 200, r.text and r.json()["created"] == 1
    evs = await _events_since(ev_mark, entity_type="poam", verb="created")
    assert len(evs) == 1
    assert evs[0].organization_id == org_id and evs[0].payload["system_id"] == system_id
    keys = {(j.consumer, j.scope_key) for j in await _jobs_since(mark)}
    assert ("assurance_graph", f"org:{org_id}") in keys
    assert ("cr26_documents", f"system:{system_id}") in keys


async def test_the_assessment_engine_emits_the_poam_it_opens() -> None:
    org_id, system_id = await _system("assess-engine")
    aid, rid = await _assessment(system_id)
    ev_mark = await _event_mark()
    async with session_scope() as s:
        await engine._ensure_poam_for_other_than_satisfied(
            s,
            proposal=SimpleNamespace(  # type: ignore[arg-type]
                id=1, assessment_id=aid, control_identifier="AC-2", rollup_rationale="gap"
            ),
            result=SimpleNamespace(id=rid, finding="other_than_satisfied"),  # type: ignore[arg-type]
        )
    evs = await _events_since(ev_mark, entity_type="poam", verb="created")
    assert len(evs) == 1
    assert evs[0].organization_id == org_id and evs[0].payload["system_id"] == system_id


async def test_a_global_principal_s_poam_change_reaches_the_org_graph() -> None:
    """An unscoped principal has no org: the event takes the system's (C)."""
    org_id, system_id = await _system("global-patch")
    poam_id = await _poam(system_id, source="assessment", title="before")
    mark = await _mark()
    app = create_app()
    app.dependency_overrides[get_principal] = lambda: Principal(
        user_id=None, email="system", org_id=None, role="admin"
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.patch(f"/api/poams/{poam_id}", json={"title": "after"})
    assert r.status_code == 200, r.text
    graph = [j for j in await _jobs_since(mark) if j.consumer == "assurance_graph"]
    assert [j.scope_key for j in graph] == [f"org:{org_id}"]
    assert graph[0].organization_id == org_id
    await _drain(mark)
    async with session_scope() as s:
        label = (
            await s.execute(
                select(AssuranceNode.label).where(
                    AssuranceNode.organization_id == org_id,
                    AssuranceNode.entity_type == "poam",
                    AssuranceNode.entity_id == str(poam_id),
                )
            )
        ).scalar_one()
    assert label == "after"


async def _engine_system(name: str, *, implemented: bool) -> tuple[int, int]:
    """A 20x system whose KSI-IAM-APM (test rule: control_state IA-2) follows IA-2."""
    org_id, sid = await _system(name, twentyx=True)
    async with session_scope() as s:
        await catalog.seed_ksis(s, overlay_path=_ENGINE_RULES)
        ctrl = (
            await s.execute(select(Control).where(Control.identifier == "IA-2"))
        ).scalar_one_or_none()
        if ctrl is None:
            ctrl = Control(identifier="IA-2", control_name="Identification and Authentication")
            s.add(ctrl)
            await s.flush()
        s.add(
            ControlImplementation(
                system_id=sid,
                control_id=ctrl.id,
                status="implemented" if implemented else "not_implemented",
            )
        )
    async with session_scope() as s:
        await validation.validate_system(s, system_id=sid)
    return org_id, sid


_ENGINE_RULES = Path(__file__).parent / "fixtures" / "ksi_rules_engine.json"


@pytest.fixture
async def _shipped_catalog_after() -> AsyncIterator[None]:
    yield
    async with session_scope() as s:
        await catalog.seed_ksis(s)  # ``ksis`` is global: leave it as shipped


async def _apm_status(org_id: int, sid: int) -> str | None:
    async with session_scope() as s:
        ksi_id = (
            await s.execute(select(KSI.id).where(KSI.identifier == "KSI-IAM-APM"))
        ).scalar_one()
        return (
            await s.execute(
                select(AssuranceNode.status).where(
                    AssuranceNode.organization_id == org_id,
                    AssuranceNode.entity_type == "ksi",
                    AssuranceNode.entity_id == f"{sid}:{ksi_id}",
                )
            )
        ).scalar_one_or_none()


@pytest.mark.usefixtures("_shipped_catalog_after")
async def test_an_improving_ksi_state_reaches_the_graph() -> None:
    """fedramp20x re-scores; its internal ksi_rescored rebuilds the graph (B)."""
    org_id, sid = await _engine_system("ksi-improves", implemented=False)
    async with session_scope() as s:
        await rebuild_org(s, org_id)
    assert await _apm_status(org_id, sid) not in (None, "pass")  # before: not passing
    async with session_scope() as s:
        await s.execute(
            update(ControlImplementation)
            .where(ControlImplementation.system_id == sid)
            .values(status="implemented")
        )
    mark = await _mark()
    async with session_scope() as s:
        # An event only fedramp20x triggers on: the graph learns of the new
        # KSI state from fedramp20x's own event, not from this one.
        await bus.emit(
            s,
            verb="updated",
            entity_type="fedramp20x_profile",
            entity_id=sid,
            summary="t",
            org_id=org_id,
        )
    assert {j.consumer for j in await _jobs_since(mark)} == {"fedramp20x"}
    await _drain(mark)  # fedramp20x re-scores, emits ksi_rescored
    rescored = [j for j in await _jobs_since(mark) if j.consumer == "assurance_graph"]
    assert [j.scope_key for j in rescored] == [f"org:{org_id}"]
    await _drain(mark)  # the graph rebuilds
    assert await _apm_status(org_id, sid) == "pass"


@pytest.mark.usefixtures("_shipped_catalog_after")
async def test_drift_a_consumer_finds_reaches_webhooks_and_bookkeeping_does_not() -> None:
    """Ruling R20: ``external=True`` survives a consumer; ordinary emits do not."""
    org_id, sid = await _engine_system("drift-hook", implemented=True)
    async with session_scope() as s:
        hook = Webhook(
            organization_id=org_id, url="https://hooks.example/in", events=[], active=True
        )
        s.add(hook)
        await s.flush()
        hook_id = hook.id
        await s.execute(
            update(ControlImplementation)
            .where(ControlImplementation.system_id == sid)
            .values(status="not_implemented")
        )
    try:
        ev_mark, mark = await _event_mark(), await _mark()
        async with session_scope() as s:
            await bus.emit(
                s,
                verb="updated",
                entity_type="fedramp20x_profile",
                entity_id=sid,
                summary="t",
                org_id=org_id,
                dispatch=False,
            )
        await _drain(mark)
        drift = await _events_since(ev_mark, entity_type="system", verb="drift")
        rescored = await _events_since(ev_mark, entity_type="system", verb="ksi_rescored")
        assert len(drift) == 1 and len(rescored) == 1
        hooks = [j for j in await _jobs_since(mark) if j.consumer == "webhook"]
        assert [j.trigger_event_id for j in hooks] == [drift[0].id]
    finally:
        async with session_scope() as s:
            await s.execute(
                delete(OutboxJob).where(
                    OutboxJob.consumer == "webhook",
                    OutboxJob.result["webhook_id"].as_integer() == hook_id,
                )
            )
            await s.execute(delete(Webhook).where(Webhook.id == hook_id))


async def test_a_seeder_written_vdr_is_refreshed_and_an_authored_one_is_kept() -> None:
    """Ruling R22: refresh what a seeder wrote; tell the author about theirs."""
    org_id, sys_a = await _system("vdr-seeded")
    org_b, sys_b = await _system("vdr-authored")
    await _seed_vdr(sys_a)
    async with session_scope() as s:
        doc = {
            "reportPeriod": {
                "from": P_FROM.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "to": P_TO.strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            "vulnerabilities": [],
            "note": "hand-edited",
        }
        await put_document(s, system_id=sys_b, kind="vdr", document=doc, updated_by="alice@x")
    authored = await _document(sys_b, "vdr")
    assert authored is not None
    kept = (dict(authored.document), authored.updated_by, authored.is_valid)
    a_poam, b_poam = await _poam(sys_a), await _poam(sys_b)
    mark = await _mark()
    async with session_scope() as s:
        for org, sid, pid in ((org_id, sys_a, a_poam), (org_b, sys_b, b_poam)):
            await bus.emit(
                s,
                verb="updated",
                entity_type="poam",
                entity_id=pid,
                summary="t",
                org_id=org,
                payload={"system_id": sid},
            )
    out = await _drain(mark)
    assert out["failed"] == 0, out

    refreshed = await _document(sys_a, "vdr")
    assert refreshed is not None and refreshed.updated_by == derived.CR26_AUTHOR
    assert [v["providerTrackingId"] for v in refreshed.document["vulnerabilities"]] == [str(a_poam)]

    after = await _document(sys_b, "vdr")
    assert after is not None
    assert (after.document, after.updated_by, after.is_valid) == kept  # byte for byte
    job = next(
        j
        for j in await _jobs_since(mark)
        if j.consumer == "cr26_documents" and j.scope_key == f"system:{sys_b}"
    )
    assert job.result["skipped"] == "author-edited" and job.result["vdr"] == "author-edited"
    async with session_scope() as s:
        notes = list(
            (
                await s.execute(
                    select(Notification).where(
                        Notification.organization_id == org_b,
                        Notification.dedupe_key == f"cr26-stale:{sys_b}:vdr",
                    )
                )
            ).scalars()
        )
    assert len(notes) == 1 and "out of date" in notes[0].title

    # A second change does not pile up a second notification.
    mark = await _mark()
    async with session_scope() as s:
        await bus.emit(
            s,
            verb="updated",
            entity_type="poam",
            entity_id=b_poam,
            summary="t",
            org_id=org_b,
            payload={"system_id": sys_b},
        )
    await _drain(mark)
    async with session_scope() as s:
        n = (
            await s.execute(
                select(func.count(Notification.id)).where(
                    Notification.dedupe_key == f"cr26-stale:{sys_b}:vdr"
                )
            )
        ).scalar_one()
    assert n == 1


async def test_a_person_s_write_during_a_reseed_is_never_overwritten() -> None:
    """The stored rows are locked before they are read (ruling R22).

    A person's PUT holds the row (uncommitted) while the consumer runs: the
    consumer must wait for it and then see its author, not read the old
    seeder-written row and overwrite the person's document after they commit.
    """
    org_id, sid = await _system("vdr-race")
    await _seed_vdr(sid)
    await _poam(sid)
    mark = await _mark()
    async with session_scope() as s:
        await bus.emit(
            s,
            verb="updated",
            entity_type="poam",
            summary="t",
            org_id=org_id,
            payload={"system_id": sid},
        )
    edited = {"reportPeriod": {"from": "2026-01-01T00:00:00Z", "to": "2026-02-01T00:00:00Z"}}
    async with session_scope() as person:
        await put_document(person, system_id=sid, kind="vdr", document=edited, updated_by="bob@x")
        drain = asyncio.create_task(_drain(mark))
        await asyncio.sleep(1.5)
        assert not drain.done()  # the consumer waits on the person's row lock
    await asyncio.wait_for(drain, timeout=30)
    doc = await _document(sid, "vdr")
    assert doc is not None and doc.updated_by == "bob@x" and doc.document == edited


async def test_a_soft_deleted_system_is_skipped_not_dead_lettered() -> None:
    """Ruling R24: every system-scoped run checks first, whoever claimed it."""
    _org, sid = await _system("deleted-mid-run", twentyx=True)
    await _seed_vdr(sid)
    async with session_scope() as s:
        system = await s.get(System, sid)
        assert system is not None
        system.deleted_at = datetime.now(UTC)
    for name in ("cr26_documents", "capability_derive", "fedramp20x"):
        async with session_scope() as s:
            out = await consumers.REGISTRY[name].run(s, f"system:{sid}", OutboxJob())
        assert out == {"system_id": sid, "skipped": "system deleted"}, name


async def test_a_reseed_promotes_an_authored_rationale_into_a_blank_column() -> None:
    """Pinned so the fix report's claim is evidence: a ver_history re-seed runs
    `_promote_rationales` (cr26/ver.py:818), which copies a rationale a person
    authored in the AVI into a BLANK `POAM.acceptance_rationale`. It never
    overwrites one, and it changes no status."""
    org_id, sid = await _system("promote")
    pid = await _poam(sid, status="risk_accepted", acceptance_rationale=None)
    async with session_scope() as s:
        await seed_ver_history(s, system_id=sid)
        await put_document(
            s,
            system_id=sid,
            kind="avi",
            document={
                "acceptedVulnerabilities": [
                    {
                        "vulnerabilityDetail": {"providerTrackingId": str(pid)},
                        "acceptanceRationale": "vendor EOL, isolated",
                    }
                ]
            },
            updated_by="carol@x",
        )
    mark = await _mark()
    async with session_scope() as s:
        await bus.emit(
            s,
            verb="updated",
            entity_type="poam",
            entity_id=pid,
            summary="t",
            org_id=org_id,
            payload={"system_id": sid},
        )
    await _drain(mark)
    async with session_scope() as s:
        row = await s.get(POAM, pid)
        assert row is not None
        assert (row.status, row.acceptance_rationale) == ("risk_accepted", "vendor EOL, isolated")


async def test_a_control_test_poam_opened_on_request_is_emitted() -> None:
    """``ensure_poam_for_control_test`` is reached by two routes that emit
    nothing of their own, so it emits: created once, updated on refresh."""
    org_id, system_id = await _system("ct-poam")
    ev_mark = await _event_mark()
    async with session_scope() as s:
        test = ControlTest(
            organization_id=org_id,
            system_id=system_id,
            control_id="AC-2",
            name="MFA enforced",
            method="manual",
        )
        s.add(test)
        await s.flush()
        poam, created = await control_tests.ensure_poam_for_control_test(s, test, "fail")
        assert poam is not None and created
        again, created_again = await control_tests.ensure_poam_for_control_test(s, test, "fail")
        assert again is not None and again.id == poam.id and not created_again
    evs = await _events_since(ev_mark, entity_type="poam")
    assert [(e.verb, e.entity_id) for e in evs] == [
        ("created", str(poam.id)),
        ("updated", str(poam.id)),
    ]
    assert all(e.organization_id == org_id and e.payload["system_id"] == system_id for e in evs)
