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
from collections.abc import AsyncIterator
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, func, select, update

import ccf
from ccf.api.auth_deps import get_principal
from ccf.api.main import create_app
from ccf.auth import Principal
from ccf.cr26.store import put_document
from ccf.cr26.ver import seed_avi, seed_vdr, seed_ver_history
from ccf.db import session_scope
from ccf.events import consumers, derived, worker
from ccf.fedramp20x import monitoring
from ccf.governance import bus
from ccf.models import (
    KSI,
    POAM,
    Approval,
    AuditLog,
    Event,
    FedRAMP20xProfile,
    KSIState,
    Organization,
    Risk,
    SSPProject,
    System,
)
from ccf.models_assurance import AssuranceNode
from ccf.models_cr26 import CertificationSnapshotFiling, Cr26Document
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
                ("control_implementation", "updated"),
                ("control_implementation", "bulk_updated"),
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
                ("control_implementation", "bulk_updated"),
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
                ("control_implementation", "bulk_updated"),
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
    async with session_scope() as s:
        poams = {
            p.id: (p.status, p.due_on)
            for p in (await s.execute(select(POAM).where(POAM.system_id == system_id))).scalars()
        }
        risks = {
            r.id: r.status
            for r in (await s.execute(select(Risk).where(Risk.system_id == system_id))).scalars()
        }
        approvals = {
            a.id: a.state
            for a in (
                await s.execute(select(Approval).where(Approval.organization_id == org_id))
            ).scalars()
        }
        ssps = {
            p.id: p.status
            for p in (
                await s.execute(select(SSPProject).where(SSPProject.system_id == system_id))
            ).scalars()
        }
    return {"poams": poams, "risks": risks, "approvals": approvals, "ssps": ssps}


async def test_a_derived_consumer_never_changes_a_gated_status() -> None:
    org_id, system_id = await _system("gated", twentyx=True)
    open_id = await _poam(system_id, due_on=date.today() + timedelta(days=90), severity="critical")
    accepted_id = await _poam(
        system_id,
        status="risk_accepted",
        due_on=date.today() + timedelta(days=30),
        acceptance_rationale="compensating control in place",
    )
    await _poam(system_id, status="closed", title="old")
    await _poam(system_id, source="assessment", title="deficiency")
    async with session_scope() as s:
        s.add(Risk(system_id=system_id, title="r1", status="accepted"))
        s.add(Risk(system_id=system_id, title="r2", status="open"))
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
    async with session_scope() as s:
        await seed_vdr(s, system_id=system_id, period_from=P_FROM, period_to=P_TO)
        await seed_avi(s, system_id=system_id, period_from=P_FROM, period_to=P_TO)
        await seed_ver_history(s, system_id=system_id)

    before = await _gated(org_id, system_id)
    assert len(before["poams"]) == 4 and before["risks"] and before["approvals"]
    mark = await _mark()
    async with session_scope() as s:
        # One event every derived consumer triggers on.
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
    queued = {j.consumer for j in await _jobs_since(mark)}
    assert set(DERIVED) <= queued
    out = await _drain(mark)
    assert out["failed"] == 0 and out["retried"] == 0, out
    ran = {
        j.consumer: j.status
        for j in await _jobs_since(mark)
        if j.consumer in DERIVED and j.merged_into is None
    }
    assert ran == dict.fromkeys(DERIVED, "done")  # positive control: each one ran
    assert await _gated(org_id, system_id) == before


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
