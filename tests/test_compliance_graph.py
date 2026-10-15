"""Compliance graph: the assurance graph stores and draws only sourced edges.

Spec: docs/superpowers/specs/2026-10-15-compliance-graph-design.md.
"""

from __future__ import annotations

import importlib.util
import itertools
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from ccf.assurance import builder, impact
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import POAM, Control, ControlImplementation, Evidence, Organization, System
from ccf.models_assurance import AssuranceEdge, AssuranceNode
from ccf.models_grc import ConnectorConfig, ControlTest

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _org_and_system() -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=f"Graph Org {next(_SEQ)}")
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"Graph Sys {next(_SEQ)}", baseline="moderate")
        s.add(sysm)
        await s.flush()
        return org.id, sysm.id


async def _system(org_id: int) -> int:
    async with session_scope() as s:
        sysm = System(organization_id=org_id, name=f"Graph Sys {next(_SEQ)}", baseline="moderate")
        s.add(sysm)
        await s.flush()
        return sysm.id


async def _control(s: Any, identifier: str, sequence_control: str | None = None) -> Control:
    c = (
        await s.execute(select(Control).where(Control.identifier == identifier))
    ).scalar_one_or_none()
    if c is None:
        c = Control(
            identifier=identifier, control_name=identifier, sequence_control=sequence_control
        )
        s.add(c)
        await s.flush()
    return c


async def _implement(
    system_id: int,
    identifier: str,
    status: str = "implemented",
    *,
    sequence_control: str | None = None,
    owner_user_id: int | None = None,
    evidence_title: str | None = None,
) -> int:
    async with session_scope() as s:
        c = await _control(s, identifier, sequence_control)
        impl = ControlImplementation(
            system_id=system_id, control_id=c.id, status=status, owner_user_id=owner_user_id
        )
        s.add(impl)
        await s.flush()
        if evidence_title:
            s.add(Evidence(implementation_id=impl.id, kind="document", title=evidence_title))
        return impl.id


async def _build(org_id: int) -> tuple[str, dict[str, Any]]:
    async with session_scope() as s:
        run = await builder.rebuild_org(s, org_id)
        return run.status, dict(run.detail)


async def _nodes(org_id: int) -> dict[str, dict[str, Any]]:
    """``{"type:entity_id": {"label", "status", "metadata"}}`` for one org."""
    async with session_scope() as s:
        return {
            f"{n.entity_type}:{n.entity_id}": {
                "label": n.label, "status": n.status, "metadata": dict(n.node_metadata or {}),
            }
            for n in (
                await s.execute(
                    select(AssuranceNode).where(AssuranceNode.organization_id == org_id)
                )
            ).scalars()
        }


async def _edges(org_id: int) -> list[tuple[str, str, str, str]]:
    """``(from "type:id", to "type:id", relationship, source)`` for one org."""
    async with session_scope() as s:
        keys = {
            n.id: f"{n.entity_type}:{n.entity_id}"
            for n in (
                await s.execute(
                    select(AssuranceNode).where(AssuranceNode.organization_id == org_id)
                )
            ).scalars()
        }
        return [
            (keys[e.source_node_id], keys[e.target_node_id], e.relationship_type, e.source)
            for e in (
                await s.execute(
                    select(AssuranceEdge).where(AssuranceEdge.organization_id == org_id)
                )
            ).scalars()
        ]


# ── Task 1: every edge names its source ──────────────────────────────────────


async def test_every_stored_edge_names_a_source() -> None:
    org, sid = await _org_and_system()
    await _implement(sid, "AC-2", evidence_title="AC-2 screenshot")
    async with session_scope() as s:
        s.add(POAM(system_id=sid, title="Fix logging", severity="high", status="open"))
    status, _ = await _build(org)
    edges = await _edges(org)
    assert status == "ok"
    assert edges and all(src for *_, src in edges)
    assert {src for *_, src in edges} >= {"control_implementations", "evidence", "poams"}


async def test_the_database_refuses_an_edge_without_a_source() -> None:
    org, _sid = await _org_and_system()
    await _build(org)
    async with session_scope() as s:
        node_id = (
            await s.execute(
                select(AssuranceNode.id).where(AssuranceNode.organization_id == org)
            )
        ).scalars().first()
        s.add(
            AssuranceEdge(
                organization_id=org, source_node_id=node_id, target_node_id=node_id,
                relationship_type="self",
            )
        )
        with pytest.raises(IntegrityError):
            await s.flush()
        await s.rollback()


def test_the_builder_refuses_an_edge_without_a_source() -> None:
    g = builder._Graph()
    a = g.node("system", 1, "s")
    b = g.node("poam", 2, "p")
    with pytest.raises(ValueError, match="no source"):
        g.edge(a, b, "has_poam", "")


async def test_the_subgraph_returns_provenance_and_no_confidence() -> None:
    org, sid = await _org_and_system()
    await _implement(sid, "AC-2")
    await _build(org)
    async with session_scope() as s:
        g = await impact.subgraph(s, org_id=org, entity_type="system", entity_id=str(sid))
    assert g["edges"] and all(e["provenance"] for e in g["edges"])
    assert not any("confidence" in e for e in g["edges"])


async def test_a_failed_contributor_is_recorded_and_the_rest_still_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def broken(session: Any, org_id: int, g: Any) -> None:
        await session.execute(text("SELECT * FROM ccf.no_such_table"))

    monkeypatch.setattr(builder, "_poams", broken)
    org, sid = await _org_and_system()
    await _implement(sid, "AC-2")
    async with session_scope() as s:
        s.add(
            ControlTest(
                organization_id=org, system_id=sid, control_id="AC-2", name="MFA on",
                method="automated",
            )
        )
    status, detail = await _build(org)
    assert status == "partial"
    assert detail["failed"]["poams"].startswith("ProgrammingError")
    # control_tests runs after poams: without a savepoint the failed SQL would
    # have aborted the transaction and this slice would be missing too.
    assert any(k.startswith("control_test:") for k in await _nodes(org))


async def test_a_contributor_that_fails_part_way_leaves_nothing_behind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def half_then_broken(session: Any, org_id: int, g: Any) -> None:
        rk = g.node("risk", 999_999, "half-written risk", "open")
        sk = next(k for k in g.nodes if k[0] == "system")
        g.edge(rk, sk, "threatens", "risks")
        g.impl_index["half"] = rk
        raise RuntimeError("risk register went away mid-read")

    monkeypatch.setattr(builder, "_risks", half_then_broken)
    org, sid = await _org_and_system()
    await _implement(sid, "AC-02")
    status, detail = await _build(org)
    assert status == "partial" and "risks" in detail["failed"]
    assert detail["sources"]["risks"] == 0
    nodes = await _nodes(org)
    # The slices that did build are there (the positive case) ...
    assert f"system:{sid}" in nodes and f"control:{sid}:AC-2" in nodes
    # ... and the failed one is absent, as the page says it is.
    assert not [k for k in nodes if k.startswith("risk:")]
    assert not [e for e in await _edges(org) if e[2] == "threatens"]


async def test_an_agent_system_id_that_names_no_system_is_skipped() -> None:
    from ccf.models_ai_agents import AiAgent  # noqa: PLC0415

    org, _first = await _org_and_system()
    # A second system, so its id is never 1: ``True == 1`` would hide a bool slip.
    sid = await _system(org)
    assert sid != 1
    async with session_scope() as s:
        a = AiAgent(organization_id=org, name="Loose bot", system_ids=["prod", str(sid), True])
        s.add(a)
        await s.flush()
        aid = a.id
    status, detail = await _build(org)
    assert status == "ok", detail
    node = (await _nodes(org))[f"ai_agent:{aid}"]
    assert node["metadata"]["system_ids"] == [sid]
    assert (f"ai_agent:{aid}", f"system:{sid}", "accesses", "ai_agents") in await _edges(org)


async def test_an_agent_system_id_of_non_ascii_digits_is_skipped() -> None:
    """``"²".isdigit()`` is true and ``int("²")`` raises; so are Arabic-Indic digits."""
    from ccf.models_ai_agents import AiAgent  # noqa: PLC0415

    org, _first = await _org_and_system()
    sid = await _system(org)
    async with session_scope() as s:
        a = AiAgent(organization_id=org, name="Odd bot",
                    system_ids=["²", "١٢", "1" * 5000, str(sid)])
        s.add(a)
        await s.flush()
        aid = a.id
    status, detail = await _build(org)
    assert status == "ok", detail
    assert (await _nodes(org))[f"ai_agent:{aid}"]["metadata"]["system_ids"] == [sid]


async def test_a_deleted_system_is_not_a_node_or_a_boundary() -> None:
    from datetime import UTC, datetime  # noqa: PLC0415

    from ccf.models_ai_agents import AiAgent  # noqa: PLC0415

    org, sid = await _org_and_system()
    gone = await _system(org)
    async with session_scope() as s:
        s.add(AiAgent(organization_id=org, name="Spanning bot", system_id=sid,
                      system_ids=[sid, gone]))
    assert (await _build(org))[0] == "ok"

    async def scoped() -> set[tuple[str, str]]:
        async with session_scope() as s:
            g = await impact.subgraph(s, org_id=org, entity_type="system",
                                      entity_id=str(sid), max_hops=6, within_system=sid)
        return {(n["entity_type"], n["entity_id"]) for n in g["nodes"]}

    # While it exists it is a node and the agent shows it as a boundary.
    assert f"system:{gone}" in await _nodes(org)
    assert ("system", str(gone)) in await scoped()
    async with session_scope() as s:
        sysm = await s.get(System, gone)
        assert sysm is not None
        sysm.deleted_at = datetime.now(UTC)
    assert (await _build(org))[0] == "ok"
    assert f"system:{gone}" not in await _nodes(org)
    ids = await scoped()
    assert ("system", str(gone)) not in ids
    assert ("system", str(sid)) in ids and any(t == "ai_agent" for t, _ in ids)


async def test_a_deleted_system_contributes_nothing_of_its_own() -> None:
    """DATA-04: a deleted system is gone, with every row that hangs off it.

    Only ``_systems`` used to filter it, so its controls, KSIs, capabilities,
    POA&Ms, risks, scans, tests and evidence objects were drawn as unconnected
    nodes (inflating /assurance and reachable from an unscoped trace).
    """
    from datetime import UTC, datetime  # noqa: PLC0415

    from ccf.models import KSIState, Risk, ScanIngestion  # noqa: PLC0415
    from ccf.models_evidence import EvidenceObject  # noqa: PLC0415

    ksi_id, ksi_ident, control = await _seeded_ksi_with_a_control()
    org, live = await _org_and_system()
    gone = await _system(org)
    ids: dict[int, dict[str, int]] = {}
    for sid in (live, gone):
        await _implement(sid, control)
        cap = await _capability(org, sid, controls=[control], ksis=[ksi_ident])
        async with session_scope() as s:
            s.add(KSIState(system_id=sid, ksi_id=ksi_id, status="pass"))
            poam = POAM(system_id=sid, title="p", severity="high", status="open")
            risk = Risk(system_id=sid, title="r")
            scan = ScanIngestion(organization_id=org, system_id=sid, scanner="nessus")
            test = ControlTest(organization_id=org, system_id=sid, control_id=control,
                               name="t", method="automated")
            ev = EvidenceObject(organization_id=org, system_id=sid, title="e")
            s.add_all([poam, risk, scan, test, ev])
            await s.flush()
            ids[sid] = {"poam": poam.id, "risk": risk.id, "scan": scan.id,
                        "control_test": test.id, "evidence_object": ev.id, "capability": cap}

    def keys(sid: int) -> set[str]:
        i = ids[sid]
        return {
            f"control:{sid}:{control}", f"ksi:{sid}:{ksi_id}",
            f"capability:{sid}:{i['capability']}", f"poam:{i['poam']}",
            f"risk:{i['risk']}", f"scan:{i['scan']}",
            f"control_test:{i['control_test']}",
            f"evidence_object:{i['evidence_object']}",
        }

    # Positive counterpart: with both systems live, every kind is present.
    assert (await _build(org))[0] == "ok"
    nodes = await _nodes(org)
    assert keys(live) <= set(nodes) and keys(gone) <= set(nodes)

    async with session_scope() as s:
        sysm = await s.get(System, gone)
        assert sysm is not None
        sysm.deleted_at = datetime.now(UTC)
    status, detail = await _build(org)
    assert status == "ok", detail
    nodes = await _nodes(org)
    assert keys(live) <= set(nodes)  # the live system's equivalents remain
    assert not (keys(gone) & set(nodes)), keys(gone) & set(nodes)


async def test_a_connector_is_not_linked_to_systems_it_does_not_feed() -> None:
    org, _sid = await _org_and_system()
    async with session_scope() as s:
        s.add(ConnectorConfig(organization_id=org, name="AWS prod", connector_type="aws"))
    await _build(org)
    assert not [e for e in await _edges(org) if "connector:" in e[0] + e[1]]


def _load_0098() -> Any:
    path = Path(__file__).parents[1] / "migrations/versions/0098_assurance_edge_source.py"
    spec = importlib.util.spec_from_file_location("m0098", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_migration_0098_labels_old_edges_then_drops_confidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``op`` is faked: this never touches the shared test database."""
    mod = _load_0098()
    calls: list[tuple[Any, ...]] = []
    monkeypatch.setattr(
        mod.op, "add_column",
        lambda table, col, **k: calls.append(("add", col.name, col.nullable)), raising=False,
    )
    monkeypatch.setattr(
        mod.op, "execute", lambda sql: calls.append(("sql", str(sql))), raising=False
    )
    monkeypatch.setattr(
        mod.op, "alter_column",
        lambda table, col, **k: calls.append(("alter", col, k.get("nullable"))), raising=False,
    )
    monkeypatch.setattr(
        mod.op, "drop_column", lambda table, col, **k: calls.append(("drop", col)), raising=False
    )
    mod.upgrade()
    assert [c[0] for c in calls] == ["add", "sql", "alter", "drop"]
    assert calls[0][1:] == ("source", True)
    assert "unsourced:pre-0098" in calls[1][1]
    assert calls[2] == ("alter", "source", False)
    assert calls[3] == ("drop", "confidence")
    calls.clear()
    mod.downgrade()
    assert [c[:2] for c in calls] == [("add", "confidence"), ("drop", "source")]


# ── Task 2: control nodes are real controls ──────────────────────────────────


def test_fold_control_places_rows_on_the_control_they_decompose() -> None:
    assert builder.fold_control("AC-02", None) == ("AC-2", True)
    assert builder.fold_control("AC-02(01)", None) == ("AC-2(1)", True)
    assert builder.fold_control("AC-02a.[01]", "AC-02") == ("AC-2", True)
    assert builder.fold_control("AC-02_ODP[01]", "AC-02") == ("AC-2", True)
    # Neither names a control: shown as recorded, never dropped or guessed.
    assert builder.fold_control("AC-06(01).b", "AC-06(01).b") == ("AC-06(01).b", False)


async def test_objective_rows_fold_into_one_node_and_the_worst_status_wins() -> None:
    org, sid = await _org_and_system()
    await _implement(sid, "AC-02", "implemented")
    await _implement(sid, f"AC-02a.[01]x{next(_SEQ)}", "planned", sequence_control="AC-02")
    await _build(org)
    nodes = await _nodes(org)
    controls = {k: v for k, v in nodes.items() if k.startswith("control:")}
    assert list(controls) == [f"control:{sid}:AC-2"]
    node = controls[f"control:{sid}:AC-2"]
    assert node["status"] == "planned" and node["metadata"]["rows"] == 2
    assert node["metadata"]["placed"] is True


async def test_a_row_that_names_no_control_is_shown_unplaced() -> None:
    org, sid = await _org_and_system()
    ident = f"ZZ-weird-{next(_SEQ)}"
    await _implement(sid, ident, "partial")
    await _build(org)
    node = (await _nodes(org))[f"control:{sid}:{ident}"]
    assert node["metadata"]["placed"] is False


async def test_owners_of_every_folded_row_are_listed() -> None:
    from ccf.models import User  # noqa: PLC0415

    org, sid = await _org_and_system()
    async with session_scope() as s:
        a = User(email=f"a{next(_SEQ)}@g.test", full_name="Ana Owner", organization_id=org)
        b = User(email=f"b{next(_SEQ)}@g.test", full_name=None, organization_id=org)
        s.add_all([a, b])
        await s.flush()
        a_id, b_id, b_email = a.id, b.id, b.email
    await _implement(sid, "AC-03", owner_user_id=a_id)
    await _implement(sid, f"AC-03b.x{next(_SEQ)}", sequence_control="AC-03", owner_user_id=b_id)
    await _build(org)
    owners = (await _nodes(org))[f"control:{sid}:AC-3"]["metadata"]["owners"]
    assert owners == sorted(["Ana Owner", b_email])


async def test_evidence_still_reaches_its_system_through_the_folded_control() -> None:
    org, sid = await _org_and_system()
    await _implement(sid, "AC-02", evidence_title="screenshot")
    await _build(org)
    edges = await _edges(org)
    has_control = (f"system:{sid}", f"control:{sid}:AC-2", "has_control", "control_implementations")
    assert has_control in edges
    assert any(
        e[0] == f"control:{sid}:AC-2" and e[1].startswith("evidence:") for e in edges
    )


async def test_an_agent_reaches_a_control_by_row_id_or_by_canonical_id() -> None:
    from ccf.models_ai_agents import AiAgent  # noqa: PLC0415

    org, sid = await _org_and_system()
    impl_id = await _implement(sid, "AC-02")
    await _implement(sid, "AU-02")
    async with session_scope() as s:
        s.add(AiAgent(organization_id=org, name="Triage bot", system_id=sid,
                      control_ids=[impl_id, "au-2"]))
    await _build(org)
    edges = {(e[0].split(":")[0], e[1], e[3]) for e in await _edges(org)}
    assert ("ai_agent", f"control:{sid}:AC-2", "ai_agents") in edges
    assert ("ai_agent", f"control:{sid}:AU-2", "ai_agents") in edges


# ── Task 3: capabilities, KSIs, tests and connectors ─────────────────────────


async def _capability(org_id: int, system_id: int, *, controls: list[str],
                      ksis: tuple[str, ...] = (), title: str = "MFA") -> int:
    from ccf.models import SystemComponent  # noqa: PLC0415
    from ccf.models_capability import (  # noqa: PLC0415
        Capability,
        CapabilityComponent,
        CapabilityControl,
        CapabilityKsi,
    )

    async with session_scope() as s:
        cap = Capability(organization_id=org_id, key=f"cap-{next(_SEQ)}", title=title,
                         status="implemented")
        comp = SystemComponent(organization_id=org_id, system_id=system_id, type="software",
                               title=f"IdP {next(_SEQ)}")
        s.add_all([cap, comp])
        await s.flush()
        s.add(CapabilityComponent(organization_id=org_id, capability_id=cap.id,
                                  component_id=comp.id))
        s.add_all([CapabilityControl(organization_id=org_id, capability_id=cap.id,
                                     control_id=c) for c in controls])
        s.add_all([CapabilityKsi(organization_id=org_id, capability_id=cap.id,
                                 ksi_identifier=k) for k in ksis])
        await s.flush()
        return cap.id


async def _seeded_ksi_with_a_control() -> tuple[int, str, str]:
    """``(ksi row id, identifier, canonical control)`` for a current KSI."""
    from ccf.catalog.canonical import canonicalize  # noqa: PLC0415
    from ccf.fedramp20x import catalog  # noqa: PLC0415

    async with session_scope() as s:
        await catalog.seed_ksis(s)
    async with session_scope() as s:
        for k in (await s.execute(catalog.current_ksis())).scalars():
            refs = {c.value for r in k.nist_refs or [] if (c := canonicalize(str(r)))}
            if len(refs) >= 2:
                return k.id, k.identifier, sorted(refs)[0]
    raise AssertionError("no current KSI names two distinct 800-53 controls")


async def test_a_capability_links_to_the_controls_and_ksis_it_claims() -> None:
    from ccf.models import KSIState  # noqa: PLC0415

    ksi_id, ksi_ident, control = await _seeded_ksi_with_a_control()
    org, sid = await _org_and_system()
    await _implement(sid, control)
    async with session_scope() as s:
        s.add(KSIState(system_id=sid, ksi_id=ksi_id, status="pass"))
    cap = await _capability(org, sid, controls=[control], ksis=[ksi_ident])
    assert (await _build(org))[0] == "ok"
    edges = await _edges(org)
    assert (f"capability:{sid}:{cap}", f"control:{sid}:{control}", "addresses",
            "capability_controls") in edges
    assert (f"capability:{sid}:{cap}", f"ksi:{sid}:{ksi_id}", "satisfies",
            "capability_ksis") in edges


async def test_a_ksi_links_to_the_controls_the_system_implements_only() -> None:
    from ccf.catalog.canonical import canonicalize  # noqa: PLC0415
    from ccf.models import KSI, KSIState  # noqa: PLC0415

    ksi_id, ksi_ident, control = await _seeded_ksi_with_a_control()
    async with session_scope() as s:
        ksi = await s.get(KSI, ksi_id)
        assert ksi is not None
        refs = {c.value for r in ksi.nist_refs or [] if (c := canonicalize(str(r)))}
        row_source = ksi.source
    assert row_source  # a seeded row records where its mappings came from
    assert len(refs) >= 2 and control in refs  # the KSI maps to more than the one implemented
    org, sid = await _org_and_system()
    await _implement(sid, control)
    async with session_scope() as s:
        s.add(KSIState(system_id=sid, ksi_id=ksi_id, status="pass"))
    assert (await _build(org))[0] == "ok"
    nodes = await _nodes(org)
    assert nodes[f"ksi:{sid}:{ksi_id}"]["label"] == ksi_ident
    ksi_edges = [e for e in await _edges(org) if e[0] == f"ksi:{sid}:{ksi_id}"]
    # The edge names the row's own source, not the vendored dataset's version.
    assert ksi_edges == [(f"ksi:{sid}:{ksi_id}", f"control:{sid}:{control}", "maps_to",
                          row_source)]


async def _ksi_system_with_source(source: str | None) -> tuple[int, int, int, str]:
    """``(org, system, ksi id, control)`` built with the KSI row's ``source``
    set to ``source``. The caller restores the row (shared catalog)."""
    from ccf.models import KSI, KSIState  # noqa: PLC0415

    ksi_id, _ident, control = await _seeded_ksi_with_a_control()
    async with session_scope() as s:
        row = await s.get(KSI, ksi_id)
        assert row is not None
        row.source = source
    org, sid = await _org_and_system()
    await _implement(sid, control)
    async with session_scope() as s:
        s.add(KSIState(system_id=sid, ksi_id=ksi_id, status="pass"))
    return org, sid, ksi_id, control


async def _restore_ksi_source(ksi_id: int, source: str | None) -> None:
    from ccf.models import KSI  # noqa: PLC0415

    async with session_scope() as s:
        row = await s.get(KSI, ksi_id)
        assert row is not None
        row.source = source


async def _ksi_source(ksi_id: int) -> str | None:
    from ccf.models import KSI  # noqa: PLC0415

    async with session_scope() as s:
        row = await s.get(KSI, ksi_id)
        assert row is not None
        return row.source


async def test_a_ksi_edge_names_a_phase_one_rows_own_source() -> None:
    """A row seeded from the earlier catalog is not labelled as FedRAMP's dataset."""
    ksi_id, _ident, _control = await _seeded_ksi_with_a_control()
    original = await _ksi_source(ksi_id)
    phase_one = "fedramp-20x-catalog:phase-one-test"
    try:
        org, sid, ksi_id, control = await _ksi_system_with_source(phase_one)
        assert (await _build(org))[0] == "ok"
        maps = [e for e in await _edges(org) if e[2] == "maps_to"]
        assert maps == [(f"ksi:{sid}:{ksi_id}", f"control:{sid}:{control}", "maps_to",
                         phase_one)]
    finally:
        await _restore_ksi_source(ksi_id, original)


@pytest.mark.parametrize("missing", [None, "", "   "])
async def test_a_ksi_row_with_no_source_draws_no_mapping(missing: str | None) -> None:
    ksi_id, _ident, _control = await _seeded_ksi_with_a_control()
    original = await _ksi_source(ksi_id)
    try:
        org, sid, ksi_id, _control = await _ksi_system_with_source(missing)
        assert (await _build(org))[0] == "ok"
        edges = await _edges(org)
        # The KSI is still drawn and assessed (the positive case) ...
        assert (f"system:{sid}", f"ksi:{sid}:{ksi_id}", "assessed_by", "ksi_states") in edges
        # ... but nothing claims where its control mapping came from.
        assert not [e for e in edges if e[2] == "maps_to"]
    finally:
        await _restore_ksi_source(ksi_id, original)


async def test_a_retired_ksi_is_not_drawn_and_maps_nothing() -> None:
    from datetime import UTC, datetime  # noqa: PLC0415

    from ccf.models import KSI, KSIState  # noqa: PLC0415

    ksi_id, _ident, control = await _seeded_ksi_with_a_control()
    org, sid = await _org_and_system()
    await _implement(sid, control)
    async with session_scope() as s:
        s.add(KSIState(system_id=sid, ksi_id=ksi_id, status="pass"))
    # Current: drawn and mapped (the positive counterpart).
    assert (await _build(org))[0] == "ok"
    assert f"ksi:{sid}:{ksi_id}" in await _nodes(org)
    assert [e for e in await _edges(org) if e[2] == "maps_to"]
    try:
        async with session_scope() as s:
            row = await s.get(KSI, ksi_id)
            assert row is not None
            row.retired_at = datetime.now(UTC)
        assert (await _build(org))[0] == "ok"
        assert f"ksi:{sid}:{ksi_id}" not in await _nodes(org)
        assert not [e for e in await _edges(org) if e[2] == "maps_to"]
        assert f"control:{sid}:{control}" in await _nodes(org)
    finally:
        async with session_scope() as s:
            row = await s.get(KSI, ksi_id)
            assert row is not None
            row.retired_at = None


async def test_control_ids_written_differently_meet_on_one_node() -> None:
    org, sid = await _org_and_system()
    await _implement(sid, "IA-02")  # catalog spelling
    cap = await _capability(org, sid, controls=["ia-2"])  # capability spelling
    assert (await _build(org))[0] == "ok"
    assert (f"capability:{sid}:{cap}", f"control:{sid}:IA-2", "addresses",
            "capability_controls") in await _edges(org)


async def test_a_capability_from_another_tenant_is_not_drawn() -> None:
    """Bound by id to org A's component, owned by org B: not in A's graph."""
    from ccf.models import SystemComponent  # noqa: PLC0415
    from ccf.models_capability import (  # noqa: PLC0415
        Capability,
        CapabilityComponent,
        CapabilityControl,
    )

    org_a, sid_a = await _org_and_system()
    org_b, _sid_b = await _org_and_system()
    await _implement(sid_a, "IA-02")
    own = await _capability(org_a, sid_a, controls=["IA-2"], title="A's MFA")
    async with session_scope() as s:  # unscoped: RLS cannot make this pass
        comp = SystemComponent(organization_id=org_a, system_id=sid_a, type="software",
                               title="A's IdP")
        cap = Capability(organization_id=org_b, key=f"b-{next(_SEQ)}", title="B's MFA",
                         status="implemented")
        s.add_all([comp, cap])
        await s.flush()
        s.add(CapabilityComponent(organization_id=org_b, capability_id=cap.id,
                                  component_id=comp.id))
        s.add(CapabilityControl(organization_id=org_b, capability_id=cap.id,
                                control_id="IA-2"))
    assert (await _build(org_a))[0] == "ok"
    caps = {k: v for k, v in (await _nodes(org_a)).items() if k.startswith("capability:")}
    assert list(caps) == [f"capability:{sid_a}:{own}"]
    assert caps[f"capability:{sid_a}:{own}"]["label"] == "A's MFA"


async def test_a_test_evidences_every_control_it_declares_with_its_check_source() -> None:
    org, sid = await _org_and_system()
    await _implement(sid, "IA-02")
    await _implement(sid, "IA-05")
    async with session_scope() as s:
        t = ControlTest(organization_id=org, system_id=sid, control_id="IA-2",
                        control_ids=["IA-2", "IA-5"], name="Secure Score: MFA",
                        method="automated", check_source="crosswalk:securescore")
        s.add(t)
        await s.flush()
        tid = t.id
    assert (await _build(org))[0] == "ok"
    edges = await _edges(org)
    for control in ("IA-2", "IA-5"):
        assert (f"control_test:{tid}", f"control:{sid}:{control}", "evidences",
                "crosswalk:securescore") in edges


async def _connector_test(org: int, sid: int, ctype: str) -> int:
    async with session_scope() as s:
        t = ControlTest(organization_id=org, system_id=sid, control_id="AC-2",
                        name=f"{ctype} check", method="connector", connector_type=ctype)
        s.add(t)
        await s.flush()
        return t.id


async def test_a_connector_reaches_a_system_only_through_its_tests() -> None:
    org, sid = await _org_and_system()
    await _system(org)  # a second system the connector must not be tied to
    tid = await _connector_test(org, sid, "aws")
    async with session_scope() as s:
        c = ConnectorConfig(organization_id=org, name="AWS prod", connector_type="aws")
        s.add(c)
        await s.flush()
        cid = c.id
    assert (await _build(org))[0] == "ok"
    edges = await _edges(org)
    assert (f"connector:{cid}", f"control_test:{tid}", "produced", "control_tests") in edges
    assert not [e for e in edges if e[0] == f"connector:{cid}" and e[1].startswith("system:")]


async def test_two_connectors_of_one_type_are_not_guessed_between() -> None:
    org, sid = await _org_and_system()
    await _connector_test(org, sid, "m365")
    async with session_scope() as s:
        s.add_all([ConnectorConfig(organization_id=org, name=f"Tenant {n}",
                                   connector_type="m365") for n in (1, 2)])
    assert (await _build(org))[0] == "ok"
    assert not [e for e in await _edges(org) if e[0].startswith("connector:")]
    reasons = [v["metadata"].get("unlinked_reason") for k, v in (await _nodes(org)).items()
               if k.startswith("connector:")]
    assert len(reasons) == 2
    assert all(r and "2 m365 connectors" in r for r in reasons)


# ── Task 4: system scope and the shared view ─────────────────────────────────


async def _two_systems_sharing_a_connector() -> tuple[int, int, int]:
    org, sid = await _org_and_system()
    other = await _system(org)
    await _implement(sid, "AC-02")
    await _implement(other, "AU-02")
    await _connector_test(org, sid, "aws")
    await _connector_test(org, other, "aws")
    async with session_scope() as s:
        s.add(ConnectorConfig(organization_id=org, name="AWS", connector_type="aws"))
    # Every absence asserted below is only meaningful if the build succeeded.
    assert (await _build(org))[0] == "ok"
    return org, sid, other


async def test_connected_scope_reaches_other_systems_through_shared_nodes() -> None:
    org, sid, other = await _two_systems_sharing_a_connector()
    async with session_scope() as s:
        g = await impact.subgraph(s, org_id=org, entity_type="system", entity_id=str(sid),
                                  max_hops=6)
    assert any(n["entity_id"] == f"{other}:AU-2" for n in g["nodes"])


async def test_system_scope_stops_at_another_systems_nodes() -> None:
    org, sid, other = await _two_systems_sharing_a_connector()
    async with session_scope() as s:
        g = await impact.subgraph(s, org_id=org, entity_type="system", entity_id=str(sid),
                                  max_hops=6, within_system=sid)
    ids = {(n["entity_type"], n["entity_id"]) for n in g["nodes"]}
    assert ("control", f"{sid}:AC-2") in ids
    assert ("control", f"{other}:AU-2") not in ids
    assert not [n for n in g["nodes"] if n["entity_type"] == "control_test"
                and n["metadata"].get("system_id") == other]


async def test_system_view_carries_the_build_and_its_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def broken(session: Any, org_id: int, g: Any) -> None:
        raise RuntimeError("risk register offline")

    monkeypatch.setattr(builder, "_risks", broken)
    org, sid = await _org_and_system()
    await _implement(sid, "AC-02")
    await _build(org)
    async with session_scope() as s:
        sysm = await s.get(System, sid)
        v = await impact.system_view(s, system=sysm)
    assert v["build_status"] == "partial" and v["built_at"]
    assert v["failed_contributors"] == {"risks": "RuntimeError: risk register offline"}


async def test_the_api_returns_the_same_view_with_scope() -> None:
    from httpx import ASGITransport, AsyncClient  # noqa: PLC0415

    from ccf.api.main import create_app  # noqa: PLC0415

    _org, sid, other = await _two_systems_sharing_a_connector()
    async with AsyncClient(transport=ASGITransport(app=create_app()),
                           base_url="http://t") as c:
        body = (await c.get(f"/api/assurance/graph/systems/{sid}?scope=system")).json()
        bad = await c.get(f"/api/assurance/graph/systems/{sid}?scope=everything")
    assert body["build_status"] == "ok" and body["failed_contributors"] == {}
    assert any(n["entity_id"] == f"{sid}:AC-2" for n in body["nodes"])
    assert all(e["provenance"] for e in body["edges"])
    assert not any(n["entity_id"] == f"{other}:AU-2" for n in body["nodes"])
    assert bad.status_code == 422


async def test_another_system_is_a_boundary_and_is_not_walked_past() -> None:
    from ccf.models_ai_agents import AiAgent  # noqa: PLC0415

    org, sid = await _org_and_system()
    other = await _system(org)
    async with session_scope() as s:
        s.add(POAM(system_id=sid, title="Own finding", status="open", severity="low"))
        s.add(POAM(system_id=other, title="Their finding", status="open", severity="low"))
        s.add(AiAgent(organization_id=org, name="Shared bot", system_id=sid,
                      system_ids=[sid, other]))
    assert (await _build(org))[0] == "ok"
    async with session_scope() as s:
        g = await impact.subgraph(s, org_id=org, entity_type="system", entity_id=str(sid),
                                  max_hops=6, within_system=sid)
    labels = {(n["entity_type"], n["label"]) for n in g["nodes"]}
    assert ("system", (await _nodes(org))[f"system:{other}"]["label"]) in labels
    # The precondition this test proves the boundary with: a POA&M names no system.
    poams = [v for k, v in (await _nodes(org)).items() if k.startswith("poam:")]
    assert len(poams) == 2 and all("system_id" not in v["metadata"] for v in poams)
    assert ("poam", "Own finding") in labels
    assert ("poam", "Their finding") not in labels


async def test_system_scope_does_not_leak_through_a_shared_vendor() -> None:
    from ccf.models import Risk, Vendor  # noqa: PLC0415
    from ccf.models_ai_agents import AiAgent  # noqa: PLC0415

    org, sid = await _org_and_system()
    other = await _system(org)
    async with session_scope() as s:
        v = Vendor(organization_id=org, name="Shared vendor")
        r = Risk(system_id=other, title="Their risk")
        s.add_all([v, r])
        await s.flush()
        s.add_all([
            AiAgent(organization_id=org, name="Agent A", system_id=sid, vendor_ids=[v.id]),
            AiAgent(organization_id=org, name="Agent B", system_id=other,
                    vendor_ids=[v.id], risk_ids=[r.id]),
            AiAgent(organization_id=org, name="Agent Both", system_id=sid,
                    system_ids=[sid, other]),
        ])
    assert (await _build(org))[0] == "ok"
    async with session_scope() as s:
        g = await impact.subgraph(s, org_id=org, entity_type="system", entity_id=str(sid),
                                  max_hops=6, within_system=sid)
    labels = {(n["entity_type"], n["label"]) for n in g["nodes"]}
    assert {("ai_agent", "Agent A"), ("vendor", "Shared vendor"),
            ("ai_agent", "Agent Both")} <= labels
    assert ("ai_agent", "Agent B") not in labels
    assert ("risk", "Their risk") not in labels


# ── Task 6: the /graph page ──────────────────────────────────────────────────


async def _page(path: str) -> Any:
    from httpx import ASGITransport, AsyncClient  # noqa: PLC0415

    from ccf.api.main import create_app  # noqa: PLC0415

    async with AsyncClient(transport=ASGITransport(app=create_app()),
                           base_url="http://t") as c:
        return await c.get(path)


async def _post(path: str, data: dict[str, str]) -> Any:
    from httpx import ASGITransport, AsyncClient  # noqa: PLC0415

    from ccf.api.main import create_app  # noqa: PLC0415

    async with AsyncClient(transport=ASGITransport(app=create_app()),
                           base_url="http://t") as c:
        return await c.post(path, data=data, follow_redirects=False)


async def test_the_page_draws_a_built_system_with_tables_matching_the_view() -> None:
    org, sid = await _org_and_system()
    await _implement(sid, "AC-02", evidence_title="screenshot")
    assert (await _build(org))[0] == "ok"
    r = await _page(f"/graph?system_id={sid}")
    assert r.status_code == 200
    async with session_scope() as s:
        v = await impact.system_view(s, system=await s.get(System, sid))
    html = r.text
    assert len(v["nodes"]) > 1 and len(v["edges"]) > 0
    assert html.count('data-graph-node-row') == len(v["nodes"])
    assert html.count('data-graph-edge-row') == len(v["edges"])
    assert "control_implementations" in html  # provenance is shown, not hidden
    assert '/static/vendor/cytoscape.min.js' in html and 'id="graph-data"' in html


async def test_the_page_says_not_built_rather_than_drawing_nothing() -> None:
    _org, sid = await _org_and_system()
    r = await _page(f"/graph?system_id={sid}")
    assert "Not built yet" in r.text and 'name="return_to" value="graph"' in r.text
    assert 'id="graph-canvas"' not in r.text


async def test_a_system_added_after_the_build_says_so() -> None:
    org, _sid = await _org_and_system()
    assert (await _build(org))[0] == "ok"
    late = await _system(org)
    r = await _page(f"/graph?system_id={late}")
    assert "not in the graph yet" in r.text and 'id="graph-canvas"' not in r.text


async def test_a_system_with_no_relationships_says_so() -> None:
    org, sid = await _org_and_system()
    assert (await _build(org))[0] == "ok"
    r = await _page(f"/graph?system_id={sid}")
    assert "No recorded relationships" in r.text and 'id="graph-canvas"' not in r.text


async def test_a_failed_contributor_is_named_on_the_page(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def broken(session: Any, org_id: int, g: Any) -> None:
        raise RuntimeError("risk register offline")

    monkeypatch.setattr(builder, "_risks", broken)
    org, sid = await _org_and_system()
    await _implement(sid, "AC-02")
    await _build(org)
    html = (await _page(f"/graph?system_id={sid}")).text
    # The embedded JSON also carries the failure, so look only at the visible page.
    visible = html.split('<script type="application/json"')[0]
    assert "Part of the graph could not be built" in visible
    assert "<strong>risks</strong>: RuntimeError: risk register offline" in visible


async def test_a_title_with_markup_is_shown_as_text() -> None:
    org, sid = await _org_and_system()
    await _implement(sid, "AC-02")
    await _capability(org, sid, controls=["AC-2"], title='<img src=x onerror="alert(1)">')
    assert (await _build(org))[0] == "ok"
    html = (await _page(f"/graph?system_id={sid}")).text
    assert "&lt;img src=x" in html  # the table shows it as text (the positive case)
    assert '<img src=x onerror="alert(1)">' not in html
    assert "\\u003cimg" in html  # the embedded data escapes it too


async def test_a_deleted_system_is_not_drawn() -> None:
    from datetime import UTC, datetime  # noqa: PLC0415

    org, sid = await _org_and_system()
    await _build(org)
    assert (await _page(f"/graph?system_id={sid}")).status_code == 200
    async with session_scope() as s:
        (await s.get(System, sid)).deleted_at = datetime.now(UTC)
    r = await _page(f"/graph?system_id={sid}")
    assert r.status_code == 404


async def test_the_nav_and_the_assurance_page_link_to_the_graph() -> None:
    _org, sid = await _org_and_system()
    html = (await _page("/assurance")).text
    assert 'href="/graph"' in html and f'href="/graph?system_id={sid}"' in html


async def test_the_assurance_page_marks_a_partial_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org, sid = await _org_and_system()
    await _implement(sid, "AC-02")
    assert (await _build(org))[0] == "ok"
    html = (await _page("/assurance")).text
    assert '<span class="chip chip--ok">built</span>' in html  # the positive case
    assert 'data-build-status="partial"' not in html

    async def broken(session: Any, org_id: int, g: Any) -> None:
        raise RuntimeError("risk register offline")

    monkeypatch.setattr(builder, "_risks", broken)
    assert (await _build(org))[0] == "partial"
    html = (await _page("/assurance")).text
    assert 'data-build-status="partial"' in html
    assert '<span class="chip chip--ok">built</span>' not in html
    assert "Not built: risks." in html


async def test_rebuild_returns_only_to_a_fixed_destination() -> None:
    _org, sid = await _org_and_system()
    back = await _post("/assurance/rebuild", {"return_to": "graph", "system_id": str(sid)})
    assert back.status_code == 303 and back.headers["location"] == f"/graph?system_id={sid}"
    for hostile in ("https://evil.example/", "//evil.example", "/admin"):
        r = await _post("/assurance/rebuild", {"return_to": hostile, "system_id": str(sid)})
        assert r.status_code == 303 and r.headers["location"] == "/assurance"
    # "graph" without a system id has nowhere to return to
    r = await _post("/assurance/rebuild", {"return_to": "graph"})
    assert r.headers["location"] == "/assurance"


# ── Task 6 fix round 1 ───────────────────────────────────────────────────────


async def test_with_a_failed_contributor_absence_is_not_stated_as_fact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def broken(session: Any, org_id: int, g: Any) -> None:
        raise RuntimeError("offline")

    # A failed ``risks`` contributor: the system is built but has no edges.
    monkeypatch.setattr(builder, "_risks", broken)
    org, sid = await _org_and_system()
    await _build(org)
    visible = (await _page(f"/graph?system_id={sid}")).text.split(
        '<script type="application/json"')[0]
    assert "No relationships in the parts that were built." in visible
    assert "No recorded relationships" not in visible


async def test_with_the_systems_contributor_failed_the_page_does_not_blame_a_late_add(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def broken(session: Any, org_id: int, g: Any) -> None:
        raise RuntimeError("offline")

    monkeypatch.setattr(builder, "_systems", broken)
    org, sid = await _org_and_system()
    await _build(org)
    visible = (await _page(f"/graph?system_id={sid}")).text
    assert "because part of the build failed" in visible
    assert "added after the last build" not in visible


async def test_choose_a_system_and_the_picker_excludes_deleted_names() -> None:
    from datetime import UTC, datetime  # noqa: PLC0415

    org, live = await _org_and_system()
    gone = await _system(org)
    async with session_scope() as s:
        live_name = (await s.get(System, live)).name
        gone_name = (await s.get(System, gone)).name
        (await s.get(System, gone)).deleted_at = datetime.now(UTC)
    html = (await _page("/graph")).text
    assert "Choose a system to draw its graph." in html
    assert live_name in html and gone_name not in html


async def test_an_organization_with_no_systems_says_so() -> None:
    from types import SimpleNamespace  # noqa: PLC0415

    from ccf.api.routes.ui_grc import graph_page  # noqa: PLC0415

    async with session_scope() as s:
        empty = Organization(name=f"Empty Org {next(_SEQ)}")
        s.add(empty)
        await s.flush()
        org_id = empty.id
    request = SimpleNamespace(state=SimpleNamespace(principal=SimpleNamespace(org_id=org_id)))
    async with session_scope() as s:
        resp = await graph_page(request, None, s)  # type: ignore[arg-type]
    assert "No systems yet." in resp.body.decode()


async def test_the_page_lists_nodes_in_a_stable_order() -> None:
    org, sid = await _org_and_system()
    await _implement(sid, "AC-02")
    await _implement(sid, "AU-02")
    assert (await _build(org))[0] == "ok"
    async with session_scope() as s:
        v = await impact.system_view(s, system=await s.get(System, sid))
    keys = [(n["entity_type"], n["label"], n["id"]) for n in v["nodes"]]
    assert len(keys) > 2 and keys == sorted(keys)
    ekeys = [(e["source"], e["target"], e["relationship_type"]) for e in v["edges"]]
    assert ekeys == sorted(ekeys)


async def test_the_legend_is_server_rendered_without_script() -> None:
    _org, sid = await _org_and_system()
    html = (await _page(f"/graph?system_id={sid}")).text
    # not-built page has no legend; the built one does
    assert 'id="graph-legend"' not in html
    org, sid2 = await _org_and_system()
    await _implement(sid2, "AC-02")
    assert (await _build(org))[0] == "ok"
    html = (await _page(f"/graph?system_id={sid2}")).text
    assert 'id="graph-legend"' in html and "var(--danger)" in html
    assert 'id="graph-notice"' in html and "hidden" not in html.split('id="graph-notice"')[1][:60]


# ── Final review fixes: the page ─────────────────────────────────────────────


async def test_another_parts_failure_does_not_blame_the_build_for_a_late_system(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def broken(session: Any, org_id: int, g: Any) -> None:
        raise RuntimeError("offline")

    monkeypatch.setattr(builder, "_risks", broken)
    org, _sid = await _org_and_system()
    assert (await _build(org))[0] == "partial"
    late = await _system(org)
    visible = (await _page(f"/graph?system_id={late}")).text.split(
        '<script type="application/json"')[0]
    assert "Part of the graph could not be built" in visible  # the failure is still shown
    assert "added after the last build" in visible
    assert "because part of the build failed" not in visible


async def test_with_no_owners_recorded_the_page_says_so_instead_of_a_picker() -> None:
    org, sid = await _org_and_system()
    await _implement(sid, "AC-02")
    assert (await _build(org))[0] == "ok"
    html = (await _page(f"/graph?system_id={sid}")).text
    assert 'id="graph-canvas"' in html  # a drawn graph, so the controls row is rendered
    assert "No owners are recorded for this system's controls." in html
    assert 'id="graph-owner"' not in html


async def test_with_an_owner_recorded_the_page_offers_the_picker() -> None:
    from ccf.models import User  # noqa: PLC0415

    org, sid = await _org_and_system()
    async with session_scope() as s:
        u = User(email=f"own{next(_SEQ)}@g.test", full_name="Olu Owner", organization_id=org)
        s.add(u)
        await s.flush()
        uid = u.id
    await _implement(sid, "AC-02", owner_user_id=uid)
    assert (await _build(org))[0] == "ok"
    html = (await _page(f"/graph?system_id={sid}")).text
    assert 'id="graph-owner"' in html
    assert "No owners are recorded" not in html


async def test_the_page_embeds_the_node_limit_and_says_it_is_drawing() -> None:
    org, sid = await _org_and_system()
    await _implement(sid, "AC-02")
    assert (await _build(org))[0] == "ok"
    html = (await _page(f"/graph?system_id={sid}")).text
    assert 'data-limit="3000"' in html
    # Server-rendered, so a page whose script never runs does not show a blank notice.
    notice = html.split('id="graph-notice"')[1].split("</p>")[0]
    assert "Drawing the graph…" in notice


async def test_choose_a_system_with_nothing_chosen_is_the_picker_not_an_error() -> None:
    _org, _sid = await _org_and_system()
    r = await _page("/graph?system_id=")
    assert r.status_code == 200
    assert "Choose a system to draw its graph." in r.text
    r = await _page("/graph?system_id=%20")
    assert r.status_code == 200 and "Choose a system to draw its graph." in r.text


@pytest.mark.parametrize("bad", ["abc", "1.5", "-3", "١٢"])
async def test_a_system_id_that_is_not_a_number_is_not_found(bad: str) -> None:
    _org, sid = await _org_and_system()
    assert (await _page(f"/graph?system_id={sid}")).status_code == 200  # the positive case
    r = await _page(f"/graph?system_id={bad}")
    assert r.status_code == 404


async def test_an_over_long_system_id_is_not_found_rather_than_an_error() -> None:
    """``int()`` raises ValueError past 4,300 digits: that was a 500."""
    _org, sid = await _org_and_system()
    assert (await _page(f"/graph?system_id={sid}")).status_code == 200  # the positive case
    assert (await _page(f"/graph?system_id={'1' * 5000}")).status_code == 404
    assert (await _page(f"/graph?system_id={'1' * 19}")).status_code == 404
