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
            for ref in k.nist_refs or []:
                c = canonicalize(str(ref))
                if c is not None:
                    return k.id, k.identifier, c.value
    raise AssertionError("no current KSI names an 800-53 control")


async def test_a_capability_links_to_the_controls_and_ksis_it_claims() -> None:
    from ccf.models import KSIState  # noqa: PLC0415

    ksi_id, ksi_ident, control = await _seeded_ksi_with_a_control()
    org, sid = await _org_and_system()
    await _implement(sid, control)
    async with session_scope() as s:
        s.add(KSIState(system_id=sid, ksi_id=ksi_id, status="pass"))
    cap = await _capability(org, sid, controls=[control], ksis=[ksi_ident])
    await _build(org)
    edges = await _edges(org)
    assert (f"capability:{sid}:{cap}", f"control:{sid}:{control}", "implements",
            "capability_controls") in edges
    assert (f"capability:{sid}:{cap}", f"ksi:{sid}:{ksi_id}", "satisfies",
            "capability_ksis") in edges


async def test_a_ksi_links_to_the_controls_the_system_implements_only() -> None:
    from ccf.fedramp20x import rules  # noqa: PLC0415
    from ccf.models import KSIState  # noqa: PLC0415

    ksi_id, ksi_ident, control = await _seeded_ksi_with_a_control()
    org, sid = await _org_and_system()
    await _implement(sid, control)
    async with session_scope() as s:
        s.add(KSIState(system_id=sid, ksi_id=ksi_id, status="pass"))
    await _build(org)
    nodes = await _nodes(org)
    assert nodes[f"ksi:{sid}:{ksi_id}"]["label"] == ksi_ident
    ksi_edges = [e for e in await _edges(org) if e[0] == f"ksi:{sid}:{ksi_id}"]
    assert ksi_edges == [(f"ksi:{sid}:{ksi_id}", f"control:{sid}:{control}", "maps_to",
                          f"fedramp-rules@{rules.load_rules().version}")]


async def test_control_ids_written_differently_meet_on_one_node() -> None:
    org, sid = await _org_and_system()
    await _implement(sid, "IA-02")  # catalog spelling
    cap = await _capability(org, sid, controls=["ia-2"])  # capability spelling
    await _build(org)
    assert (f"capability:{sid}:{cap}", f"control:{sid}:IA-2", "implements",
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
    await _build(org_a)
    assert not [k for k in await _nodes(org_a) if k.startswith("capability:")]


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
    await _build(org)
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
    other = await _system(org)
    tid = await _connector_test(org, sid, "aws")
    async with session_scope() as s:
        c = ConnectorConfig(organization_id=org, name="AWS prod", connector_type="aws")
        s.add(c)
        await s.flush()
        cid = c.id
    await _build(org)
    edges = await _edges(org)
    assert (f"connector:{cid}", f"control_test:{tid}", "produced", "control_tests") in edges
    assert not [e for e in edges if e[0] == f"connector:{cid}" and e[1] == f"system:{other}"]


async def test_two_connectors_of_one_type_are_not_guessed_between() -> None:
    org, sid = await _org_and_system()
    await _connector_test(org, sid, "m365")
    async with session_scope() as s:
        s.add_all([ConnectorConfig(organization_id=org, name=f"Tenant {n}",
                                   connector_type="m365") for n in (1, 2)])
    await _build(org)
    assert not [e for e in await _edges(org) if e[0].startswith("connector:")]
    reasons = [v["metadata"].get("unlinked_reason") for k, v in (await _nodes(org)).items()
               if k.startswith("connector:")]
    assert all(r and "2 m365 connectors" in r for r in reasons)
