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
