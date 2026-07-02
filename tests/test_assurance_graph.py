"""Assurance graph — build, impact traversal, RLS isolation, audit on rebuild."""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.assurance import builder, impact
from ccf.config import get_settings
from ccf.db import session_scope, set_session_tenant
from ccf.models import (
    POAM,
    AuditLog,
    Control,
    ControlImplementation,
    Evidence,
    Organization,
    System,
)
from ccf.models_assurance import AssuranceEdge, AssuranceNode

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _seed_system_with_control_and_evidence(org_name: str) -> tuple[int, int, int]:
    """Create org + system + one control implementation + evidence + POA&M."""
    async with session_scope() as s:
        org = Organization(name=org_name)
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"{org_name}-sys", baseline="moderate")
        s.add(sysm)
        await s.flush()
        control = (
            await s.execute(select(Control).limit(1))
        ).scalar_one_or_none()
        if control is None:
            control = Control(identifier="AC-2", control_name="Account Management")
            s.add(control)
            await s.flush()
        impl = ControlImplementation(
            system_id=sysm.id, control_id=control.id, status="implemented"
        )
        s.add(impl)
        await s.flush()
        ev = Evidence(implementation_id=impl.id, kind="document", title="AC-2 screenshot")
        s.add(ev)
        s.add(POAM(system_id=sysm.id, title="Fix logging", severity="high", status="open"))
        await s.flush()
        return org.id, sysm.id, ev.id


@pytest.mark.asyncio
async def test_build_creates_nodes_and_edges() -> None:
    org_id, _sys_id, _ev_id = await _seed_system_with_control_and_evidence("GraphBuildOrg")
    async with session_scope() as s:
        run = await builder.rebuild_org(s, org_id)
        assert run.status == "ok"
        assert run.node_count >= 3  # system + control + evidence (+ poam)
    async with session_scope() as s:
        types = {
            n.entity_type
            for n in (
                await s.execute(
                    select(AssuranceNode).where(AssuranceNode.organization_id == org_id)
                )
            ).scalars().all()
        }
        assert {"system", "control", "evidence", "poam"} <= types
        edges = (
            await s.execute(
                select(AssuranceEdge).where(AssuranceEdge.organization_id == org_id)
            )
        ).scalars().all()
        assert any(e.relationship_type == "supported_by" for e in edges)


@pytest.mark.asyncio
async def test_impact_traversal_from_evidence_reaches_system() -> None:
    org_id, _sys_id, ev_id = await _seed_system_with_control_and_evidence("GraphImpactOrg")
    async with session_scope() as s:
        await builder.rebuild_org(s, org_id)
    async with session_scope() as s:
        result = await impact.impact_for(
            session=s, org_id=org_id, entity_type="evidence", entity_id=str(ev_id)
        )
        assert result["root"] is not None
        assert "control" in result["affected"]
        assert "system" in result["affected"]  # evidence → control → system


@pytest.mark.asyncio
async def test_missing_entity_returns_empty_impact() -> None:
    async with session_scope() as s:
        result = await impact.impact_for(
            session=s, org_id=None, entity_type="evidence", entity_id="99999999"
        )
        assert result["root"] is None
        assert result["affected_count"] == 0


@pytest.mark.asyncio
async def test_rebuild_route_emits_audit_and_returns_counts() -> None:
    _org_id, _sys, _ev = await _seed_system_with_control_and_evidence("GraphRouteOrg")
    async with AsyncClient(
        transport=ASGITransport(app=create_app()), base_url="http://t"
    ) as c:
        r = await c.post("/api/assurance/graph/rebuild")
        assert r.status_code == 200, r.text
        assert any(row["nodes"] > 0 for row in r.json()["rebuilt"])
    async with session_scope() as s:
        audited = (
            await s.execute(
                select(AuditLog).where(
                    AuditLog.entity_type == "assurance", AuditLog.action == "create"
                )
            )
        ).scalars().first()
        assert audited is not None  # POST is auto-audited by the middleware


@pytest.mark.asyncio
async def test_rls_prevents_cross_tenant_graph_leakage() -> None:
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")
    org_a, _sa, _ea = await _seed_system_with_control_and_evidence("GraphRlsA")
    org_b, _sb, _eb = await _seed_system_with_control_and_evidence("GraphRlsB")
    async with session_scope() as s:
        await builder.rebuild_org(s, org_a)
        await builder.rebuild_org(s, org_b)
    async with session_scope() as s:
        await set_session_tenant(s, org_a)
        orgs = {
            n.organization_id
            for n in (await s.execute(select(AssuranceNode))).scalars().all()
        }
        assert orgs == {org_a}  # tenant A cannot see B's graph
