"""AI agent governance — inventory, risk scoring, approval, monitoring, kill-switch, graph."""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.ai_governance import score_agent
from ccf.api.main import create_app
from ccf.assurance import builder
from ccf.config import get_settings
from ccf.db import session_scope, set_session_tenant
from ccf.models import Organization, System
from ccf.models_ai_agents import AiAgent, AiAgentKillSwitchEvent
from ccf.models_assurance import AssuranceNode
from ccf.reliability.checks import run_checks

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return org.id


# --- pure risk scorer --------------------------------------------------------


def test_high_risk_agent_scores_above_low_risk() -> None:
    high = AiAgent(
        name="H", autonomy_level="full", production_access=True, regulated_data_access=True,
        external_action_capability=True, human_oversight="none", monitoring_coverage="none",
        financial_impact="high", operational_impact="high",
    )
    low = AiAgent(
        name="L", autonomy_level="low", production_access=False, regulated_data_access=False,
        external_action_capability=False, human_oversight="human_over_loop",
        monitoring_coverage="full",
    )
    assert score_agent(high)["score"] > score_agent(low)["score"]
    assert score_agent(high)["rating"] in ("high", "critical")
    assert score_agent(low)["rating"] == "low"


# --- lifecycle ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_agent_lifecycle_create_assess_approve_monitor_killswitch() -> None:
    await _org("AgentOrg")
    async with _client() as c:
        created = await c.post(
            "/api/ai-agents",
            json={"name": "Copilot", "autonomy_level": "high", "production_access": True,
                  "regulated_data_access": True, "human_oversight": "none"},
        )
        assert created.status_code == 201, created.text
        aid = created.json()["id"]
        assert created.json()["risk_rating"] in ("high", "critical")  # scored on create

        approved = await c.post(f"/api/ai-agents/{aid}/approve")
        assert approved.json()["approval_status"] == "approved"

        mon = await c.post(
            f"/api/ai-agents/{aid}/monitoring-events",
            json={"event_type": "anomalous_tool_use", "severity": "critical", "detail": "x"},
        )
        assert mon.status_code == 201

        inc = await c.post(
            f"/api/ai-agents/{aid}/incidents", json={"title": "Data exfil attempt"}
        )
        assert inc.status_code == 201

        ks = await c.post(f"/api/ai-agents/{aid}/kill-switch", json={"reason": "runaway"})
        assert ks.json()["kill_switch_status"] == "engaged"

    async with session_scope() as s:
        events = (
            await s.execute(
                select(AiAgentKillSwitchEvent).where(AiAgentKillSwitchEvent.agent_id == aid)
            )
        ).scalars().all()
        assert len(events) == 1


@pytest.mark.asyncio
async def test_unapproved_production_access_flagged_in_reliability() -> None:
    await _org("AgentRelOrg")
    async with _client() as c:
        await c.post(
            "/api/ai-agents",
            json={"name": "Unapproved", "production_access": True, "autonomy_level": "high"},
        )
    async with session_scope() as s:
        checks = await run_checks(s)
        gov = next(ch for ch in checks if ch.name == "ai_agent_governance")
        assert gov.status == "warn"


@pytest.mark.asyncio
async def test_assurance_graph_includes_agent_relationships() -> None:
    async with session_scope() as s:
        org = Organization(name="AgentGraphOrg")
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name="AgSys", baseline="moderate")
        s.add(sysm)
        await s.flush()
        agent = AiAgent(
            organization_id=org.id, name="GraphAgent", system_id=sysm.id,
            system_ids=[sysm.id],
        )
        s.add(agent)
        await s.flush()
        org_id, agent_id = org.id, agent.id
    async with session_scope() as s:
        await builder.rebuild_org(s, org_id)
    async with session_scope() as s:
        node = (
            await s.execute(
                select(AssuranceNode).where(
                    AssuranceNode.organization_id == org_id,
                    AssuranceNode.entity_type == "ai_agent",
                    AssuranceNode.entity_id == str(agent_id),
                )
            )
        ).scalar_one_or_none()
        assert node is not None


@pytest.mark.asyncio
async def test_rls_blocks_cross_tenant_agents() -> None:
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")
    org_a = await _org("AgentRlsA")
    org_b = await _org("AgentRlsB")
    async with session_scope() as s:
        s.add(AiAgent(organization_id=org_a, name="A-agent"))
        s.add(AiAgent(organization_id=org_b, name="B-agent"))
    async with session_scope() as s:
        await set_session_tenant(s, org_a)
        orgs = {a.organization_id for a in (await s.execute(select(AiAgent))).scalars().all()}
        assert orgs == {org_a}
