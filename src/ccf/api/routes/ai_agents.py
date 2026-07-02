"""AI agent governance API — inventory, risk, approval, monitoring, kill-switch."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...ai_governance import service as gov
from ...assurance import impact as assurance_impact
from ...auth import Principal
from ...governance import bus
from ...models_ai_agents import (
    AiAgent,
    AiAgentIncident,
    AiAgentMonitoringEvent,
)
from ..auth_deps import get_principal
from ..deps import get_session

router = APIRouter(prefix="/api/ai-agents", tags=["ai-agents"])


class AgentIn(BaseModel):
    name: str
    description: str | None = None
    owner: str | None = None
    business_purpose: str | None = None
    system_id: int | None = None
    model_provider: str | None = None
    vendor_id: int | None = None
    autonomy_level: str = Field("low", pattern=r"^(low|medium|high|full)$")
    human_oversight: str = "human_in_loop"
    external_action_capability: bool = False
    external_communication: bool = False
    production_access: bool = False
    regulated_data_access: bool = False
    data_classification: str | None = None
    financial_impact: str = Field("low", pattern=r"^(low|moderate|high)$")
    operational_impact: str = Field("low", pattern=r"^(low|moderate|high)$")
    monitoring_coverage: str = Field("none", pattern=r"^(none|partial|full)$")
    evaluation_coverage: str = Field("none", pattern=r"^(none|partial|full)$")
    tools: list[Any] = Field(default_factory=list)
    system_ids: list[Any] = Field(default_factory=list)
    vendor_ids: list[Any] = Field(default_factory=list)
    policy_ids: list[Any] = Field(default_factory=list)
    control_ids: list[Any] = Field(default_factory=list)
    risk_ids: list[Any] = Field(default_factory=list)


class AgentUpdate(BaseModel):
    name: str | None = None
    owner: str | None = None
    autonomy_level: str | None = None
    human_oversight: str | None = None
    production_access: bool | None = None
    regulated_data_access: bool | None = None
    monitoring_coverage: str | None = None
    evaluation_coverage: str | None = None
    next_review_on: str | None = None


class MonitoringIn(BaseModel):
    event_type: str
    severity: str = Field("info", pattern=r"^(info|warning|critical)$")
    detail: str | None = None


class IncidentIn(BaseModel):
    title: str
    severity: str = "moderate"
    detail: str | None = None


class ReviewIn(BaseModel):
    decision: str = Field(..., pattern=r"^(approved|rejected)$")
    note: str | None = None


class KillSwitchIn(BaseModel):
    reason: str | None = None


def _out(a: AiAgent) -> dict[str, Any]:
    return {
        "id": a.id, "name": a.name, "owner": a.owner, "system_id": a.system_id,
        "vendor_id": a.vendor_id, "model_provider": a.model_provider,
        "autonomy_level": a.autonomy_level, "human_oversight": a.human_oversight,
        "production_access": a.production_access, "regulated_data_access": a.regulated_data_access,
        "external_action_capability": a.external_action_capability,
        "monitoring_coverage": a.monitoring_coverage, "approval_status": a.approval_status,
        "risk_rating": a.risk_rating, "risk_score": a.risk_score,
        "kill_switch_status": a.kill_switch_status, "next_review_on": a.next_review_on,
        "tools": a.tools, "system_ids": a.system_ids, "vendor_ids": a.vendor_ids,
        "policy_ids": a.policy_ids, "control_ids": a.control_ids, "risk_ids": a.risk_ids,
    }


async def _require(session: AsyncSession, aid: int, principal: Principal) -> AiAgent:
    a = await session.get(AiAgent, aid)
    if a is None or (principal.org_id is not None and a.organization_id != principal.org_id):
        raise HTTPException(404, "AI agent not found")
    return a


@router.get("")
async def list_agents(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    stmt = select(AiAgent).order_by(AiAgent.name)
    if principal.org_id is not None:
        stmt = stmt.where(AiAgent.organization_id == principal.org_id)
    return [_out(a) for a in (await session.execute(stmt)).scalars().all()]


@router.post("", status_code=201)
async def create_agent(
    body: AgentIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    agent = AiAgent(organization_id=principal.org_id, **body.model_dump())
    session.add(agent)
    await session.flush()
    await gov.risk_assess(session, agent, actor=principal.email)  # score on creation
    await bus.emit(
        session, verb="created", entity_type="ai_agent", entity_id=agent.id,
        summary=f"AI agent inventoried: {agent.name}", org_id=principal.org_id,
        actor=principal.email,
    )
    await session.commit()
    return _out(agent)


@router.get("/{aid}")
async def get_agent(
    aid: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    return _out(await _require(session, aid, principal))


@router.patch("/{aid}")
async def update_agent(
    aid: int,
    body: AgentUpdate,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    agent = await _require(session, aid, principal)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(agent, k, v)
    await gov.risk_assess(session, agent, actor=principal.email)  # rescore on change
    await session.commit()
    return _out(agent)


@router.post("/{aid}/risk-assess")
async def risk_assess(
    aid: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    agent = await _require(session, aid, principal)
    assessment = await gov.risk_assess(session, agent, actor=principal.email)
    await session.commit()
    return {"agent_id": aid, "score": assessment.score, "rating": assessment.rating,
            "factors": assessment.factors}


@router.post("/{aid}/approve")
async def approve(
    aid: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    agent = await _require(session, aid, principal)
    await gov.review_agent(session, agent, decision="approved", reviewer=principal.email, note=None)
    await session.commit()
    return _out(agent)


@router.post("/{aid}/reject")
async def reject(
    aid: int,
    body: ReviewIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    agent = await _require(session, aid, principal)
    await gov.review_agent(
        session, agent, decision="rejected", reviewer=principal.email, note=body.note
    )
    await session.commit()
    return _out(agent)


@router.post("/{aid}/monitoring-events", status_code=201)
async def add_monitoring_event(
    aid: int,
    body: MonitoringIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    agent = await _require(session, aid, principal)
    ev = AiAgentMonitoringEvent(
        organization_id=agent.organization_id, agent_id=agent.id, **body.model_dump()
    )
    session.add(ev)
    if body.severity in ("warning", "critical"):
        await bus.notify(
            session, category="ai_agent",
            title=f"AI agent monitoring {body.severity}: {agent.name}",
            body=body.detail, org_id=agent.organization_id, severity=body.severity,
            entity_type="ai_agent", entity_id=agent.id,
        )
    await session.commit()
    return {"id": ev.id, "agent_id": aid, "event_type": ev.event_type, "severity": ev.severity}


@router.post("/{aid}/incidents", status_code=201)
async def add_incident(
    aid: int,
    body: IncidentIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    agent = await _require(session, aid, principal)
    inc = AiAgentIncident(
        organization_id=agent.organization_id, agent_id=agent.id, **body.model_dump()
    )
    session.add(inc)
    await session.commit()
    return {"id": inc.id, "agent_id": aid, "title": inc.title, "status": inc.status}


@router.post("/{aid}/kill-switch")
async def kill_switch(
    aid: int,
    body: KillSwitchIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    agent = await _require(session, aid, principal)
    ev = await gov.engage_kill_switch(session, agent, reason=body.reason, actor=principal.email)
    await session.commit()
    return {"agent_id": aid, "kill_switch_status": agent.kill_switch_status, "event_id": ev.id}


@router.get("/{aid}/assurance-impact")
async def agent_assurance_impact(
    aid: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    await _require(session, aid, principal)
    return await assurance_impact.impact_for(
        session, org_id=principal.org_id, entity_type="ai_agent", entity_id=str(aid)
    )
