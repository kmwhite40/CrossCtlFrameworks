"""AI agent governance service — pure risk scoring + audited state changes."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..models_ai_agents import (
    AiAgent,
    AiAgentApproval,
    AiAgentKillSwitchEvent,
    AiAgentRiskAssessment,
)

# Higher = riskier. Weighted average of normalized dimensions (0..1) → 0-100.
_LEVEL3 = {"low": 0.0, "moderate": 0.5, "high": 1.0}
_AUTONOMY = {"low": 0.2, "medium": 0.5, "high": 0.8, "full": 1.0}
# Oversight REDUCES risk: more human oversight → lower contribution.
_OVERSIGHT = {"human_over_loop": 0.1, "human_on_loop": 0.4, "human_in_loop": 0.6, "none": 1.0}
_COVERAGE = {"full": 0.0, "partial": 0.5, "none": 1.0}  # less coverage → more risk

_WEIGHTS = {
    "autonomy": 2.0,
    "regulated_data_access": 2.0,
    "production_access": 2.0,
    "external_action": 2.0,
    "external_communication": 1.0,
    "financial_impact": 1.0,
    "operational_impact": 1.0,
    "human_oversight": 2.0,
    "monitoring_coverage": 1.5,
    "evaluation_coverage": 1.0,
}
_BANDS = [(80, "critical"), (60, "high"), (35, "moderate")]


def rating_for(score: float) -> str:
    for threshold, rating in _BANDS:
        if score >= threshold:
            return rating
    return "low"


def score_agent(agent: AiAgent) -> dict[str, Any]:
    """Pure risk scorer → ``{score, rating, factors}`` (higher = riskier)."""
    values = {
        "autonomy": _AUTONOMY.get(agent.autonomy_level, 0.5),
        "regulated_data_access": 1.0 if agent.regulated_data_access else 0.2,
        "production_access": 1.0 if agent.production_access else 0.2,
        "external_action": 1.0 if agent.external_action_capability else 0.1,
        "external_communication": 1.0 if agent.external_communication else 0.2,
        "financial_impact": _LEVEL3.get(agent.financial_impact, 0.0),
        "operational_impact": _LEVEL3.get(agent.operational_impact, 0.0),
        "human_oversight": _OVERSIGHT.get(agent.human_oversight, 0.6),
        "monitoring_coverage": _COVERAGE.get(agent.monitoring_coverage, 1.0),
        "evaluation_coverage": _COVERAGE.get(agent.evaluation_coverage, 1.0),
    }
    total_w = sum(_WEIGHTS.values())
    score = round(100 * sum(_WEIGHTS[k] * v for k, v in values.items()) / total_w, 1)
    factors = {
        k: {"value": round(v, 2), "weight": _WEIGHTS[k], "contribution": round(_WEIGHTS[k] * v, 2)}
        for k, v in values.items()
    }
    return {"score": score, "rating": rating_for(score), "factors": factors}


async def _audit(session: AsyncSession, **kw: Any) -> None:
    from ..api.audit import record_event  # noqa: PLC0415 — avoid import cycle

    await record_event(session, **kw)


async def risk_assess(
    session: AsyncSession, agent: AiAgent, *, actor: str | None = None
) -> AiAgentRiskAssessment:
    result = score_agent(agent)
    agent.risk_score = result["score"]
    agent.risk_rating = result["rating"]
    assessment = AiAgentRiskAssessment(
        organization_id=agent.organization_id, agent_id=agent.id,
        score=result["score"], rating=result["rating"], factors=result["factors"],
        assessed_by=actor,
    )
    session.add(assessment)
    await _audit(
        session, actor=actor or "system", action="update", entity_type="ai_agent",
        entity_id=str(agent.id),
        diff={"event": "risk_assess", "score": result["score"], "rating": result["rating"]},
    )
    await session.flush()
    return assessment


async def review_agent(
    session: AsyncSession, agent: AiAgent, *, decision: str, reviewer: str | None, note: str | None
) -> AiAgentApproval:
    if decision not in ("approved", "rejected"):
        raise ValueError("decision must be 'approved' or 'rejected'")
    agent.approval_status = decision
    agent.last_reviewed_on = datetime.now(UTC).date()
    approval = AiAgentApproval(
        organization_id=agent.organization_id, agent_id=agent.id,
        decision=decision, reviewer=reviewer, note=note,
    )
    session.add(approval)
    await _audit(
        session, actor=reviewer or "reviewer", action="update", entity_type="ai_agent",
        entity_id=str(agent.id), diff={"event": "review", "decision": decision},
    )
    await session.flush()
    return approval


async def engage_kill_switch(
    session: AsyncSession, agent: AiAgent, *, reason: str | None, actor: str | None
) -> AiAgentKillSwitchEvent:
    agent.kill_switch_status = "engaged"
    event = AiAgentKillSwitchEvent(
        organization_id=agent.organization_id, agent_id=agent.id,
        action="engage", reason=reason, actor=actor,
    )
    session.add(event)
    await _audit(
        session, actor=actor or "operator", action="update", entity_type="ai_agent",
        entity_id=str(agent.id), diff={"event": "kill_switch", "reason": reason},
    )
    await session.flush()
    return event
