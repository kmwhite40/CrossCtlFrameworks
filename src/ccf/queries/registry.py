"""Assurance query templates — a registry of deterministic, parameterized queries.

Each template is a named, typed question over the authorization data (evidence,
implementations, POA&Ms, grants, AI agents). Runners are plain parameterized SQL
— no AI, no free-form input — so the same template + params always yields the same
answer, and results are auditable. Every runner is tenant-scoped: it filters by the
caller's ``org_id`` directly (org-owned tables) or via a join to ``ccf.systems``
(tables scoped through their system).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

Runner = Callable[[AsyncSession, dict[str, Any], int | None], Awaitable[list[dict[str, Any]]]]


@dataclass(frozen=True)
class QueryParam:
    name: str
    type: str  # int | str
    label: str
    required: bool = False
    default: Any = None


@dataclass(frozen=True)
class QueryTemplate:
    key: str
    title: str
    description: str
    category: str
    columns: list[str]
    params: list[QueryParam] = field(default_factory=list)
    run: Runner = None  # type: ignore[assignment]


async def _rows(session: AsyncSession, sql: str, binds: dict[str, Any]) -> list[dict[str, Any]]:
    result = await session.execute(text(sql), binds)
    return [dict(r) for r in result.mappings().all()]


# --- runners ----------------------------------------------------------------


async def _expired_evidence(
    session: AsyncSession, p: dict[str, Any], org_id: int | None
) -> list[dict[str, Any]]:
    sql = """
        SELECT s.name AS system, e.title, e.control_id, e.framework, e.status, e.expires_on
        FROM ccf.evidence_objects e
        LEFT JOIN ccf.systems s ON s.id = e.system_id
        WHERE (CAST(:org AS integer) IS NULL OR e.organization_id = CAST(:org AS integer))
          AND (e.status = 'expired'
               OR (e.expires_on IS NOT NULL AND e.expires_on < CURRENT_DATE))
          AND (CAST(:control_id AS text) IS NULL OR e.control_id = CAST(:control_id AS text))
        ORDER BY e.expires_on NULLS LAST, e.id
    """
    return await _rows(session, sql, {"org": org_id, "control_id": p.get("control_id")})


async def _stale_evidence(
    session: AsyncSession, p: dict[str, Any], org_id: int | None
) -> list[dict[str, Any]]:
    sql = """
        SELECT s.name AS system, e.title, e.control_id, e.expires_on
        FROM ccf.evidence_objects e
        LEFT JOIN ccf.systems s ON s.id = e.system_id
        WHERE (CAST(:org AS integer) IS NULL OR e.organization_id = CAST(:org AS integer))
          AND e.expires_on IS NOT NULL
          AND e.expires_on >= CURRENT_DATE
          AND e.expires_on < CURRENT_DATE + make_interval(days => CAST(:days AS integer))
        ORDER BY e.expires_on
    """
    return await _rows(session, sql, {"org": org_id, "days": p["days"]})


async def _controls_failing(
    session: AsyncSession, p: dict[str, Any], org_id: int | None
) -> list[dict[str, Any]]:
    sql = """
        SELECT c.identifier AS control,
               count(DISTINCT ci.system_id)::int AS systems_affected
        FROM ccf.control_implementations ci
        JOIN ccf.systems s ON s.id = ci.system_id
        JOIN ccf.controls c ON c.id = ci.control_id
        WHERE (CAST(:org AS integer) IS NULL OR s.organization_id = CAST(:org AS integer))
          AND ci.status IN ('not_implemented', 'partial')
        GROUP BY c.identifier
        HAVING count(DISTINCT ci.system_id) >= CAST(:min_systems AS integer)
        ORDER BY systems_affected DESC, control
    """
    return await _rows(session, sql, {"org": org_id, "min_systems": p["min_systems"]})


async def _overdue_poams(
    session: AsyncSession, p: dict[str, Any], org_id: int | None
) -> list[dict[str, Any]]:
    sql = """
        SELECT s.name AS system, po.title, po.severity, po.status,
               COALESCE(po.scheduled_completion, po.due_on) AS due
        FROM ccf.poams po
        JOIN ccf.systems s ON s.id = po.system_id
        WHERE (CAST(:org AS integer) IS NULL OR s.organization_id = CAST(:org AS integer))
          AND po.status <> 'closed'
          AND COALESCE(po.scheduled_completion, po.due_on) IS NOT NULL
          AND COALESCE(po.scheduled_completion, po.due_on) < CURRENT_DATE
        ORDER BY due
    """
    return await _rows(session, sql, {"org": org_id})


async def _expiring_grants(
    session: AsyncSession, p: dict[str, Any], org_id: int | None
) -> list[dict[str, Any]]:
    sql = """
        SELECT g.label, g.kind, g.expires_at
        FROM ccf.external_access_grants g
        WHERE (CAST(:org AS integer) IS NULL OR g.organization_id = CAST(:org AS integer))
          AND NOT g.revoked
          AND g.expires_at IS NOT NULL
          AND g.expires_at >= now()
          AND g.expires_at < now() + make_interval(days => CAST(:days AS integer))
        ORDER BY g.expires_at
    """
    return await _rows(session, sql, {"org": org_id, "days": p["days"]})


async def _high_risk_agents(
    session: AsyncSession, p: dict[str, Any], org_id: int | None
) -> list[dict[str, Any]]:
    sql = """
        SELECT name, autonomy_level, risk_rating, monitoring_coverage, production_access
        FROM ccf.ai_agents
        WHERE (CAST(:org AS integer) IS NULL OR organization_id = CAST(:org AS integer))
          AND production_access = true
          AND (risk_rating IN ('high', 'critical') OR monitoring_coverage = 'none')
        ORDER BY risk_score DESC NULLS LAST, name
    """
    return await _rows(session, sql, {"org": org_id})


# --- registry ---------------------------------------------------------------

TEMPLATES: list[QueryTemplate] = [
    QueryTemplate(
        key="expired-evidence",
        title="Systems with expired evidence",
        description="Evidence objects that are expired or past their expiry date, "
        "optionally filtered to one control.",
        category="Evidence",
        columns=["system", "title", "control_id", "framework", "status", "expires_on"],
        params=[QueryParam("control_id", "str", "Control (e.g. AC-2)", required=False)],
        run=_expired_evidence,
    ),
    QueryTemplate(
        key="stale-evidence",
        title="Evidence expiring soon",
        description="Evidence with an expiry date falling within the next N days.",
        category="Evidence",
        columns=["system", "title", "control_id", "expires_on"],
        params=[QueryParam("days", "int", "Within days", required=False, default=30)],
        run=_stale_evidence,
    ),
    QueryTemplate(
        key="controls-failing-across-systems",
        title="Controls failing across systems",
        description="Controls implemented as not-implemented or partial across at "
        "least N systems.",
        category="Controls",
        columns=["control", "systems_affected"],
        params=[QueryParam("min_systems", "int", "Minimum systems", required=False, default=2)],
        run=_controls_failing,
    ),
    QueryTemplate(
        key="overdue-poams",
        title="Overdue POA&Ms",
        description="Open POA&Ms past their scheduled completion (or due) date.",
        category="Remediation",
        columns=["system", "title", "severity", "status", "due"],
        params=[],
        run=_overdue_poams,
    ),
    QueryTemplate(
        key="expiring-grants",
        title="External grants expiring soon",
        description="Active external portal grants expiring within the next N days.",
        category="External access",
        columns=["label", "kind", "expires_at"],
        params=[QueryParam("days", "int", "Within days", required=False, default=7)],
        run=_expiring_grants,
    ),
    QueryTemplate(
        key="high-risk-ai-agents",
        title="High-risk AI agents",
        description="AI agents with production access that are high/critical risk or "
        "have no monitoring.",
        category="AI governance",
        columns=["name", "autonomy_level", "risk_rating", "monitoring_coverage",
                 "production_access"],
        params=[],
        run=_high_risk_agents,
    ),
]

REGISTRY: dict[str, QueryTemplate] = {t.key: t for t in TEMPLATES}
