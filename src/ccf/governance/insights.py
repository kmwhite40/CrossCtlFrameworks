"""GRC insights — data-quality checks, unified-control analysis, exec reporting.

Pure read/aggregation over the existing model; no new tables. Complements the
operational `reliability` checks (service health) with GRC *data* health, the
crosswalk's "implement once, satisfy many" analysis, and a consolidated
executive rollup for dashboards.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..analytics import org_summary
from ..models import (
    POAM,
    Control,
    ControlImplementation,
    Evidence,
    FrameworkMapping,
    Policy,
    Risk,
    ScoringStatus,
    System,
    SystemProfile,
    Vendor,
)
from .risk import band


def _org_systems(org_id: int | None) -> Any:
    q = select(System.id)
    return q if org_id is None else q.where(System.organization_id == org_id)


async def data_quality(session: AsyncSession, *, org_id: int | None = None) -> dict[str, Any]:
    """Find GRC data gaps that undermine an assessment (item 12)."""
    today = datetime.now(UTC).date()
    sys_ids = _org_systems(org_id)
    findings: list[dict[str, Any]] = []

    async def _n(stmt: Any) -> int:
        return int((await session.execute(stmt)).scalar_one() or 0)

    # Systems without a defined profile / owner.
    findings.append(
        {
            "check": "systems_without_profile",
            "severity": "warning",
            "count": await _n(
                select(func.count(System.id))
                .where(System.id.in_(sys_ids))
                .where(~System.id.in_(select(SystemProfile.system_id)))
            ),
        }
    )
    # Practices never assessed.
    findings.append(
        {
            "check": "controls_not_assessed",
            "severity": "info",
            "count": await _n(
                select(func.count(ScoringStatus.id))
                .where(ScoringStatus.system_id.in_(sys_ids))
                .where(ScoringStatus.state == "not_assessed")
            ),
        }
    )
    # Implemented/inherited controls with no evidence attached.
    impl_no_ev = (
        select(func.count(ControlImplementation.id))
        .where(ControlImplementation.system_id.in_(sys_ids))
        .where(ControlImplementation.status.in_(("implemented", "inherited")))
        .where(~ControlImplementation.id.in_(select(Evidence.implementation_id)))
    )
    findings.append(
        {
            "check": "implemented_without_evidence",
            "severity": "warning",
            "count": await _n(impl_no_ev),
        }
    )
    # Expired evidence.
    findings.append(
        {
            "check": "expired_evidence",
            "severity": "critical",
            "count": await _n(
                select(func.count(Evidence.id))
                .join(ControlImplementation, ControlImplementation.id == Evidence.implementation_id)
                .where(ControlImplementation.system_id.in_(sys_ids))
                .where(Evidence.expires_on.is_not(None))
                .where(Evidence.expires_on < today)
            ),
        }
    )
    # Open POA&Ms without a due date.
    findings.append(
        {
            "check": "poams_without_due_date",
            "severity": "warning",
            "count": await _n(
                select(func.count(POAM.id))
                .where(POAM.system_id.in_(sys_ids))
                .where(POAM.status.in_(("open", "in_progress")))
                .where(POAM.due_on.is_(None))
            ),
        }
    )
    # Open risks without a treatment plan.
    r_stmt = select(func.count(Risk.id)).where(Risk.status == "open", Risk.treatment.is_(None))
    if org_id is not None:
        r_stmt = r_stmt.where(Risk.system_id.in_(sys_ids))
    findings.append(
        {"check": "risks_without_treatment", "severity": "warning", "count": await _n(r_stmt)}
    )
    # Vendors without a review status/date.
    v_stmt = select(func.count(Vendor.id)).where(
        Vendor.status == "active", Vendor.next_review_on.is_(None)
    )
    if org_id is not None:
        v_stmt = v_stmt.where(Vendor.organization_id == org_id)
    findings.append(
        {"check": "vendors_without_review", "severity": "info", "count": await _n(v_stmt)}
    )
    # Policies overdue for review.
    p_stmt = select(func.count(Policy.id)).where(
        Policy.next_review_on.is_not(None), Policy.next_review_on < today
    )
    if org_id is not None:
        p_stmt = p_stmt.where(Policy.organization_id == org_id)
    findings.append(
        {"check": "policies_overdue_review", "severity": "warning", "count": await _n(p_stmt)}
    )

    issues = [f for f in findings if f["count"] > 0]
    return {
        "generated_at": today.isoformat(),
        "total_issues": sum(f["count"] for f in issues),
        "checks": findings,
        "failing_checks": [f["check"] for f in issues],
        "clean": not issues,
    }


async def unified_controls(session: AsyncSession, *, limit: int = 25) -> dict[str, Any]:
    """'Implement once, satisfy many' — controls by cross-framework coverage (item 10)."""
    rows = (
        await session.execute(
            select(
                FrameworkMapping.control_id,
                func.count(func.distinct(FrameworkMapping.framework_id)).label("frameworks"),
                func.count(FrameworkMapping.id).label("mappings"),
            )
            .group_by(FrameworkMapping.control_id)
            .order_by(func.count(func.distinct(FrameworkMapping.framework_id)).desc())
            .limit(limit)
        )
    ).all()
    ctl: dict[int, str] = {
        row[0]: row[1]
        for row in (
            await session.execute(
                select(Control.id, Control.identifier).where(
                    Control.id.in_([r.control_id for r in rows] or [0])
                )
            )
        ).all()
    }
    total_controls = int(
        (
            await session.execute(select(func.count(func.distinct(FrameworkMapping.control_id))))
        ).scalar_one()
        or 0
    )
    return {
        "mapped_controls": total_controls,
        "note": "Implement a high-coverage control once to satisfy many frameworks.",
        "top_controls": [
            {
                "identifier": ctl.get(r.control_id, str(r.control_id)),
                "frameworks_covered": int(r.frameworks),
                "mappings": int(r.mappings),
            }
            for r in rows
        ],
    }


async def executive(session: AsyncSession, *, org_id: int | None = None) -> dict[str, Any]:
    """Consolidated executive rollup for dashboards/exports (item 9)."""
    today = datetime.now(UTC).date()
    summary = await org_summary(session, today=today, org_id=org_id)

    # Risk posture by residual band.
    r_stmt = select(Risk.residual_score, Risk.status)
    if org_id is not None:
        r_stmt = r_stmt.where(Risk.system_id.in_(_org_systems(org_id)))
    by_band = {"low": 0, "moderate": 0, "high": 0, "critical": 0, "unknown": 0}
    for score, status in (await session.execute(r_stmt)).all():
        if status in ("closed",):
            continue
        by_band[band(score)] += 1

    dq = await data_quality(session, org_id=org_id)
    return {
        "generated_at": today.isoformat(),
        "avg_sprs_score": summary.get("avg_sprs_score"),
        "systems_total": summary.get("systems_total"),
        "systems_by_ato": summary.get("systems_by_ato"),
        "open_poams": summary.get("open_poams"),
        "overdue_poams": summary.get("overdue_poams"),
        "poam_aging": summary.get("poam_aging"),
        "evidence": summary.get("evidence"),
        "risk_by_residual_band": by_band,
        "data_quality_issues": dq["total_issues"],
    }
