"""Org-wide compliance posture computations (async DB → plain dicts)."""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import (
    POAM,
    ControlImplementation,
    Evidence,
    Risk,
    System,
)
from ..scoring.service import system_score_summary

# Implementation statuses that count as "met" for coverage.
_MET_IMPL = ("implemented", "inherited")
EXPIRING_WINDOW_DAYS = 30


async def sprs_for_system(session: AsyncSession, system_id: int) -> dict[str, Any]:
    """Live SPRS summary for one system (shared with the scoring API)."""
    return await system_score_summary(session, system_id)


async def _impl_coverage(session: AsyncSession, system_id: int) -> dict[str, int]:
    rows = (
        await session.execute(
            select(ControlImplementation.status, func.count())
            .where(ControlImplementation.system_id == system_id)
            .group_by(ControlImplementation.status)
        )
    ).all()
    counts = {status: n for status, n in rows}
    total = sum(counts.values())
    met = sum(counts.get(s, 0) for s in _MET_IMPL)
    return {"total": total, "met": met, "by_status": counts}


async def systems_scorecard(session: AsyncSession, *, today: date) -> list[dict[str, Any]]:
    """Per-system scorecard: SPRS, implementation coverage, POA&M and evidence health."""
    systems = (await session.execute(select(System).order_by(System.name))).scalars().all()
    scorecards: list[dict[str, Any]] = []
    for sys in systems:
        sprs = await sprs_for_system(session, sys.id)
        coverage = await _impl_coverage(session, sys.id)
        open_poams = (
            await session.execute(
                select(func.count(POAM.id))
                .where(POAM.system_id == sys.id)
                .where(POAM.status.in_(("open", "in_progress")))
            )
        ).scalar_one()
        overdue_poams = (
            await session.execute(
                select(func.count(POAM.id))
                .where(POAM.system_id == sys.id)
                .where(POAM.status.in_(("open", "in_progress")))
                .where(POAM.due_on.is_not(None))
                .where(POAM.due_on < today)
            )
        ).scalar_one()
        evidence_total = (
            await session.execute(
                select(func.count(Evidence.id))
                .join(ControlImplementation, ControlImplementation.id == Evidence.implementation_id)
                .where(ControlImplementation.system_id == sys.id)
            )
        ).scalar_one()
        expired_evidence = (
            await session.execute(
                select(func.count(Evidence.id))
                .join(ControlImplementation, ControlImplementation.id == Evidence.implementation_id)
                .where(ControlImplementation.system_id == sys.id)
                .where(Evidence.expires_on.is_not(None))
                .where(Evidence.expires_on < today)
            )
        ).scalar_one()
        scorecards.append(
            {
                "system_id": sys.id,
                "name": sys.name,
                "baseline": sys.baseline,
                "ato_status": sys.ato_status,
                "sprs_score": sprs["score"],
                "sprs_percentage": sprs["percentage"],
                "ssp_present": sprs["ssp_present"],
                "controls_assessed": sprs["total_controls"] - sprs["state_counts"].get(
                    "not_assessed", 0
                ),
                "impl_total": coverage["total"],
                "impl_met": coverage["met"],
                "open_poams": open_poams,
                "overdue_poams": overdue_poams,
                "evidence_total": evidence_total,
                "expired_evidence": expired_evidence,
            }
        )
    return scorecards


async def poam_aging(session: AsyncSession, *, today: date) -> dict[str, Any]:
    """Aging buckets for open POA&Ms by days since identification."""
    rows = (
        (
            await session.execute(
                select(POAM).where(POAM.status.in_(("open", "in_progress")))
            )
        )
        .scalars()
        .all()
    )
    buckets = {"0-30": 0, "31-60": 0, "61-90": 0, "90+": 0, "unknown": 0}
    overdue = 0
    by_severity: dict[str, int] = {}
    for p in rows:
        if p.identified_on is None:
            buckets["unknown"] += 1
        else:
            age = (today - p.identified_on).days
            if age <= 30:
                buckets["0-30"] += 1
            elif age <= 60:
                buckets["31-60"] += 1
            elif age <= 90:
                buckets["61-90"] += 1
            else:
                buckets["90+"] += 1
        if p.due_on is not None and p.due_on < today:
            overdue += 1
        by_severity[p.severity] = by_severity.get(p.severity, 0) + 1
    return {
        "open_total": len(rows),
        "overdue": overdue,
        "buckets": buckets,
        "by_severity": by_severity,
    }


async def evidence_freshness(session: AsyncSession, *, today: date) -> dict[str, Any]:
    """Classify evidence as fresh / expiring-soon / expired by expiry date."""
    rows = (await session.execute(select(Evidence.expires_on))).all()
    horizon = today + timedelta(days=EXPIRING_WINDOW_DAYS)
    fresh = expiring = expired = no_expiry = 0
    for (expires_on,) in rows:
        if expires_on is None:
            no_expiry += 1
        elif expires_on < today:
            expired += 1
        elif expires_on <= horizon:
            expiring += 1
        else:
            fresh += 1
    return {
        "total": len(rows),
        "fresh": fresh,
        "expiring_soon": expiring,
        "expired": expired,
        "no_expiry": no_expiry,
        "window_days": EXPIRING_WINDOW_DAYS,
    }


async def org_summary(session: AsyncSession, *, today: date) -> dict[str, Any]:
    """Top-level executive rollup across the whole portfolio."""
    cards = await systems_scorecard(session, today=today)
    poams = await poam_aging(session, today=today)
    evidence = await evidence_freshness(session, today=today)

    scored = [c for c in cards if c["controls_assessed"] > 0]
    avg_sprs = round(sum(c["sprs_score"] for c in scored) / len(scored), 1) if scored else None

    risk_rows = (
        await session.execute(
            select(Risk.status, func.count()).group_by(Risk.status)
        )
    ).all()
    ato_rows = (
        await session.execute(
            select(System.ato_status, func.count()).group_by(System.ato_status)
        )
    ).all()

    return {
        "generated_for": today.isoformat(),
        "systems_total": len(cards),
        "systems_scored": len(scored),
        "avg_sprs_score": avg_sprs,
        "sprs_max": 110,
        "open_poams": poams["open_total"],
        "overdue_poams": poams["overdue"],
        "evidence": evidence,
        "poam_aging": poams,
        "risks_by_status": {status: n for status, n in risk_rows},
        "systems_by_ato": {(s or "none"): n for s, n in ato_rows},
        "systems": cards,
    }
