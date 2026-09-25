"""Org-wide compliance posture computations (async DB → plain dicts)."""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..constants import POAM_ACTIVE_STATUSES
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


def org_system_subq(org_id: int | None) -> Any:
    """Subquery of **live** System ids in an org (or all orgs when org_id is None).

    Public (not module-private) because ``ccf.analytics.overview`` reuses it to
    scope its own ``_block`` functions to the same org — a scoped dashboard must
    be provably org-filtered in the query itself, not only via RLS.

    Soft-deleted systems are excluded, which they were not. A deleted system
    kept contributing to every executive number: an organization with one live
    system reported three, and the headline "worst system" was a system that had
    been deleted, carrying an SPRS of -203 that set the organization's average.
    Leadership would have directed remediation at a system that no longer
    exists while the live one went unmentioned -- and SPRS scores are reported
    to DoD.

    ``api.auth_deps.org_systems_subq`` already excluded them. Two helpers with
    the same job and different answers is how this survived: the API surface was
    right and the analytics surface was not.
    """
    stmt = select(System.id).where(System.deleted_at.is_(None))
    if org_id is not None:
        stmt = stmt.where(System.organization_id == org_id)
    return stmt


async def systems_scorecard(
    session: AsyncSession, *, today: date, org_id: int | None = None
) -> list[dict[str, Any]]:
    """Per-system scorecard: SPRS, implementation coverage, POA&M and evidence health."""
    sys_stmt = select(System).where(System.deleted_at.is_(None)).order_by(System.name)
    if org_id is not None:
        sys_stmt = sys_stmt.where(System.organization_id == org_id)
    systems = (await session.execute(sys_stmt)).scalars().all()
    scorecards: list[dict[str, Any]] = []
    for sys in systems:
        sprs = await sprs_for_system(session, sys.id)
        coverage = await _impl_coverage(session, sys.id)
        open_poams = (
            await session.execute(
                select(func.count(POAM.id))
                .where(POAM.system_id == sys.id)
                .where(POAM.status.in_(POAM_ACTIVE_STATUSES))
            )
        ).scalar_one()
        # Overdue falls back to scheduled_completion / original_due_on when due_on
        # is null, so a POA&M tracked only via those fields isn't silently excluded.
        effective_due = func.coalesce(POAM.due_on, POAM.scheduled_completion, POAM.original_due_on)
        overdue_poams = (
            await session.execute(
                select(func.count(POAM.id))
                .where(POAM.system_id == sys.id)
                .where(POAM.status.in_(POAM_ACTIVE_STATUSES))
                .where(effective_due.is_not(None))
                .where(effective_due < today)
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
        controls_assessed = sprs["total_controls"] - sprs["state_counts"].get(
            "not_assessed", 0
        )
        # A system nobody has assessed has no score, and must not render one.
        #
        # SPRS starts at the baseline and subtracts for unmet controls, so an
        # unassessed system lands at the floor -- -203 for 800-171. That is the
        # worst value the scale produces, and it was appearing on the scorecard
        # as though someone had measured it. The executive summary meanwhile
        # excluded such a system from `worst_system` (correctly), so the two
        # views sat on the same page disagreeing: the scorecard showed -203 as
        # the worst number present while the headline named a different system
        # at -163.
        #
        # The exclusion was right and the rendering was wrong: -203 here is a
        # claim about posture that no assessment supports. `assessed` carries
        # the distinction so a view can say "not assessed" instead of guessing.
        assessed = controls_assessed > 0
        scorecards.append(
            {
                "system_id": sys.id,
                "name": sys.name,
                "baseline": sys.baseline,
                "ato_status": sys.ato_status,
                "assessed": assessed,
                "sprs_score": sprs["score"] if assessed else None,
                "sprs_percentage": sprs["percentage"] if assessed else None,
                "ssp_present": sprs["ssp_present"],
                "controls_assessed": controls_assessed,
                "impl_total": coverage["total"],
                "impl_met": coverage["met"],
                "open_poams": open_poams,
                "overdue_poams": overdue_poams,
                "evidence_total": evidence_total,
                "expired_evidence": expired_evidence,
            }
        )
    return scorecards


async def poam_aging(
    session: AsyncSession, *, today: date, org_id: int | None = None
) -> dict[str, Any]:
    """Aging buckets for open POA&Ms by days since identification.

    Also surfaces two honesty signals that don't fit the open/overdue split:

    - ``accepted``: POA&Ms with status ``risk_accepted`` — residual risk leadership
      has formally accepted rather than remediated. These are excluded from
      ``open_total`` (they aren't "open" work) but must not be invisible, so they
      get their own bucket.
    - ``data_quality.completed_missing_closure``: POA&Ms marked ``completed`` with
      no ``closed_on`` date — a record that claims to be done but can't prove when,
      which is a data-quality problem, not a clean close.

    Overdue falls back to ``scheduled_completion`` then ``original_due_on`` when
    ``due_on`` is null, and any open POA&M with none of the three lands in
    ``no_due_date`` rather than defaulting to on-track. Invariant:
    ``on_track + overdue + no_due_date == open_total``.
    """
    stmt = select(POAM).where(POAM.status.in_(POAM_ACTIVE_STATUSES))
    if org_id is not None:
        stmt = stmt.where(POAM.system_id.in_(org_system_subq(org_id)))
    rows = (await session.execute(stmt)).scalars().all()
    buckets = {"0-30": 0, "31-60": 0, "61-90": 0, "90+": 0, "unknown": 0}
    overdue = 0
    no_due_date = 0
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
        effective_due = p.due_on or p.scheduled_completion or p.original_due_on
        if effective_due is None:
            no_due_date += 1
        elif effective_due < today:
            overdue += 1
        by_severity[p.severity] = by_severity.get(p.severity, 0) + 1

    open_total = len(rows)
    on_track = open_total - overdue - no_due_date

    accepted_stmt = select(func.count(POAM.id)).where(POAM.status == "risk_accepted")
    dq_stmt = select(func.count(POAM.id)).where(
        POAM.status == "completed", POAM.closed_on.is_(None)
    )
    if org_id is not None:
        accepted_stmt = accepted_stmt.where(POAM.system_id.in_(org_system_subq(org_id)))
        dq_stmt = dq_stmt.where(POAM.system_id.in_(org_system_subq(org_id)))
    accepted = (await session.execute(accepted_stmt)).scalar_one()
    completed_missing_closure = (await session.execute(dq_stmt)).scalar_one()

    return {
        "open_total": open_total,
        "overdue": overdue,
        "no_due_date": no_due_date,
        "on_track": on_track,
        "buckets": buckets,
        "by_severity": by_severity,
        # Residual risk: formally accepted, not remediated — visible, not silently
        # dropped from every metric.
        "accepted": accepted,
        "data_quality": {"completed_missing_closure": completed_missing_closure},
    }


async def evidence_freshness(
    session: AsyncSession, *, today: date, org_id: int | None = None
) -> dict[str, Any]:
    """Classify evidence as fresh / expiring-soon / expired by expiry date."""
    stmt = select(Evidence.expires_on)
    if org_id is not None:
        stmt = (
            stmt.join(
                ControlImplementation, ControlImplementation.id == Evidence.implementation_id
            ).where(ControlImplementation.system_id.in_(org_system_subq(org_id)))
        )
    rows = (await session.execute(stmt)).all()
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


async def org_summary(
    session: AsyncSession, *, today: date, org_id: int | None = None
) -> dict[str, Any]:
    """Top-level executive rollup across the portfolio (optionally one org)."""
    cards = await systems_scorecard(session, today=today, org_id=org_id)
    poams = await poam_aging(session, today=today, org_id=org_id)
    evidence = await evidence_freshness(session, today=today, org_id=org_id)

    # Same predicate as the `assessed` flag on each card, so a system can
    # never be scored here while rendering "not assessed" there.
    scored = [c for c in cards if c["assessed"]]
    avg_sprs = round(sum(c["sprs_score"] for c in scored) / len(scored), 1) if scored else None

    # CISO-09: the average masks a failing system — surface the weakest
    # assessed system explicitly rather than making leadership infer it from
    # the mean. ``min()`` over ``scored`` (not ``cards``) so an unassessed
    # system (no controls scored yet) can't falsely look like the worst
    # performer at score 0.
    worst = min(scored, key=lambda c: c["sprs_score"]) if scored else None
    min_sprs = worst["sprs_score"] if worst else None
    worst_system = (
        {
            "system_id": worst["system_id"],
            "name": worst["name"],
            "sprs_score": worst["sprs_score"],
            "sprs_percentage": worst["sprs_percentage"],
        }
        if worst
        else None
    )

    risk_stmt = select(Risk.status, func.count()).group_by(Risk.status)
    ato_stmt = (
        select(System.ato_status, func.count())
        .where(System.deleted_at.is_(None))
        .group_by(System.ato_status)
    )
    if org_id is not None:
        risk_stmt = risk_stmt.where(Risk.system_id.in_(org_system_subq(org_id)))
        ato_stmt = ato_stmt.where(System.organization_id == org_id)
    risk_rows = (await session.execute(risk_stmt)).all()
    ato_rows = (await session.execute(ato_stmt)).all()

    return {
        "generated_for": today.isoformat(),
        "systems_total": len(cards),
        "systems_scored": len(scored),
        "avg_sprs_score": avg_sprs,
        "min_sprs_score": min_sprs,
        "worst_system": worst_system,
        "sprs_max": 110,
        "open_poams": poams["open_total"],
        "overdue_poams": poams["overdue"],
        # Residual risk (risk_accepted) and the "completed but no closed_on" data-quality
        # signal, surfaced at the top level so consumers don't have to reach into
        # poam_aging to see them. Additive — existing keys above are unchanged.
        "accepted_poams": poams["accepted"],
        "poam_data_quality": poams["data_quality"],
        "evidence": evidence,
        "poam_aging": poams,
        "risks_by_status": {status: n for status, n in risk_rows},
        "systems_by_ato": {(s or "none"): n for s, n in ato_rows},
        "systems": cards,
    }
