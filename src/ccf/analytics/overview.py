"""Dashboard overview aggregation.

One async call that assembles the operational-overview metrics the ``/dashboard``
page renders — catalog coverage, per-system readiness, POA&M/finding posture, risk
bands, and continuous-monitoring health. Every section is guarded so the dashboard
degrades gracefully on an empty/partly-seeded database (each block returns zeros
rather than raising). Tenant isolation is handled by the request session's RLS
context, so callers pass ``org_id`` only when they also want the explicit scoping
that :mod:`ccf.analytics.posture` applies.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..governance.risk import band
from ..models import (
    Control,
    Framework,
    FrameworkMapping,
    IngestionRun,
    KSIState,
    Risk,
    Task,
    Worksheet,
)
from ..models_grc import ControlTest
from . import posture

_SEV_ORDER = ("critical", "high", "moderate", "low")
_BAND_ORDER = ("critical", "high", "moderate", "low", "unknown")


async def _catalog(session: AsyncSession) -> dict[str, Any]:
    controls = (await session.execute(select(func.count(Control.id)))).scalar_one()
    return {
        "controls": controls,
        "mappings": (await session.execute(select(func.count(FrameworkMapping.id)))).scalar_one(),
        "frameworks": (await session.execute(select(func.count(Framework.id)))).scalar_one(),
        "worksheets": (await session.execute(select(func.count(Worksheet.id)))).scalar_one(),
        "baseline": {
            "low": (
                await session.execute(
                    select(func.count()).select_from(Control).where(Control.fisma_low.is_(True))
                )
            ).scalar_one(),
            "mod": (
                await session.execute(
                    select(func.count()).select_from(Control).where(Control.fisma_mod.is_(True))
                )
            ).scalar_one(),
            "high": (
                await session.execute(
                    select(func.count()).select_from(Control).where(Control.fisma_high.is_(True))
                )
            ).scalar_one(),
        },
    }


async def _framework_tiles(session: AsyncSession, limit: int = 6) -> list[dict[str, Any]]:
    """Top frameworks by mapping volume, with a coverage ratio for a gauge."""
    total_controls = (await session.execute(select(func.count(Control.id)))).scalar_one() or 0
    rows = (
        await session.execute(
            select(
                Framework.code,
                Framework.name,
                func.count(func.distinct(FrameworkMapping.control_id)),
                func.count(FrameworkMapping.id),
            )
            .join(FrameworkMapping, FrameworkMapping.framework_id == Framework.id, isouter=True)
            .group_by(Framework.id)
            .order_by(func.count(FrameworkMapping.id).desc())
            .limit(limit)
        )
    ).all()
    tiles: list[dict[str, Any]] = []
    for code, name, mapped_controls, mappings in rows:
        pct = round(100 * (mapped_controls or 0) / total_controls, 1) if total_controls else 0.0
        tiles.append(
            {
                "code": code,
                "name": name,
                "mapped_controls": mapped_controls or 0,
                "mappings": mappings or 0,
                "coverage_pct": pct,
            }
        )
    return tiles


async def _risk_by_band(session: AsyncSession) -> dict[str, int]:
    out = dict.fromkeys(_BAND_ORDER, 0)
    for score, status in (
        await session.execute(select(Risk.residual_score, Risk.status))
    ).all():
        if status == "closed":
            continue
        out[band(score)] += 1
    return out


async def _mttr_trend(session: AsyncSession, months: int = 12) -> dict[str, Any]:
    """Mean days-to-close for POA&Ms, bucketed by close month over the past year."""
    from ..models import POAM  # noqa: PLC0415 - local to keep the import surface small

    rows = (
        await session.execute(
            select(POAM.identified_on, POAM.closed_on).where(POAM.closed_on.is_not(None))
        )
    ).all()
    now = datetime.now(UTC).date()
    # Build the trailing-`months` window as (year, month) keys.
    keys: list[tuple[int, int]] = []
    y, m = now.year, now.month
    for _ in range(months):
        keys.append((y, m))
        m -= 1
        if m == 0:
            y, m = y - 1, 12
    keys.reverse()
    sums: dict[tuple[int, int], list[int]] = {k: [] for k in keys}
    for identified_on, closed_on in rows:
        if identified_on is None or closed_on is None:
            continue
        key = (closed_on.year, closed_on.month)
        if key in sums:
            sums[key].append(max((closed_on - identified_on).days, 0))
    series = [round(sum(v) / len(v), 1) if v else 0.0 for v in (sums[k] for k in keys)]
    closed_total = sum(len(sums[k]) for k in keys)
    latest = next((s for s in reversed(series) if s), 0.0)
    return {"series": series, "closed_total": closed_total, "latest": latest}


async def _control_tests(session: AsyncSession) -> dict[str, int]:
    rows = (
        await session.execute(
            select(ControlTest.last_status, func.count()).group_by(ControlTest.last_status)
        )
    ).all()
    out = {"pass": 0, "warn": 0, "fail": 0, "untested": 0, "total": 0}
    for status, n in rows:
        out["total"] += n
        out[status if status in ("pass", "warn", "fail") else "untested"] += n
    return out


async def _ksi_states(session: AsyncSession) -> dict[str, int]:
    rows = (
        await session.execute(select(KSIState.status, func.count()).group_by(KSIState.status))
    ).all()
    out = {
        "pass": 0, "warn": 0, "fail": 0, "not_tested": 0,
        "manual_review_required": 0, "total": 0,
    }
    for status, n in rows:
        out["total"] += n
        out[status] = out.get(status, 0) + n
    return out


async def _tasks_by_priority(session: AsyncSession) -> dict[str, int]:
    rows = (
        await session.execute(
            select(Task.priority, func.count())
            .where(Task.status.in_(("open", "in_progress")))
            .group_by(Task.priority)
        )
    ).all()
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for priority, n in rows:
        out[priority if priority in out else "medium"] += n
    out["total"] = sum(out.values())
    return out


async def dashboard_overview(
    session: AsyncSession, *, org_id: int | None = None
) -> dict[str, Any]:
    """Assemble every metric block the operational dashboard renders."""
    today = datetime.now(UTC).date()
    summary = await posture.org_summary(session, today=today, org_id=org_id)
    poam = summary["poam_aging"]
    by_sev = poam.get("by_severity", {})
    findings_by_severity = [
        {"key": s, "count": by_sev.get(s, 0)} for s in _SEV_ORDER if by_sev.get(s, 0)
    ] or [{"key": s, "count": by_sev.get(s, 0)} for s in _SEV_ORDER]
    open_total = poam.get("open_total", 0)
    overdue = poam.get("overdue", 0)

    # Readiness cards: assessed systems first, ranked by SPRS %.
    systems = summary.get("systems", [])
    readiness = sorted(
        systems, key=lambda c: (c["controls_assessed"] > 0, c["sprs_percentage"]), reverse=True
    )

    last_run = (
        await session.execute(select(IngestionRun).order_by(IngestionRun.id.desc()).limit(1))
    ).scalar_one_or_none()

    return {
        "generated_at": today.isoformat(),
        "catalog": await _catalog(session),
        "frameworks": await _framework_tiles(session),
        "last_run": last_run,
        # Compliance & audit readiness
        "readiness": readiness,
        "systems_total": summary["systems_total"],
        "systems_scored": summary["systems_scored"],
        "avg_sprs": summary["avg_sprs_score"],
        "sprs_max": summary["sprs_max"],
        "systems_by_ato": summary["systems_by_ato"],
        "evidence": summary["evidence"],
        # Vulnerability / POA&M response
        "findings_total": open_total,
        "findings_by_severity": findings_by_severity,
        "sla": {
            "open": open_total,
            "overdue": overdue,
            "on_track": max(open_total - overdue, 0),
            "on_track_pct": round(100 * (open_total - overdue) / open_total, 1)
            if open_total
            else 100.0,
        },
        "poam_buckets": poam.get("buckets", {}),
        "mttr": await _mttr_trend(session),
        "risk_by_band": await _risk_by_band(session),
        # Continuous-monitoring operations
        "control_tests": await _control_tests(session),
        "ksi": await _ksi_states(session),
        "tasks": await _tasks_by_priority(session),
    }
