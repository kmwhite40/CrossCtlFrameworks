"""Key risk indicators: the registry of computed metrics, thresholds, readings.

A KRI (``models_program.KeyRiskIndicator``) is either **manual** -- readings
are entered by a person -- or **computed**, when its ``metric_key`` names an
entry in :data:`METRICS`. A computed KRI's readings come only from its metric:
a hand-entered value would stand in for the computed one, so the page refuses
it, and "compute now" refuses a manual KRI for the same reason.

Each metric is a count or ratio Concord already reports elsewhere, computed
here the same way, over the organization's live systems:

* open critical and high POA&Ms, and overdue POA&Ms (``POAM_ACTIVE_STATUSES``,
  as the dashboard counts the backlog);
* failing controls and the controls-passing ratio (``analytics.gaps``, as the
  command center's control-health tile reads it);
* expired evidence (the evidence repository, as the command center reads it);
* active risks above appetite (``governance.risk.appetite_placements``,
  scoped by ``risk_in_scope``).

A metric with nothing to compute over (a ratio with an empty denominator) has
no value. No reading is recorded for it and the reason is returned; a 0 or a
100 is never written in its place.

Status against thresholds respects ``direction``: for ``higher_is_worse`` a
value at or above the critical threshold is critical and at or above warn is
warn; for ``lower_is_worse`` the comparisons turn round. A KRI with no
thresholds has no status, only a value.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import date
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..analytics.posture import org_system_subq
from ..constants import POAM_ACTIVE_STATUSES
from ..models import POAM
from ..models_evidence import EvidenceObject
from ..models_program import KeyRiskIndicator, KriReading
from .risk import breach_count

DIRECTIONS: tuple[str, ...] = ("higher_is_worse", "lower_is_worse")
STATUSES: tuple[str, ...] = ("critical", "warn", "ok", "no_threshold", "no_reading")


@dataclass(frozen=True)
class Metric:
    key: str
    label: str
    unit: str
    #: The direction a new KRI on this metric is created with.
    direction: str
    #: What is counted, over what. Shown beside every computed value.
    basis: str
    compute: Callable[[AsyncSession, int, date], Awaitable[float | None]]


async def _poams_open_critical_high(session: AsyncSession, org_id: int, today: date) -> float:
    n = (
        await session.execute(
            select(func.count())
            .select_from(POAM)
            .where(
                POAM.system_id.in_(org_system_subq(org_id)),
                POAM.status.in_(POAM_ACTIVE_STATUSES),
                POAM.severity.in_(("critical", "high")),
            )
        )
    ).scalar_one()
    return float(n)


async def _poams_overdue(session: AsyncSession, org_id: int, today: date) -> float:
    n = (
        await session.execute(
            select(func.count())
            .select_from(POAM)
            .where(
                POAM.system_id.in_(org_system_subq(org_id)),
                POAM.status.in_(POAM_ACTIVE_STATUSES),
                POAM.due_on.is_not(None),
                POAM.due_on < today,
            )
        )
    ).scalar_one()
    return float(n)


async def _gaps(session: AsyncSession, org_id: int, today: date) -> dict[str, Any]:
    from ..analytics.gaps import compliance_gaps  # noqa: PLC0415 -- heavy; only when used

    return await compliance_gaps(session, org_id, today=today)


async def _controls_failing(session: AsyncSession, org_id: int, today: date) -> float:
    return float((await _gaps(session, org_id, today))["open"])


async def _controls_passing_pct(session: AsyncSession, org_id: int, today: date) -> float | None:
    gaps = await _gaps(session, org_id, today)
    judged = gaps["passing"] + gaps["failing"] + gaps["manual_review"]
    if judged <= 0:
        return None
    return round(100.0 * gaps["passing"] / judged, 1)


async def _evidence_expired(session: AsyncSession, org_id: int, today: date) -> float:
    n = (
        await session.execute(
            select(func.count())
            .select_from(EvidenceObject)
            .where(
                EvidenceObject.organization_id == org_id,
                or_(
                    EvidenceObject.status == "expired",
                    EvidenceObject.expires_on < today,
                ),
            )
        )
    ).scalar_one()
    return float(n)


async def _risks_above_appetite(session: AsyncSession, org_id: int, today: date) -> float:
    return float(await breach_count(session, org_id))


METRICS: dict[str, Metric] = {
    m.key: m
    for m in (
        Metric(
            "poams_open_critical_high",
            "Open critical and high POA&Ms",
            "POA&Ms",
            "higher_is_worse",
            "Open and in-progress POA&Ms of critical or high severity on live systems.",
            _poams_open_critical_high,
        ),
        Metric(
            "poams_overdue",
            "Overdue POA&Ms",
            "POA&Ms",
            "higher_is_worse",
            "Open and in-progress POA&Ms on live systems whose due date has passed.",
            _poams_overdue,
        ),
        Metric(
            "controls_failing",
            "Failing controls",
            "controls",
            "higher_is_worse",
            "Controls whose latest automated test failed on a live system, excluding failures "
            "under an approved acceptance (the command center's failing count).",
            _controls_failing,
        ),
        Metric(
            "controls_passing_pct",
            "Controls passing",
            "%",
            "lower_is_worse",
            "Controls whose latest test passed, over controls whose latest test produced a "
            "result (pass, fail, or needs a human) on live systems. No value when no control "
            "has a result.",
            _controls_passing_pct,
        ),
        Metric(
            "evidence_expired",
            "Expired evidence",
            "evidence items",
            "higher_is_worse",
            "Evidence repository items marked expired or past their expiry date.",
            _evidence_expired,
        ),
        Metric(
            "risks_above_appetite",
            "Risks above appetite",
            "risks",
            "higher_is_worse",
            "Open and mitigated risks of the organization (on its live systems, or owned "
            "directly with no system) whose residual score is above the appetite for their "
            "category, or the default appetite.",
            _risks_above_appetite,
        ),
    )
}


def status(  # noqa: PLR0911 -- one return per outcome, each named
    value: float | None, direction: str, warn: float | None, critical: float | None
) -> str:
    """``critical`` / ``warn`` / ``ok`` against the thresholds, read the right way round.

    ``no_reading`` without a value; ``no_threshold`` when neither threshold is
    set (a value alone is not a judgement)."""
    if value is None:
        return "no_reading"
    if warn is None and critical is None:
        return "no_threshold"
    if direction == "lower_is_worse":
        if critical is not None and value <= critical:
            return "critical"
        if warn is not None and value <= warn:
            return "warn"
        return "ok"
    if critical is not None and value >= critical:
        return "critical"
    if warn is not None and value >= warn:
        return "warn"
    return "ok"


def threshold_problem(direction: str, warn: float | None, critical: float | None) -> str | None:
    """Why a pair of thresholds cannot be read, or ``None`` if it can.

    Warn must be reached before critical: for ``higher_is_worse`` warn is the
    lower number, for ``lower_is_worse`` the higher one."""
    if direction not in DIRECTIONS:
        return f"direction must be one of {', '.join(DIRECTIONS)}"
    if warn is None or critical is None:
        return None
    if direction == "higher_is_worse" and warn > critical:
        return (
            f"when higher is worse the warning threshold ({warn:g}) must not be above the "
            f"critical one ({critical:g})"
        )
    if direction == "lower_is_worse" and warn < critical:
        return (
            f"when lower is worse the warning threshold ({warn:g}) must not be below the "
            f"critical one ({critical:g})"
        )
    return None


async def compute(session: AsyncSession, org_id: int, metric_key: str, today: date) -> float | None:
    metric = METRICS.get(metric_key)
    if metric is None:
        raise KeyError(metric_key)
    return await metric.compute(session, org_id, today)


async def record_computed_readings(
    session: AsyncSession,
    org_id: int,
    today: date | None = None,
    *,
    kri_ids: list[int] | None = None,
    actor: str = "scheduler",
) -> dict[str, Any]:
    """Record one computed reading for each active computed KRI of ``org_id``.

    For the scheduler (``kri_ids`` None: every active computed KRI) and for a
    page's "compute now" (``kri_ids`` narrows it). Flushes; the caller owns the
    commit. A metric is computed once per call however many KRIs share it.
    Returns ``{"recorded": [...], "skipped": [...]}`` with a reason for each
    KRI that got no reading."""
    today = today or date.today()
    stmt = select(KeyRiskIndicator).where(
        KeyRiskIndicator.organization_id == org_id,
        KeyRiskIndicator.active.is_(True),
        KeyRiskIndicator.metric_key.is_not(None),
    )
    if kri_ids is not None:
        stmt = stmt.where(KeyRiskIndicator.id.in_(kri_ids))
    kris = (await session.execute(stmt.order_by(KeyRiskIndicator.id))).scalars().all()
    values: dict[str, float | None] = {}
    recorded: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for kri in kris:
        key = kri.metric_key or ""
        metric = METRICS.get(key)
        if metric is None:
            skipped.append({"kri_id": kri.id, "reason": f"unknown metric {key!r}"})
            continue
        if key not in values:
            values[key] = await metric.compute(session, org_id, today)
        value = values[key]
        if value is None:
            skipped.append(
                {"kri_id": kri.id, "reason": f"{metric.label} has nothing to compute over"}
            )
            continue
        session.add(
            KriReading(
                organization_id=org_id,
                kri_id=kri.id,
                value=value,
                source="computed",
                recorded_by=actor,
                note=metric.basis,
            )
        )
        recorded.append({"kri_id": kri.id, "metric": key, "value": value})
    await session.flush()
    return {"recorded": recorded, "skipped": skipped}


async def readings_by_kri(
    session: AsyncSession, org_id: int, kri_ids: list[int], *, per_kri: int = 30
) -> dict[int, list[KriReading]]:
    """The latest ``per_kri`` readings of each KRI, newest first."""
    if not kri_ids:
        return {}
    ranked = (
        select(
            KriReading.id,
            func.row_number()
            .over(
                partition_by=KriReading.kri_id,
                order_by=(KriReading.recorded_at.desc(), KriReading.id.desc()),
            )
            .label("rn"),
        )
        .where(KriReading.organization_id == org_id, KriReading.kri_id.in_(kri_ids))
        .subquery()
    )
    rows = (
        (
            await session.execute(
                select(KriReading)
                .join(ranked, ranked.c.id == KriReading.id)
                .where(ranked.c.rn <= per_kri)
                .order_by(KriReading.kri_id, KriReading.recorded_at.desc(), KriReading.id.desc())
            )
        )
        .scalars()
        .all()
    )
    out: dict[int, list[KriReading]] = {k: [] for k in kri_ids}
    for r in rows:
        out.setdefault(r.kri_id, []).append(r)
    return out


def sparkline_points(values: list[float], *, width: int = 120, height: int = 28) -> str | None:
    """SVG polyline points for ``values`` (oldest first); ``None`` under two values.

    A flat series is drawn mid-height: one point is not a line, and a scale
    with no range would divide by zero."""
    if len(values) < 2:
        return None
    lo, hi = min(values), max(values)
    span = hi - lo
    step = width / (len(values) - 1)
    pts = []
    for n, v in enumerate(values):
        y = height / 2 if span == 0 else height - 2 - (v - lo) / span * (height - 4)
        pts.append(f"{n * step:.1f},{y:.1f}")
    return " ".join(pts)
