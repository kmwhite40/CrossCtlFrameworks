"""Posture history: daily snapshots, the trends drawn from them, and a
projection fitted to them.

Spec: docs/superpowers/specs/2026-10-20-grc-buildout-design.md, "A -- history".

Before this module Concord kept no history of SPRS, framework posture or risk
bands: they are recomputed and overwritten in place, so nothing could be drawn
over time without inventing it. :func:`capture_snapshot` copies what the
command center computes on a day into one ``PostureSnapshot`` row; every
trend and projection here reads only those rows.

Rules this module keeps:

* **One row per organization per day.** A second capture on the same day
  replaces the first (the unique constraint ``uq_posture_snapshot_day`` makes
  the upsert atomic). Nothing else edits a snapshot.
* **Every plotted value is a recorded value.** When a range holds more
  snapshots than a chart can label, :func:`thin` keeps the latest snapshot in
  each interval and labels it with its own date; it never averages or
  interpolates. Every snapshot in the range is still in the page's table.
* **Parts sum to their whole.** Each stacked series is chosen so its segments
  add up to the denominator the label names; the tests check it.
* **A ratio over nothing is ``None``** (``command_center.ratio``).
* **A projection is labelled as one**, fitted only when there are at least
  :data:`MIN_POINTS` snapshots spanning :data:`MIN_SPAN_DAYS` days, and never
  extended more than :data:`HORIZON_DAYS` days past the last recorded day.
* **Org scope is in every query**, not left to RLS.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import set_session_tenant
from ..logging import get_logger
from ..models import Organization
from ..models_program import PostureSnapshot
from .command_center import SEVERITIES, command_center, ratio
from .posture import org_summary

log = get_logger(__name__)

#: Version of the ``metrics`` layout written by :func:`build_metrics`.
METRICS_SCHEMA = 1
SNAPSHOT_SOURCES: tuple[str, ...] = ("scheduler", "manual")

#: The most columns a trend chart draws; more snapshots than this are thinned.
MAX_CHART_POINTS = 12
#: Ranges offered on /trends, in days (0 = every recorded snapshot).
RANGES: tuple[int, ...] = (30, 90, 180, 365, 0)
DEFAULT_RANGE = 90

#: Projection preconditions and bound.
MIN_POINTS = 4
MIN_SPAN_DAYS = 14
HORIZON_DAYS = 90
#: Snapshots older than this before the latest one are not fitted: a backlog's
#: pace a year ago says little about its pace now.
FIT_WINDOW_DAYS = 90

RISK_BANDS: tuple[str, ...] = ("critical", "high", "moderate", "low", "unknown")
MONITORING_STATES: tuple[str, ...] = ("healthy", "due_soon", "at_risk", "overdue")


# ── capture ──────────────────────────────────────────────────────────────────


def build_metrics(cc: dict[str, Any], sprs: dict[str, Any]) -> dict[str, Any]:
    """The JSON a snapshot stores, from ``command_center`` and ``org_summary``.

    Only counts and the SPRS figures are copied; every ratio is recomputed
    from the counts when read, so a stored percentage can never disagree with
    the counts beside it."""
    k = cc["kpis"]
    ch = k["control_health"]
    failing_all = ch["judged"] - ch["passing"] - ch["manual_review"]
    by_sev = {s: int(k["findings"]["by_severity"].get(s, 0)) for s in SEVERITIES}
    repo = k["evidence"]["repo"]
    dated = repo["total"] - repo["no_expiry"]
    mon = k["monitoring"]
    return {
        "schema": METRICS_SCHEMA,
        "systems_live": int(cc["systems_live"]),
        "controls": {
            "passing": int(ch["passing"]),
            "failing_open": int(ch["failing"]),
            "failing_accepted": int(failing_all - ch["failing"]),
            "manual_review": int(ch["manual_review"]),
            "judged": int(ch["judged"]),
            "not_in_scope": int(ch["not_in_scope"]),
        },
        "findings": {
            "open": int(k["findings"]["open"]),
            "by_severity": by_sev,
            "other": int(k["findings"]["open"] - sum(by_sev.values())),
        },
        "risks": {
            "open": int(k["risks"]["open"]),
            "by_band": {b: int(k["risks"]["by_band"].get(b, 0)) for b in RISK_BANDS},
        },
        "remediation": {
            "resolved": int(k["remediation"]["resolved"]),
            "remediable": int(k["remediation"]["remediable"]),
            "risk_accepted": int(k["remediation"]["accepted"]),
        },
        "overdue": {
            "poams": int(k["overdue"]["poams"]),
            "tasks": int(k["overdue"]["tasks"]),
            "total": int(k["overdue"]["total"]),
        },
        "frameworks": [
            {
                "label": f["label"],
                "addressed": int(f["passing"] + f["documented"]),
                "failing": int(f["failing"]),
                "total": int(f["total"]),
                "unit": f["unit"],
                "systems": int(f["systems"]),
            }
            for f in cc["frameworks"]
            if f.get("state") == "measured"
        ],
        "sprs": {
            "average": sprs.get("avg_sprs_score"),
            "minimum": sprs.get("min_sprs_score"),
            "systems_scored": int(sprs.get("systems_scored") or 0),
        },
        "evidence": {
            "current": int(dated - repo["expired"]),
            "expired": int(repo["expired"]),
            "dated": int(dated),
            "undated": int(repo["no_expiry"]),
            "total": int(repo["total"]),
        },
        "monitoring": {
            **{s: int(mon["by_status"].get(s, 0)) for s in MONITORING_STATES},
            "total": int(mon["total"]),
        },
    }


async def capture_snapshot(
    session: AsyncSession, org_id: int, *, today: date, source: str
) -> dict[str, Any]:
    """Record ``org_id``'s posture for ``today``, replacing any row for that day.

    Returns ``{"id", "taken_on", "replaced"}``. The caller commits."""
    if source not in SNAPSHOT_SOURCES:
        raise ValueError(f"source must be one of {', '.join(SNAPSHOT_SOURCES)}")
    cc = await command_center(session, org_id, today=today)
    sprs = await org_summary(session, today=today, org_id=org_id)
    metrics = build_metrics(cc, sprs)
    existing = (
        await session.execute(
            select(PostureSnapshot.id).where(
                PostureSnapshot.organization_id == org_id, PostureSnapshot.taken_on == today
            )
        )
    ).scalar_one_or_none()
    stmt = pg_insert(PostureSnapshot).values(
        organization_id=org_id, taken_on=today, source=source, metrics=metrics
    )
    stmt = stmt.on_conflict_do_update(
        constraint="uq_posture_snapshot_day",
        set_={
            "source": stmt.excluded.source,
            "metrics": stmt.excluded.metrics,
            "taken_at": func.now(),
        },
    ).returning(PostureSnapshot.id)
    snap_id = (await session.execute(stmt)).scalar_one()
    return {"id": int(snap_id), "taken_on": today, "replaced": existing is not None}


async def capture_all(
    session: AsyncSession, today: date, *, source: str = "scheduler"
) -> dict[str, Any]:
    """Capture every live organization's snapshot for ``today``.

    For the scheduler's global phase: each organization runs clamped to its
    own RLS tenant and inside its own savepoint, so one failure neither
    aborts the transaction nor stops the others. The session is left unscoped
    (bypass), as the global phase expects. The caller commits."""
    org_ids = sorted(
        (await session.execute(select(Organization.id).where(Organization.deleted_at.is_(None))))
        .scalars()
        .all()
    )
    captured: list[dict[str, Any]] = []
    failed: list[int] = []
    try:
        for org_id in org_ids:
            await set_session_tenant(session, org_id)
            try:
                async with session.begin_nested():
                    out = await capture_snapshot(session, org_id, today=today, source=source)
                captured.append({"organization_id": org_id, **out})
            except Exception as e:
                log.warning("posture_history.capture_failed", org_id=org_id, error=str(e)[:200])
                failed.append(org_id)
    finally:
        await set_session_tenant(session, None)
    return {"captured": captured, "failed": failed}


# ── reading ──────────────────────────────────────────────────────────────────


async def load_snapshots(
    session: AsyncSession, org_id: int, *, since: date | None = None
) -> list[PostureSnapshot]:
    """The organization's snapshots, oldest first, optionally from ``since``."""
    stmt = select(PostureSnapshot).where(PostureSnapshot.organization_id == org_id)
    if since is not None:
        stmt = stmt.where(PostureSnapshot.taken_on >= since)
    return list((await session.execute(stmt.order_by(PostureSnapshot.taken_on))).scalars().all())


def thin(snaps: Sequence[Any], max_points: int = MAX_CHART_POINTS) -> list[Any]:
    """At most ``max_points`` of ``snaps`` (oldest first): the latest snapshot
    in each equal interval of the range, so every point is a recorded value on
    its own date. The newest snapshot is always kept."""
    if len(snaps) <= max_points:
        return list(snaps)
    first = snaps[0].taken_on
    span = (snaps[-1].taken_on - first).days + 1
    step = max(1, math.ceil(span / max_points))
    latest: dict[int, Any] = {}
    for s in snaps:
        latest[(s.taken_on - first).days // step] = s
    return [latest[k] for k in sorted(latest)]


def _label(d: date) -> str:
    return d.strftime("%b %-d")


@dataclass(frozen=True)
class _Part:
    name: str
    tone: str
    #: ``None`` is the remainder: the chart's whole less its other parts.
    path: tuple[str, ...] | None


def _get(metrics: dict[str, Any], path: Sequence[str]) -> Any:
    cur: Any = metrics
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


#: Each stacked chart: its parts, and the whole they must add up to.
CHARTS: tuple[dict[str, Any], ...] = (
    {
        "key": "controls",
        "title": "Controls by latest test result",
        "whole": ("controls", "judged"),
        "unit": "controls with a result",
        "basis": "Controls on live systems whose latest automated test produced a result: "
        "passed, failed (open or under an accepted risk), or needs a human. Not-applicable "
        "and not-yet-run tests are outside it. Not a framework score.",
        "parts": (
            _Part("Passing", "--success", ("controls", "passing")),
            _Part("Failing", "--danger", ("controls", "failing_open")),
            _Part("Failing, risk accepted", "--warning", ("controls", "failing_accepted")),
            _Part("Needs a human", "--info", ("controls", "manual_review")),
        ),
    },
    {
        "key": "findings",
        "title": "Open POA&Ms by severity",
        "whole": ("findings", "open"),
        "unit": "open",
        "basis": "Open and in-progress POA&Ms on live systems. Risk-accepted POA&Ms are not open.",
        "parts": (
            _Part("Critical", "--sev-critical", ("findings", "by_severity", "critical")),
            _Part("High", "--sev-high", ("findings", "by_severity", "high")),
            _Part("Moderate", "--sev-moderate", ("findings", "by_severity", "moderate")),
            _Part("Low", "--sev-low", ("findings", "by_severity", "low")),
            _Part("Other severity", "--sev-none", ("findings", "other")),
        ),
    },
    {
        "key": "risks",
        "title": "Active risks by residual band",
        "whole": ("risks", "open"),
        "unit": "active",
        "basis": "Open and mitigated risks on live systems, by residual band.",
        "parts": (
            _Part("Critical", "--sev-critical", ("risks", "by_band", "critical")),
            _Part("High", "--sev-high", ("risks", "by_band", "high")),
            _Part("Moderate", "--sev-moderate", ("risks", "by_band", "moderate")),
            _Part("Low", "--sev-low", ("risks", "by_band", "low")),
            _Part("Unscored", "--sev-none", ("risks", "by_band", "unknown")),
        ),
    },
    {
        "key": "remediation",
        "title": "Remediation: resolved and still open",
        "whole": ("remediation", "remediable"),
        "unit": "needing or needed remediation",
        "basis": "POA&Ms that need or needed remediation: completed or closed, and still open. "
        "Risk-accepted POA&Ms are in neither.",
        "parts": (
            _Part("Resolved", "--success", ("remediation", "resolved")),
            _Part("Still open", "--series-1", None),  # remediable - resolved
        ),
    },
    {
        "key": "overdue",
        "title": "Overdue items",
        "whole": ("overdue", "total"),
        "unit": "overdue",
        "basis": "Open POA&Ms past their due date and open tasks past their due date.",
        "parts": (
            _Part("POA&Ms", "--danger", ("overdue", "poams")),
            _Part("Tasks", "--warning", ("overdue", "tasks")),
        ),
    },
    {
        "key": "evidence",
        "title": "Repository evidence with an expiry date",
        "whole": ("evidence", "dated"),
        "unit": "with an expiry date",
        "basis": "Evidence objects in the repository that carry an expiry date: current and "
        "expired. Evidence without an expiry date is counted in the table, not here.",
        "parts": (
            _Part("Current", "--success", ("evidence", "current")),
            _Part("Expired", "--danger", ("evidence", "expired")),
        ),
    },
    {
        "key": "monitoring",
        "title": "Continuous monitoring",
        "whole": ("monitoring", "total"),
        "unit": "implementations",
        "basis": "Control implementations on live systems by their continuous-monitoring state.",
        "parts": (
            _Part("Healthy", "--success", ("monitoring", "healthy")),
            _Part("Due soon", "--info", ("monitoring", "due_soon")),
            _Part("At risk", "--warning", ("monitoring", "at_risk")),
            _Part("Overdue", "--danger", ("monitoring", "overdue")),
        ),
    },
)


def _part_value(metrics: dict[str, Any], chart: dict[str, Any], part: _Part) -> int | None:
    if part.path is None:  # the remainder of the whole
        whole = _get(metrics, chart["whole"])
        resolved = _get(metrics, ("remediation", "resolved"))
        return None if whole is None or resolved is None else int(whole) - int(resolved)
    v = _get(metrics, part.path)
    return None if v is None else int(v)


def _stacked(chart: dict[str, Any], snaps: Sequence[Any]) -> dict[str, Any]:
    """One stacked chart over the snapshots that recorded it."""
    have = [s for s in snaps if _get(s.metrics or {}, chart["whole"]) is not None]
    shown = thin(have)
    series = [
        {
            "name": p.name,
            "tone": p.tone,
            "values": [_part_value(s.metrics, chart, p) for s in shown],
        }
        for p in chart["parts"]
    ]
    return {
        "key": chart["key"],
        "title": chart["title"],
        "unit": chart["unit"],
        "basis": chart["basis"],
        "labels": [_label(s.taken_on) for s in shown],
        "series": series,
        "wholes": [int(_get(s.metrics, chart["whole"])) for s in shown],
        "shown": len(shown),
        "recorded": len(have),
        "latest": int(_get(have[-1].metrics, chart["whole"])) if have else None,
        "first": int(_get(have[0].metrics, chart["whole"])) if have else None,
        "first_label": _label(have[0].taken_on) if have else None,
    }


def _framework_charts(snaps: Sequence[Any]) -> list[dict[str, Any]]:
    """One chart per measured framework, over the days it was measured."""
    labels: list[str] = []
    for s in snaps:
        for f in (s.metrics or {}).get("frameworks") or []:
            if f["label"] not in labels:
                labels.append(f["label"])
    out = []
    for label in labels:
        rows = []
        for s in snaps:
            f = next((x for x in s.metrics.get("frameworks") or [] if x["label"] == label), None)
            if f is not None and f.get("total"):
                rows.append((s, f))
        if not rows:
            continue
        shown_snaps = thin([s for s, _ in rows])
        by_id = {id(s): f for s, f in rows}
        fs = [by_id[id(s)] for s in shown_snaps]
        last = rows[-1][1]
        out.append(
            {
                "key": "framework",
                "title": label,
                "basis": f"{last['unit'].capitalize()}s addressed (passing or documented) over "
                f"the {last['unit']}s the declared baseline requires, summed over the systems "
                "that declare it. The total can change when a system is added or removed.",
                "labels": [_label(s.taken_on) for s in shown_snaps],
                "series": [
                    {
                        "name": "Addressed",
                        "tone": "--success",
                        "values": [f["addressed"] for f in fs],
                    },
                    {
                        "name": "Not addressed",
                        "tone": "--sev-none",
                        "values": [f["total"] - f["addressed"] for f in fs],
                    },
                ],
                "wholes": [f["total"] for f in fs],
                "shown": len(shown_snaps),
                "recorded": len(rows),
                "latest_pct": ratio(last["addressed"], last["total"]),
                "unit": last["unit"],
            }
        )
    return out


def snapshot_row(s: Any) -> dict[str, Any]:
    """One line of the all-snapshots table: counts with their ratios."""
    m = s.metrics or {}
    c = m.get("controls") or {}
    r = m.get("remediation") or {}
    e = m.get("evidence") or {}
    mon = m.get("monitoring") or {}
    return {
        "taken_on": s.taken_on,
        "source": s.source,
        "controls_passing": c.get("passing"),
        "controls_judged": c.get("judged"),
        "controls_pct": ratio(c.get("passing", 0), c.get("judged", 0)),
        "poams_open": _get(m, ("findings", "open")),
        "risks_open": _get(m, ("risks", "open")),
        "resolved": r.get("resolved"),
        "remediable": r.get("remediable"),
        "remediation_pct": ratio(r.get("resolved", 0), r.get("remediable", 0)),
        "overdue": _get(m, ("overdue", "total")),
        "sprs_average": _get(m, ("sprs", "average")),
        "sprs_minimum": _get(m, ("sprs", "minimum")),
        "sprs_systems": _get(m, ("sprs", "systems_scored")),
        "evidence_current": e.get("current"),
        "evidence_dated": e.get("dated"),
        "evidence_pct": ratio(e.get("current", 0), e.get("dated", 0)),
        "monitoring_healthy": mon.get("healthy"),
        "monitoring_total": mon.get("total"),
        "monitoring_pct": ratio(mon.get("healthy", 0), mon.get("total", 0)),
    }


def trends(snaps: Sequence[Any], *, range_days: int, today: date) -> dict[str, Any]:
    """Everything ``/trends`` renders, from the snapshots in range (oldest first)."""
    return {
        "range_days": range_days,
        "count": len(snaps),
        "first_on": snaps[0].taken_on if snaps else None,
        "last_on": snaps[-1].taken_on if snaps else None,
        "enough": len(snaps) >= 2,
        "charts": [_stacked(c, snaps) for c in CHARTS],
        "frameworks": _framework_charts(snaps),
        "rows": [snapshot_row(s) for s in reversed(snaps)],
        "today": today,
    }


async def trends_for(
    session: AsyncSession, org_id: int, *, today: date, range_days: int = DEFAULT_RANGE
) -> dict[str, Any]:
    since = today - timedelta(days=range_days) if range_days else None
    snaps = await load_snapshots(session, org_id, since=since)
    out = trends(snaps, range_days=range_days, today=today)
    out["total_recorded"] = await _count(session, org_id)
    return out


async def _count(session: AsyncSession, org_id: int) -> int:
    return int(
        (
            await session.execute(
                select(func.count())
                .select_from(PostureSnapshot)
                .where(PostureSnapshot.organization_id == org_id)
            )
        ).scalar_one()
    )


async def posture_over_time(session: AsyncSession, org_id: int, *, today: date) -> dict[str, Any]:
    """The command center's "Posture over time" tab: the last 90 days of
    snapshots, controls by result and open POA&Ms."""
    snaps = await load_snapshots(session, org_id, since=today - timedelta(days=90))
    total = await _count(session, org_id)
    by_key = {c["key"]: c for c in CHARTS}
    return {
        "count": len(snaps),
        "total_recorded": total,
        "first_on": snaps[0].taken_on if snaps else None,
        "last_on": snaps[-1].taken_on if snaps else None,
        "enough": len(snaps) >= 2,
        "controls": _stacked(by_key["controls"], snaps),
        "findings": _stacked(by_key["findings"], snaps),
    }


# ── forecast ─────────────────────────────────────────────────────────────────


#: What /forecast projects: (key, label, path into metrics, basis).
FORECAST_METRICS: tuple[tuple[str, str, tuple[str, ...], str], ...] = (
    (
        "poams",
        "Open POA&Ms",
        ("findings", "open"),
        "Open and in-progress POA&Ms on live systems.",
    ),
    (
        "controls",
        "Failing controls",
        ("controls", "failing_open"),
        "Controls whose latest automated test failed and whose failure is not under an "
        "accepted risk.",
    ),
    (
        "risks",
        "Active risks",
        ("risks", "open"),
        "Open and mitigated risks on live systems.",
    ),
)


def linear_fit(points: Sequence[tuple[float, float]]) -> dict[str, float | None]:
    """Ordinary least squares ``y = slope * x + intercept`` over ``points``.

    ``r2`` is ``None`` when every ``y`` is the same: there is no variance for
    the line to explain, and calling that a perfect (1.0) or useless (0.0) fit
    would both be a claim the data does not make."""
    n = len(points)
    if n < 2:
        raise ValueError("a line needs at least two points")
    mx = sum(x for x, _ in points) / n
    my = sum(y for _, y in points) / n
    sxx = sum((x - mx) ** 2 for x, _ in points)
    if sxx == 0:
        raise ValueError("every point is on the same day")
    sxy = sum((x - mx) * (y - my) for x, y in points)
    slope = sxy / sxx
    intercept = my - slope * mx
    ss_tot = sum((y - my) ** 2 for _, y in points)
    ss_res = sum((y - (slope * x + intercept)) ** 2 for x, y in points)
    r2 = None if ss_tot == 0 else 1 - ss_res / ss_tot
    return {"slope": slope, "intercept": intercept, "r2": r2}


def project(
    observations: Sequence[tuple[date, int]],
    *,
    min_points: int = MIN_POINTS,
    min_span_days: int = MIN_SPAN_DAYS,
    horizon_days: int = HORIZON_DAYS,
) -> dict[str, Any]:
    """Fit a line to dated counts and project it at most ``horizon_days`` past
    the last observation.

    Refuses (``ok`` False with ``reason``) when there are fewer than
    ``min_points`` observations or they span fewer than ``min_span_days``.
    ``zero_on`` -- the day the fitted line reaches zero -- is given only when
    the slope is negative and that day falls inside the horizon."""
    obs = sorted(observations)
    if len(obs) < min_points:
        return {
            "ok": False,
            "points": len(obs),
            "reason": f"{len(obs)} snapshot{'s' if len(obs) != 1 else ''} recorded; "
            f"a projection needs at least {min_points}.",
        }
    first, last = obs[0][0], obs[-1][0]
    span = (last - first).days
    if span < min_span_days:
        return {
            "ok": False,
            "points": len(obs),
            "span_days": span,
            "reason": f"The snapshots span {span} day{'s' if span != 1 else ''}; "
            f"a projection needs at least {min_span_days}.",
        }
    fit = linear_fit([((d - first).days, float(v)) for d, v in obs])
    slope, intercept = float(fit["slope"]), float(fit["intercept"])
    end = last + timedelta(days=horizon_days)

    def at(d: date) -> float:
        return slope * (d - first).days + intercept

    marks = []
    for ahead in (30, 60, 90):
        if ahead > horizon_days:
            break
        d = last + timedelta(days=ahead)
        v = at(d)
        marks.append({"days": ahead, "on": d, "value": round(max(v, 0.0), 1), "floored": v < 0})
    zero_on = None
    zero_note = None
    if slope < 0:
        # Compared in days before any date is built: a slope a hair below zero
        # puts the crossing millions of years out, past ``date.max``.
        x0 = math.ceil(-intercept / slope)
        if x0 <= (last - first).days:
            zero_note = "already"
        elif x0 > (end - first).days:
            zero_note = "beyond"
        else:
            zero_on = first + timedelta(days=x0)
    return {
        "ok": True,
        "points": len(obs),
        "span_days": span,
        "first_on": first,
        "last_on": last,
        "latest": obs[-1][1],
        "fitted_latest": round(at(last), 1),
        "slope_per_day": slope,
        "slope_per_week": round(slope * 7, 2),
        "r2": None if fit["r2"] is None else round(float(fit["r2"]), 3),
        "direction": "down" if slope < 0 else ("up" if slope > 0 else "flat"),
        "marks": marks,
        "horizon_on": end,
        "zero_on": zero_on,
        "zero_note": zero_note,
    }


def forecast(snaps: Sequence[Any], *, today: date) -> dict[str, Any]:
    """Everything ``/forecast`` renders: each backlog fitted over the
    snapshots from the last :data:`FIT_WINDOW_DAYS` days before the latest."""
    window: list[Any] = []
    if snaps:
        cutoff = snaps[-1].taken_on - timedelta(days=FIT_WINDOW_DAYS)
        window = [s for s in snaps if s.taken_on >= cutoff]
    metrics = []
    for key, label, path, basis in FORECAST_METRICS:
        obs = [
            (s.taken_on, int(v)) for s in window if (v := _get(s.metrics or {}, path)) is not None
        ]
        metrics.append({"key": key, "label": label, "basis": basis, **project(obs)})
    return {
        "today": today,
        "recorded": len(snaps),
        "window": len(window),
        "first_on": window[0].taken_on if window else None,
        "last_on": window[-1].taken_on if window else None,
        "stale_days": (today - snaps[-1].taken_on).days if snaps else None,
        "metrics": metrics,
    }


async def forecast_for(session: AsyncSession, org_id: int, *, today: date) -> dict[str, Any]:
    return forecast(await load_snapshots(session, org_id), today=today)


__all__ = [
    "CHARTS",
    "FORECAST_METRICS",
    "HORIZON_DAYS",
    "MIN_POINTS",
    "MIN_SPAN_DAYS",
    "build_metrics",
    "capture_all",
    "capture_snapshot",
    "forecast",
    "forecast_for",
    "linear_fit",
    "load_snapshots",
    "posture_over_time",
    "project",
    "snapshot_row",
    "thin",
    "trends",
    "trends_for",
]
