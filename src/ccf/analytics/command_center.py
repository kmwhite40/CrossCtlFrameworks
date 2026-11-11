"""The executive command center at ``/dashboard``.

One read-only call that composes what the platform already records into the
page leadership opens first. It computes nothing new about compliance: every
figure is either an existing analytic (``compliance_gaps``,
``org_framework_posture``, ``poam_aging``, ``conmon.health_summary``,
``evidence_freshness``) or a count over dated rows. Each KPI carries ``basis``
-- the sentence a reader needs to know what the number is over -- because a
number on an executive page is read as a claim.

Rules this module keeps, each learned the hard way on other pages:

* **A ratio over nothing is ``None``.** 0% reads as a finding and 100% as an
  achievement; neither is true of an empty set. :func:`ratio` is the one place
  that decides, so the rule is testable without a database.
* **No cross-framework "compliance score".** ``org_framework_posture`` refuses
  to sum across frameworks with different denominators, and so does this page.
  The headline is the share of *assessed* controls passing, labelled as such.
* **Only dated records are trended.** SPRS, framework posture, implementation
  status and risk scores are overwritten in place, so they are never
  reconstructed. What is trended is either rebuilt from rows that carry their
  own dates (POA&M flow, control-test runs) or read from the daily posture
  snapshots (``analytics.posture_history``), which exist only from the day the
  first was recorded. ``trends["not_recorded"]`` names what is still missing.
* **Org scope is in every query**, not only in RLS, and soft-deleted systems
  are excluded throughout via ``posture.org_system_subq``.
* **Nothing here writes.** ``conmon.scan``, ``digest`` escalation and
  ``evidence.mark_expired`` all mutate rows and are deliberately not called.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..constants import POAM_ACTIVE_STATUSES
from ..governance import conmon
from ..governance.risk import SCALE, band, effective_scores, risk_in_scope
from ..models import POAM, Event, Risk, System, Task
from ..models_evidence import EvidenceObject, EvidenceVersion
from ..models_grc import AuditEngagement, AuditFinding, AuditRequest, ControlTest, ControlTestResult
from . import posture
from .framework_posture import org_framework_posture
from .gaps import compliance_gaps

#: Task statuses that still need someone (``api/routes/tasks.py``).
TASK_OPEN_STATUSES: tuple[str, ...] = ("open", "in_progress", "blocked")
#: The three likelihood/impact levels the Risk model records, low → high.
#: The three-level likelihood/impact enum. Still accepted by the heat map's
#: ``likelihood=``/``impact=`` drill-down; the grid itself is five-point.
RISK_LEVELS: tuple[str, ...] = ("low", "moderate", "high")
SEVERITIES: tuple[str, ...] = ("critical", "high", "moderate", "low")
#: The kanban's columns, in workflow order. ``completed`` is a closed status
#: that still awaits closure review, so it is shown, not hidden.
KANBAN_COLUMNS: tuple[tuple[str, str], ...] = (
    ("open", "To do"),
    ("in_progress", "In progress"),
    ("completed", "Completed — awaiting closure"),
)

#: Measured posture, one row per declared baseline. 800-53 and FedRAMP are one
#: measurement (the FedRAMP/FISMA baseline is a selection of 800-53 controls),
#: and CMMC L2 is measured on the 800-171 requirements it adopts, so each pair
#: is one row that names both -- two rows with identical numbers would read as
#: two independent results.
POSTURE_ROWS: tuple[tuple[str, str, str | None], ...] = (
    ("fedramp_high", "NIST SP 800-53 Rev. 5 · FedRAMP High", None),
    ("fedramp_moderate", "NIST SP 800-53 Rev. 5 · FedRAMP Moderate", None),
    ("fedramp_low", "NIST SP 800-53 Rev. 5 · FedRAMP Low", None),
    ("nist_800_171", "NIST SP 800-171 Rev. 2 · CMMC Level 2", "CMMC L2 adopts these requirements"),
)
#: Frameworks with a crosswalk in the catalog but no posture measurement.
MAPPING_ROWS: tuple[tuple[str, str], ...] = (
    ("NIST_CSF_2_0", "NIST CSF 2.0"),
    ("ISO_27001", "ISO/IEC 27001"),
    ("SOC2", "SOC 2"),
    ("CIS_V8", "CIS Controls v8"),
)


def ratio(part: int, whole: int) -> float | None:
    """``part / whole`` as a percentage, or ``None`` when ``whole`` is 0.

    The one decision about empty denominators on this page. Rounded to a whole
    percent: a tenth of a percent on an executive tile implies a precision the
    underlying counts rarely have."""
    if whole <= 0:
        return None
    return round(100.0 * part / whole)


def _month_keys(today: date, months: int) -> list[tuple[int, int]]:
    keys: list[tuple[int, int]] = []
    y, m = today.year, today.month
    for _ in range(months):
        keys.append((y, m))
        m -= 1
        if m == 0:
            y, m = y - 1, 12
    return list(reversed(keys))


def _week_start(d: date) -> date:
    return d - timedelta(days=d.weekday())


# ── KPI sources ──────────────────────────────────────────────────────────────


async def _poam_status_counts(session: AsyncSession, org_id: int) -> dict[str, int]:
    rows = (
        await session.execute(
            select(POAM.status, func.count())
            .where(POAM.system_id.in_(posture.org_system_subq(org_id)))
            .group_by(POAM.status)
        )
    ).all()
    return {status: int(n) for status, n in rows}


async def _overdue_tasks(session: AsyncSession, org_id: int, today: date) -> int:
    return int(
        (
            await session.execute(
                select(func.count())
                .select_from(Task)
                .where(
                    Task.organization_id == org_id,
                    Task.status.in_(TASK_OPEN_STATUSES),
                    Task.due_on.is_not(None),
                    Task.due_on < today,
                )
            )
        ).scalar_one()
    )


async def _open_audit_findings(session: AsyncSession, org_id: int) -> dict[str, int]:
    """Open findings, scoped as ``/audit/findings`` and ``/issues`` scope them:
    through the engagement (a finding raised in the UI may carry a NULL
    ``organization_id`` of its own), and never on a deleted system."""
    rows = (
        await session.execute(
            select(AuditFinding.severity, func.count())
            .join(AuditEngagement, AuditEngagement.id == AuditFinding.engagement_id)
            .where(
                AuditEngagement.organization_id == org_id,
                AuditFinding.status != "closed",
                or_(
                    AuditFinding.system_id.is_(None),
                    AuditFinding.system_id.in_(posture.org_system_subq(org_id)),
                ),
            )
            .group_by(AuditFinding.severity)
        )
    ).all()
    return {sev or "unrated": int(n) for sev, n in rows}


async def _audit_readiness(session: AsyncSession, org_id: int, today: date) -> dict[str, Any]:
    """Evidence requests (PBC) accepted by the auditor, over every request on
    an engagement that is not closed.

    Concord has no general audit-readiness model. This is the narrower,
    checkable thing it does record: whether what an auditor asked for has been
    accepted. ``accepted`` is the one status the audit workspace reads as done
    (``audit_detail.html``); every other value is outstanding."""
    rows = (
        await session.execute(
            select(AuditRequest.status, AuditRequest.due_on)
            .join(AuditEngagement, AuditEngagement.id == AuditRequest.engagement_id)
            .where(AuditEngagement.organization_id == org_id, AuditEngagement.status != "closed")
        )
    ).all()
    engagements = int(
        (
            await session.execute(
                select(func.count())
                .select_from(AuditEngagement)
                .where(
                    AuditEngagement.organization_id == org_id, AuditEngagement.status != "closed"
                )
            )
        ).scalar_one()
    )
    accepted = sum(1 for status, _ in rows if status == "accepted")
    overdue = sum(
        1 for status, due in rows if status != "accepted" and due is not None and due < today
    )
    return {
        "pct": ratio(accepted, len(rows)),
        "accepted": accepted,
        "requests": len(rows),
        "overdue": overdue,
        "engagements": engagements,
        "basis": "Auditor evidence requests accepted, over all requests on open engagements.",
    }


async def _evidence_repository(session: AsyncSession, org_id: int, today: date) -> dict[str, int]:
    """Freshness of the versioned evidence repository (``EvidenceObject``).

    ``posture.evidence_freshness`` reads only the legacy ``Evidence`` table, so
    an organization that uses the repository would read as having no evidence.
    Both are reported; neither is substituted for the other."""
    rows = (
        await session.execute(
            select(EvidenceObject.status, EvidenceObject.expires_on).where(
                EvidenceObject.organization_id == org_id
            )
        )
    ).all()
    soon = today + timedelta(days=30)
    out = {
        "total": len(rows),
        "approved": 0,
        "pending_review": 0,
        "expired": 0,
        "expiring_soon": 0,
        "no_expiry": 0,
    }
    for status, expires_on in rows:
        if status == "approved":
            out["approved"] += 1
        elif status in ("draft", "submitted"):
            out["pending_review"] += 1
        if status == "expired" or (expires_on is not None and expires_on < today):
            out["expired"] += 1
        elif expires_on is None:
            out["no_expiry"] += 1
        elif expires_on <= soon:
            out["expiring_soon"] += 1
    return out


async def risk_matrix(session: AsyncSession, org_id: int | None) -> dict[str, Any]:
    """Open and mitigated risks of the organization, by likelihood x impact, 5x5.

    Scoped by ``governance.risk.risk_in_scope``: risks on live systems and
    system-less (enterprise) risks the organization owns.

    ``cells[likelihood][impact]`` is keyed by the 1-5 scores. A risk is placed
    by its recorded score, else by its three-level enum read as 1, 3 or 5 --
    the value it has always been scored at -- so a risk that predates the
    five-point scale lands where its inherent score says. A risk with neither
    on an axis is counted in ``unplaced``, not dropped silently."""
    rows = (
        await session.execute(
            select(
                Risk.id,
                Risk.title,
                Risk.likelihood,
                Risk.impact,
                Risk.likelihood_score,
                Risk.impact_score,
                Risk.residual_score,
                Risk.inherent_score,
                Risk.status,
            ).where(
                Risk.status.in_(("open", "mitigated")),
                risk_in_scope(org_id),
            )
        )
    ).all()
    cells: dict[int, dict[int, int]] = {lk: {im: 0 for im in SCALE} for lk in SCALE}
    unplaced = 0
    bands: Counter[str] = Counter()
    for r in rows:
        lk, im = effective_scores(r.likelihood_score, r.likelihood, r.impact_score, r.impact)
        if lk is not None and im is not None:
            cells[lk][im] += 1
        else:
            unplaced += 1
        bands[band(r.residual_score)] += 1
    return {
        "total": len(rows),
        "cells": cells,
        "unplaced": unplaced,
        "by_band": {b: bands.get(b, 0) for b in ("critical", "high", "moderate", "low", "unknown")},
    }


# ── trends: dated rows only ──────────────────────────────────────────────────


async def _poam_flow(
    session: AsyncSession, org_id: int, today: date, months: int = 6
) -> dict[str, Any]:
    keys = _month_keys(today, months)
    opened: Counter[tuple[int, int]] = Counter()
    closed: Counter[tuple[int, int]] = Counter()
    rows = (
        await session.execute(
            select(POAM.identified_on, POAM.closed_on).where(
                POAM.system_id.in_(posture.org_system_subq(org_id))
            )
        )
    ).all()
    undated = 0
    for identified_on, closed_on in rows:
        if identified_on is None:
            undated += 1
        else:
            opened[(identified_on.year, identified_on.month)] += 1
        if closed_on is not None:
            closed[(closed_on.year, closed_on.month)] += 1
    return {
        "labels": [date(y, m, 1).strftime("%b") for y, m in keys],
        "opened": [opened.get(k, 0) for k in keys],
        "closed": [closed.get(k, 0) for k in keys],
        "undated": undated,
    }


async def _test_runs_by_week(
    session: AsyncSession, org_id: int, today: date, weeks: int = 12
) -> dict[str, Any]:
    """Control-test runs per week, by outcome, on live systems.

    This is run history, not posture: a test run twice in a week counts twice.
    The page says so. ``evaluated == 0`` runs (a collection that found
    nothing) are excluded, matching ``posture.latest``."""
    start = _week_start(today) - timedelta(weeks=weeks - 1)
    since = datetime.combine(start, datetime.min.time(), tzinfo=UTC)
    rows = (
        await session.execute(
            select(ControlTestResult.run_at, ControlTestResult.status)
            .join(ControlTest, ControlTest.id == ControlTestResult.control_test_id)
            .where(
                ControlTest.organization_id == org_id,
                ControlTest.system_id.in_(posture.org_system_subq(org_id)),
                ControlTestResult.run_at >= since,
                ControlTestResult.evaluated > 0,
            )
        )
    ).all()
    weeks_list = [start + timedelta(weeks=i) for i in range(weeks)]
    passed: Counter[date] = Counter()
    failed: Counter[date] = Counter()
    for run_at, status in rows:
        wk = _week_start(run_at.astimezone(UTC).date())
        if status == "pass":
            passed[wk] += 1
        elif status == "fail":
            failed[wk] += 1
    # The most recent week that had runs, named with its date and run count:
    # "latest week" alone hid both how old the week was and how small.
    latest = None
    for w in reversed(weeks_list):
        n = passed.get(w, 0) + failed.get(w, 0)
        if n:
            latest = {
                "week_of": w,
                "runs": n,
                "pct": ratio(passed.get(w, 0), n),
                "weeks_ago": (_week_start(today) - w).days // 7,
            }
            break
    return {
        "labels": [w.strftime("%b %-d") for w in weeks_list],
        "passed": [passed.get(w, 0) for w in weeks_list],
        "failed": [failed.get(w, 0) for w in weeks_list],
        "pass_rate": [
            ratio(passed.get(w, 0), passed.get(w, 0) + failed.get(w, 0)) for w in weeks_list
        ],
        # What the chart plots: pass and fail runs. Other outcomes are not drawn.
        "runs": sum(passed.values()) + sum(failed.values()),
        "latest": latest,
    }


# ── operational panels ───────────────────────────────────────────────────────


async def _kanban(session: AsyncSession, org_id: int, per_column: int = 4) -> list[dict[str, Any]]:
    sev_rank = {s: i for i, s in enumerate(SEVERITIES)}
    out = []
    for status, label in KANBAN_COLUMNS:
        rows = (
            await session.execute(
                select(
                    POAM.id,
                    POAM.title,
                    POAM.severity,
                    POAM.due_on,
                    POAM.owner_user_id,
                    POAM.point_of_contact,
                    System.id.label("system_id"),
                    System.name.label("system"),
                )
                .join(System, System.id == POAM.system_id)
                .where(POAM.status == status, POAM.system_id.in_(posture.org_system_subq(org_id)))
            )
        ).all()
        rows = sorted(rows, key=lambda r: (sev_rank.get(r.severity, 9), r.due_on or date.max, r.id))
        out.append(
            {
                "status": status,
                "label": label,
                "count": len(rows),
                "unowned": sum(
                    1 for r in rows if r.owner_user_id is None and not r.point_of_contact
                ),
                "cards": [r._asdict() for r in rows[:per_column]],
            }
        )
    return out


async def _recent_uploads(
    session: AsyncSession, org_id: int, limit: int = 5
) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(
                EvidenceVersion.filename,
                EvidenceVersion.uploaded_by,
                EvidenceVersion.created_at,
                EvidenceVersion.version,
                EvidenceObject.id.label("object_id"),
                EvidenceObject.title,
                EvidenceObject.status,
                EvidenceObject.control_id,
            )
            .join(EvidenceObject, EvidenceObject.id == EvidenceVersion.evidence_object_id)
            .where(EvidenceObject.organization_id == org_id)
            .order_by(EvidenceVersion.created_at.desc(), EvidenceVersion.id.desc())
            .limit(limit)
        )
    ).all()
    return [r._asdict() for r in rows]


async def _activity(session: AsyncSession, org_id: int, limit: int = 7) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(
                Event.actor,
                Event.verb,
                Event.entity_type,
                Event.entity_id,
                Event.summary,
                Event.created_at,
            )
            .where(Event.organization_id == org_id)
            .order_by(Event.id.desc())
            .limit(limit)
        )
    ).all()
    return [r._asdict() for r in rows]


async def _milestones(
    session: AsyncSession, org_id: int, today: date, limit: int = 6
) -> dict[str, Any]:
    """Dated commitments: audit targets, PBC due dates, ATO expiries and POA&M
    due dates within 90 days, plus anything missed in the last 30. A missed
    date matters, but without a lookback, old overdue dates filled the panel
    and no future milestone was ever shown; older misses are counted instead."""
    horizon = today + timedelta(days=90)
    lookback = today - timedelta(days=30)
    items: list[dict[str, Any]] = []
    for e in (
        await session.execute(
            select(AuditEngagement.id, AuditEngagement.name, AuditEngagement.target_on).where(
                AuditEngagement.organization_id == org_id,
                AuditEngagement.target_on.is_not(None),
                AuditEngagement.target_on >= today,
                AuditEngagement.target_on <= horizon,
                AuditEngagement.status != "closed",
            )
        )
    ).all():
        items.append(
            {
                "on": e.target_on,
                "kind": "Audit target",
                "title": e.name,
                "href": f"/audit-workspace/{e.id}",
            }
        )
    for r in (
        await session.execute(
            select(AuditRequest.title, AuditRequest.due_on, AuditEngagement.id.label("eid"))
            .join(AuditEngagement, AuditEngagement.id == AuditRequest.engagement_id)
            .where(
                AuditEngagement.organization_id == org_id,
                AuditRequest.due_on.is_not(None),
                AuditRequest.due_on <= horizon,
                AuditRequest.status != "accepted",
            )
        )
    ).all():
        items.append(
            {
                "on": r.due_on,
                "kind": "Evidence request",
                "title": r.title,
                "href": f"/audit-workspace/{r.eid}",
            }
        )
    for s in (
        await session.execute(
            select(System.id, System.name, System.ato_expires_on).where(
                System.id.in_(posture.org_system_subq(org_id)),
                System.ato_expires_on.is_not(None),
                System.ato_expires_on <= horizon,
            )
        )
    ).all():
        items.append(
            {
                "on": s.ato_expires_on,
                "kind": "ATO expires",
                "title": s.name,
                "href": f"/systems/{s.id}",
            }
        )
    # POA&M due dates are aggregated per day: a scan files many POA&Ms with
    # one due date, and listed one by one they push every other kind of
    # milestone off the panel.
    due: Counter[date] = Counter(
        d
        for d in (
            await session.execute(
                select(POAM.due_on).where(
                    POAM.system_id.in_(posture.org_system_subq(org_id)),
                    POAM.status.in_(POAM_ACTIVE_STATUSES),
                    POAM.due_on.is_not(None),
                    POAM.due_on <= horizon,
                )
            )
        )
        .scalars()
        .all()
        if d is not None
    )
    for on, n in due.items():
        items.append(
            {
                "on": on,
                "kind": "POA&M due",
                "title": f"{n} POA&M{'s' if n != 1 else ''} due",
                "href": "/poams?status=open",
            }
        )
    older = sum(1 for i in items if i["on"] < lookback)
    items = sorted((i for i in items if i["on"] >= lookback), key=lambda i: i["on"])
    for i in items:
        i["overdue"] = i["on"] < today
        i["days"] = (i["on"] - today).days
    return {"items": items[:limit], "more": max(len(items) - limit, 0), "older_overdue": older}


def _framework_coverage(fw: dict[str, Any], mapped_codes: set[str]) -> list[dict[str, Any]]:
    """Rows saying how Concord answers for each framework the brief names.

    ``measured``: posture is computed (passing + documented over the declared
    denominator), one row per baseline some system declares. ``mapped``: the
    catalog crosswalk exists but Concord does not measure posture against it --
    shown, never given a bar. ``not_configured``: no system declares it, or
    the catalog lacks it."""
    by_fw = fw.get("by_framework", {})
    rows: list[dict[str, Any]] = []
    for key, label, via in POSTURE_ROWS:
        f = by_fw.get(key)
        if not f or not f.get("total"):
            continue
        rows.append(
            {
                "label": label,
                "state": "measured",
                "pct": ratio(f["passing"] + f["documented"], f["total"]),
                "passing": f["passing"],
                "documented": f["documented"],
                "failing": f["failing"],
                "unaddressed": f["unaddressed"],
                "total": f["total"],
                "unit": f["unit"],
                "systems": f["systems"],
                "basis": f["label"],
                "via": via,
            }
        )
    if not any(
        by_fw.get(k, {}).get("total") for k in ("fedramp_high", "fedramp_moderate", "fedramp_low")
    ):
        rows.append(
            {
                "label": "NIST SP 800-53 Rev. 5 · FedRAMP",
                "state": "not_configured",
                "detail": "No system declares an 800-53 baseline.",
            }
        )
    if not by_fw.get("nist_800_171", {}).get("total"):
        rows.append(
            {
                "label": "NIST SP 800-171 Rev. 2 · CMMC Level 2",
                "state": "not_configured",
                "detail": (
                    "No system declares 800-171 or CMMC, or the requirement matrix is not loaded."
                ),
            }
        )
    for code, label in MAPPING_ROWS:
        state = "mapped" if code in mapped_codes else "not_configured"
        rows.append(
            {
                "label": label,
                "state": state,
                "detail": (
                    "Crosswalk mappings exist; Concord does not measure "
                    "posture against this framework."
                    if state == "mapped"
                    else "Not in the loaded catalog."
                ),
            }
        )
    return rows


async def _mapped_framework_codes(session: AsyncSession) -> set[str]:
    from ..models import Framework, FrameworkMapping  # noqa: PLC0415

    rows = (
        (
            await session.execute(
                select(Framework.code).where(
                    Framework.id.in_(select(FrameworkMapping.framework_id).distinct())
                )
            )
        )
        .scalars()
        .all()
    )
    return set(rows)


# ── the page ─────────────────────────────────────────────────────────────────


async def command_center(
    session: AsyncSession, org_id: int | None, *, today: date | None = None
) -> dict[str, Any]:
    """Everything ``/dashboard`` renders, for one organization.

    ``org_id`` of ``None`` (auth off, or a global principal) returns
    ``{"scoped": False}``: this is a customer-facing page, and "no
    organization" is not a licence to aggregate every tenant."""
    today = today or date.today()
    if org_id is None:
        return {"scoped": False, "today": today}

    gaps = await compliance_gaps(session, org_id, today=today)
    # failing includes failures under an approved acceptance; open excludes them.
    judged = gaps["passing"] + gaps["failing"] + gaps["manual_review"]
    fw = await org_framework_posture(session, org_id)
    aging = await posture.poam_aging(session, today=today, org_id=org_id)
    statuses = await _poam_status_counts(session, org_id)
    risks = await risk_matrix(session, org_id)
    overdue_tasks = await _overdue_tasks(session, org_id, today)
    findings = await _open_audit_findings(session, org_id)
    legacy_evidence = await posture.evidence_freshness(session, today=today, org_id=org_id)
    repo_evidence = await _evidence_repository(session, org_id, today)
    health = await conmon.health_summary(session, today=today, org_id=org_id)
    audit = await _audit_readiness(session, org_id, today)
    systems_live = int(
        (
            await session.execute(
                select(func.count()).select_from(posture.org_system_subq(org_id).subquery())
            )
        ).scalar_one()
    )

    # Remediation completion: closed or completed over every POA&M that was
    # remediated or still needs remediation. Accepted risk is neither, so it is
    # out of both numerator and denominator (and reported beside the figure).
    resolved = statuses.get("closed", 0) + statuses.get("completed", 0)
    remediable = resolved + sum(statuses.get(s, 0) for s in POAM_ACTIVE_STATUSES)

    evidence_dated = repo_evidence["total"] - repo_evidence["no_expiry"]
    evidence_current = evidence_dated - repo_evidence["expired"]

    kpis = {
        "control_health": {
            # Over controls whose latest test produced a result -- pass, fail,
            # or a human must judge -- so the three parts sum to the
            # denominator. ``assessed`` also counts not-applicable and
            # not-yet-run tests, which say nothing about the control.
            "pct": ratio(gaps["passing"], judged),
            "passing": gaps["passing"],
            "judged": judged,
            "failing": gaps["open"],
            "accepted": gaps["accepted"],
            "manual_review": gaps["manual_review"],
            "not_in_scope": gaps["not_in_scope"],
            "systems": gaps["systems_assessed"],
            "last": gaps["last_assessed"],
            "basis": "Controls whose latest automated test passed, over controls whose latest "
            "test produced a result (pass, fail, or needs a human) on live systems. "
            "Not-applicable and not-yet-run tests, and unassessed controls, are outside it. "
            "Not a framework score.",
        },
        "findings": {
            "open": aging["open_total"],
            "by_severity": {s: aging["by_severity"].get(s, 0) for s in SEVERITIES},
            "audit_findings": sum(findings.values()),
            "basis": (
                "Open and in-progress POA&Ms on live systems; accepted risk is counted separately."
            ),
        },
        "risks": {
            "open": risks["total"],
            "by_band": risks["by_band"],
            "basis": "Open and mitigated risks on live systems and enterprise risks owned by the "
            "organization, by residual band "
            "(inherent likelihood x impact, adjusted by treatment).",
        },
        "remediation": {
            "pct": ratio(resolved, remediable),
            "resolved": resolved,
            "remediable": remediable,
            "accepted": statuses.get("risk_accepted", 0),
            "basis": "Completed or closed POA&Ms over all POA&Ms that need or needed remediation. "
            "Risk-accepted items are excluded from both.",
        },
        "overdue": {
            "total": aging["overdue"] + overdue_tasks,
            "poams": aging["overdue"],
            "tasks": overdue_tasks,
            "poams_undated": aging["no_due_date"],
            "basis": "Open POA&Ms past their due date (or, where none is set, their scheduled "
            "completion or original due date), and open tasks past their due date. Items "
            "with no date at all cannot be overdue and are counted beside it.",
        },
        "audit": {**audit, "findings_open": sum(findings.values())},
        "monitoring": {
            "pct": health["health_pct"],
            "total": health["total"],
            "by_status": health["by_status"],
            "basis": "Implementations within their continuous-monitoring assessment window.",
        },
        "evidence": {
            "pct": ratio(evidence_current, evidence_dated),
            "repo": repo_evidence,
            "legacy": legacy_evidence,
            "basis": (
                "Repository evidence that is not expired, over "
                "evidence that carries an expiry date."
            ),
        },
    }

    # Imported here: posture_history captures snapshots *from* this function.
    from .posture_history import posture_over_time  # noqa: PLC0415

    posture_hist = await posture_over_time(session, org_id, today=today)

    return {
        "scoped": True,
        "today": today,
        "systems_live": systems_live,
        "kpis": kpis,
        "frameworks": _framework_coverage(fw, await _mapped_framework_codes(session)),
        "systems_without_framework": len(fw.get("systems_without_a_framework") or []),
        "risk": risks,
        "trends": {
            "poam_flow": await _poam_flow(session, org_id, today),
            "test_runs": await _test_runs_by_week(session, org_id, today),
            "posture": posture_hist,
            # Snapshots record SPRS, framework posture and risk bands from the
            # first one on; before any exists, nothing records them at all.
            "not_recorded": (
                ["individual risk scores", "implementation status"]
                if posture_hist["total_recorded"]
                else ["SPRS score", "framework posture", "risk scores", "implementation status"]
            ),
        },
        "kanban": await _kanban(session, org_id),
        "uploads": await _recent_uploads(session, org_id),
        "activity": await _activity(session, org_id),
        "milestones": await _milestones(session, org_id, today),
        "audit_findings": findings,
    }


__all__ = [
    "KANBAN_COLUMNS",
    "MAPPING_ROWS",
    "POSTURE_ROWS",
    "RISK_LEVELS",
    "TASK_OPEN_STATUSES",
    "command_center",
    "ratio",
    "risk_matrix",
]
