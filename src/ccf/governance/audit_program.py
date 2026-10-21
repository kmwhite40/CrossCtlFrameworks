"""Audit and assurance program: workpapers, compensating controls, and the
cross-engagement views over what the audit workspace already records.

Spec: ``docs/superpowers/specs/2026-10-20-grc-buildout-design.md`` (D -- auditprog).

Three rules shape everything here.

* **Tenant scope is one predicate per query.** Every read takes ``org``
  (``None`` = an unscoped, global caller) and filters on it once, at the table
  that owns the tenant: the engagement for PBC requests and findings (neither
  carries a trustworthy ``organization_id`` of its own -- a finding raised
  through the UI before ISSM-04 has NULL), the record itself for workpapers,
  compensating controls and packages, and a **live** system
  (``posture.org_system_subq``) for implementations and control tests. A
  second, redundant predicate would hide the first from a mutation test.
* **Separation of duties.** A workpaper is finalised by a reviewer who did not
  prepare it; a compensating control is decided by someone who did not propose
  it. :func:`may_sign_off` is the one comparison, and it refuses when the
  signer cannot be identified -- the safe direction. Unlike
  ``waivers.can_approve`` there is no exemption for a global principal: a
  workpaper signed off by "system" is not a review.
* **A ratio over nothing is None** (``command_center.ratio``), rendered ``—``.

Nothing here decides compliance or fabricates a record. Refusals raise
:class:`RefusalError`, which the routes turn into an HTTP status with the reason.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..analytics import posture
from ..analytics.command_center import ratio
from ..catalog.canonical import canonicalize
from ..models import POAM, Control, ControlImplementation, System, User
from ..models_grc import AuditEngagement, AuditFinding, AuditRequest, ControlTest
from ..models_packages import (
    PACKAGE_KINDS,
    AuthorizationPackage,
    AuthorizationPackageArtifact,
    AuthorizationPackageDiff,
    AuthorizationPackageFact,
    AuthorizationPackageReplayRun,
)
from ..models_program import AuditWorkpaper, CompensatingControl
from ..packages import service as package_service

# The runner's own frequency table, so "due" here and "due" to the runner can
# never disagree (``control_tests._is_due`` reads the same dict).
from .control_tests import _FREQ_DAYS as TEST_FREQUENCY_DAYS

#: The vocabularies the audit workspace already uses (``command_center`` reads
#: them the same way): an engagement is open until ``closed``, a PBC request is
#: done once ``accepted``, a finding is open until ``closed``.
ENGAGEMENT_CLOSED = "closed"
REQUEST_DONE = "accepted"
FINDING_CLOSED = "closed"
SEVERITIES = ("critical", "high", "moderate", "low")

WORKPAPER_ROLES = ("admin", "assessor")
WORKPAPER_STATUSES = ("draft", "in_review", "final")
WORKPAPER_CONCLUSIONS = ("effective", "ineffective", "not_tested")

CC_PROPOSE_ROLES = ("admin", "control_owner", "assessor")
CC_DECIDE_ROLES = ("admin",)
CC_STATUSES = ("proposed", "approved", "rejected", "retired")


class RefusalError(Exception):
    """A request the program will not carry out, and why."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message


def may_sign_off(prepared_by: str | None, signer: str | None) -> bool:
    """Separation of duties: the signer is identified and is not the preparer."""
    if not signer or not signer.strip():
        return False
    return (prepared_by or "").strip().lower() != signer.strip().lower()


def _clean(raw: str | None) -> str | None:
    value = (raw or "").strip()
    return value or None


def _nonneg(raw: int | None, name: str) -> int | None:
    if raw is not None and raw < 0:
        raise RefusalError(422, f"{name} cannot be negative")
    return raw


# ── Workpapers ───────────────────────────────────────────────────────────────


def _finding_on_live_system(org: int | None) -> Any:
    """A finding with no system, or one on a live system of ``org``."""
    return or_(
        AuditFinding.system_id.is_(None),
        AuditFinding.system_id.in_(posture.org_system_subq(org)),
    )


async def engagement_in_scope(
    session: AsyncSession, eng_id: int, org: int | None
) -> AuditEngagement:
    stmt = select(AuditEngagement).where(AuditEngagement.id == eng_id)
    if org is not None:
        stmt = stmt.where(AuditEngagement.organization_id == org)
    engagement = (await session.execute(stmt)).scalar_one_or_none()
    if engagement is None:
        raise RefusalError(404, "engagement not found")
    return engagement


async def workpaper_in_scope(session: AsyncSession, wp_id: int, org: int | None) -> AuditWorkpaper:
    stmt = select(AuditWorkpaper).where(AuditWorkpaper.id == wp_id)
    if org is not None:
        stmt = stmt.where(AuditWorkpaper.organization_id == org)
    wp = (await session.execute(stmt)).scalar_one_or_none()
    if wp is None:
        raise RefusalError(404, "workpaper not found")
    return wp


def _require_status(wp: AuditWorkpaper, expected: str, doing: str) -> None:
    """One guard per transition. A final workpaper is read-only, whatever
    the transition; anything else names the status it needs."""
    if wp.status == "final":
        raise RefusalError(409, "a final workpaper is read-only")
    if wp.status != expected:
        raise RefusalError(409, f"cannot {doing} a workpaper that is {wp.status.replace('_', ' ')}")


def _workpaper_fields(
    *,
    title: str,
    control_id: str | None,
    procedure: str | None,
    sample_size: int | None,
    exceptions_found: int | None,
    conclusion: str | None,
    evidence_refs: str | None,
) -> dict[str, Any]:
    title_clean = _clean(title)
    if title_clean is None:
        raise RefusalError(422, "a workpaper needs a title")
    conclusion_clean = _clean(conclusion)
    if conclusion_clean is not None and conclusion_clean not in WORKPAPER_CONCLUSIONS:
        raise RefusalError(422, f"conclusion must be one of {', '.join(WORKPAPER_CONCLUSIONS)}")
    sample = _nonneg(sample_size, "sample size")
    found = _nonneg(exceptions_found, "exceptions found")
    if sample is not None and found is not None and found > sample:
        raise RefusalError(422, "exceptions found cannot exceed the sample size")
    control = _clean(control_id)
    if control is not None:
        canon = canonicalize(control)
        control = canon.value if canon is not None else control
    refs = [line.strip() for line in (evidence_refs or "").splitlines() if line.strip()]
    return {
        "title": title_clean,
        "control_id": control,
        "procedure": _clean(procedure),
        "sample_size": sample,
        "exceptions_found": found,
        "conclusion": conclusion_clean,
        "evidence_refs": refs,
    }


async def create_workpaper(
    session: AsyncSession, engagement: AuditEngagement, *, actor: str, **fields: Any
) -> AuditWorkpaper:
    if engagement.organization_id is None:
        raise RefusalError(409, "this engagement belongs to no organization")
    wp = AuditWorkpaper(
        organization_id=engagement.organization_id,
        engagement_id=engagement.id,
        status="draft",
        prepared_by=actor,
        **_workpaper_fields(**fields),
    )
    session.add(wp)
    await session.flush()
    return wp


def edit_workpaper(wp: AuditWorkpaper, *, actor: str, **fields: Any) -> dict[str, Any]:
    """Change a draft. Only its preparer edits it: a second hand in the
    working would be a second preparer, who could then finalise it."""
    _require_status(wp, "draft", "edit")
    if (wp.prepared_by or "").strip().lower() != actor.strip().lower():
        raise RefusalError(403, "only the workpaper's preparer may edit it")
    changes = _workpaper_fields(**fields)
    diff = {k: v for k, v in changes.items() if getattr(wp, k) != v}
    for key, value in changes.items():
        setattr(wp, key, value)
    return diff


def submit_workpaper(wp: AuditWorkpaper) -> None:
    _require_status(wp, "draft", "submit")
    wp.status = "in_review"


def return_workpaper(wp: AuditWorkpaper) -> None:
    _require_status(wp, "in_review", "return")
    wp.status = "draft"


def finalise_workpaper(wp: AuditWorkpaper, *, actor: str, now: datetime) -> None:
    _require_status(wp, "in_review", "finalise")
    if not may_sign_off(wp.prepared_by, actor):
        raise RefusalError(
            403,
            "separation of duties: the preparer of a workpaper cannot finalise it; "
            "another reviewer must",
        )
    if wp.conclusion is None:
        raise RefusalError(422, "record a conclusion before the workpaper can be finalised")
    wp.status = "final"
    wp.reviewed_by = actor
    wp.reviewed_at = now


async def list_workpapers(
    session: AsyncSession, org: int | None, *, engagement_id: int | None = None
) -> list[tuple[AuditWorkpaper, str]]:
    stmt = (
        select(AuditWorkpaper, AuditEngagement.name)
        .join(AuditEngagement, AuditEngagement.id == AuditWorkpaper.engagement_id)
        .order_by(AuditWorkpaper.id.desc())
    )
    if org is not None:
        stmt = stmt.where(AuditWorkpaper.organization_id == org)
    if engagement_id is not None:
        stmt = stmt.where(AuditWorkpaper.engagement_id == engagement_id)
    return [(wp, name) for wp, name in (await session.execute(stmt)).all()]


async def engagements(session: AsyncSession, org: int | None) -> list[AuditEngagement]:
    stmt = select(AuditEngagement).order_by(AuditEngagement.id.desc())
    if org is not None:
        stmt = stmt.where(AuditEngagement.organization_id == org)
    return list((await session.execute(stmt)).scalars().all())


# ── Findings across engagements ──────────────────────────────────────────────


async def findings(
    session: AsyncSession,
    org: int | None,
    *,
    severity: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    """Every audit finding of the caller's engagements, with the POA&M each
    was promoted to -- shown only when that POA&M is on a live system of the
    same organization, so a stale or foreign link cannot name another tenant's
    record."""
    stmt = (
        select(AuditFinding, AuditEngagement.name)
        .join(AuditEngagement, AuditEngagement.id == AuditFinding.engagement_id)
        .order_by(AuditFinding.id.desc())
    )
    if org is not None:
        stmt = stmt.where(AuditEngagement.organization_id == org)
    # A finding raised against a system that was later deleted goes with the
    # system, as POA&Ms and risks do; one raised against no system stays.
    stmt = stmt.where(_finding_on_live_system(org))
    all_rows = (await session.execute(stmt)).all()
    by_severity = Counter(f.severity for f, _ in all_rows if f.status != FINDING_CLOSED)
    statuses = Counter(f.status for f, _ in all_rows)
    rows = [
        (f, name)
        for f, name in all_rows
        if (severity is None or f.severity == severity) and (status is None or f.status == status)
    ]
    poam_ids = {f.poam_id for f, _ in rows if f.poam_id is not None}
    poams: dict[int, POAM] = {}
    if poam_ids:
        poams = {
            p.id: p
            for p in (
                await session.execute(
                    select(POAM).where(
                        POAM.id.in_(poam_ids), POAM.system_id.in_(posture.org_system_subq(org))
                    )
                )
            )
            .scalars()
            .all()
        }
    return {
        "rows": [
            {"f": f, "engagement": name, "poam": poams.get(f.poam_id) if f.poam_id else None}
            for f, name in rows
        ],
        "open_by_severity": {s: by_severity.get(s, 0) for s in SEVERITIES},
        "open_total": sum(by_severity.values()),
        "open_other": sum(n for s, n in by_severity.items() if s not in SEVERITIES),
        "statuses": sorted(statuses),
        "total": len(all_rows),
    }


# ── Evidence requests (PBC) across engagements ───────────────────────────────


async def pbc_requests(
    session: AsyncSession, org: int | None, today: date, *, status: str | None = None
) -> dict[str, Any]:
    stmt = select(AuditRequest, AuditEngagement.name).join(
        AuditEngagement, AuditEngagement.id == AuditRequest.engagement_id
    )
    if org is not None:
        stmt = stmt.where(AuditEngagement.organization_id == org)
    all_rows = (await session.execute(stmt)).all()
    owners = await user_names(session, {r.owner_user_id for r, _ in all_rows})
    items = []
    for r, name in all_rows:
        overdue = r.status != REQUEST_DONE and r.due_on is not None and r.due_on < today
        items.append(
            {
                "r": r,
                "engagement": name,
                "owner": owners.get(r.owner_user_id) if r.owner_user_id else None,
                "overdue": overdue,
            }
        )
    counts = {
        "total": len(items),
        "accepted": sum(1 for i in items if i["r"].status == REQUEST_DONE),
        "overdue": sum(1 for i in items if i["overdue"]),
    }
    counts["outstanding"] = counts["total"] - counts["accepted"]
    if status == "overdue":
        items = [i for i in items if i["overdue"]]
    elif status == "outstanding":
        items = [i for i in items if i["r"].status != REQUEST_DONE]
    elif status:
        items = [i for i in items if i["r"].status == status]
    # Overdue first (oldest due first), then by due date, undated last.
    items.sort(key=lambda i: (not i["overdue"], i["r"].due_on or date.max, -int(i["r"].id)))
    return {"items": items, "counts": counts}


async def user_names(session: AsyncSession, ids: set[int | None]) -> dict[int, str]:
    wanted = {i for i in ids if i is not None}
    if not wanted:
        return {}
    rows = (
        await session.execute(
            select(User.id, User.full_name, User.email).where(User.id.in_(wanted))
        )
    ).all()
    return {r.id: (r.full_name or r.email) for r in rows}


# ── Authorization packages ───────────────────────────────────────────────────


async def packages(session: AsyncSession, org: int | None) -> list[dict[str, Any]]:
    """The organization's persisted authorization packages, their contents
    (facts by type, rendered artifacts) and their latest replay verdict.

    A package for a soft-deleted system is left out, as every page leaves out
    a deleted system's records."""
    stmt = (
        select(AuthorizationPackage, System.name)
        .outerjoin(System, System.id == AuthorizationPackage.system_id)
        .where(System.deleted_at.is_(None))
        .order_by(AuthorizationPackage.id.desc())
    )
    if org is not None:
        stmt = stmt.where(AuthorizationPackage.organization_id == org)
    pkgs = (await session.execute(stmt)).all()
    ids = [p.id for p, _ in pkgs]
    facts: dict[int, dict[str, int]] = defaultdict(dict)
    artifacts: dict[int, list[AuthorizationPackageArtifact]] = defaultdict(list)
    replays: dict[int, AuthorizationPackageReplayRun] = {}
    if ids:
        for pid, ftype, n in (
            await session.execute(
                select(
                    AuthorizationPackageFact.package_id,
                    AuthorizationPackageFact.fact_type,
                    func.count(),
                )
                .where(AuthorizationPackageFact.package_id.in_(ids))
                .group_by(AuthorizationPackageFact.package_id, AuthorizationPackageFact.fact_type)
            )
        ).all():
            facts[pid][ftype] = int(n)
        for a in (
            await session.execute(
                select(AuthorizationPackageArtifact).where(
                    AuthorizationPackageArtifact.package_id.in_(ids)
                )
            )
        ).scalars():
            artifacts[a.package_id].append(a)
        for run in (
            await session.execute(
                select(AuthorizationPackageReplayRun)
                .where(AuthorizationPackageReplayRun.package_id.in_(ids))
                .order_by(AuthorizationPackageReplayRun.ran_at)
            )
        ).scalars():
            replays[run.package_id] = run  # ascending, so the last one wins
    return [
        {
            "p": p,
            "system": system_name,
            "facts": dict(sorted(facts[p.id].items())),
            "artifacts": artifacts[p.id],
            "replay": replays.get(p.id),
        }
        for p, system_name in pkgs
    ]


#: Who may export, replay or compare a package from the page. The JSON API
#: (``api/routes/packages.py``) takes any authenticated principal and the
#: middleware refuses a viewer's write, so its effective gate is every role but
#: viewer; the page states the same gate explicitly.
PACKAGE_ROLES = ("admin", "control_owner", "assessor")


async def package_in_scope(
    session: AsyncSession, pid: int, org: int | None
) -> AuthorizationPackage:
    """The package ``pid`` names, iff the caller's organization owns it and
    its system (if any) is live."""
    stmt = (
        select(AuthorizationPackage)
        .outerjoin(System, System.id == AuthorizationPackage.system_id)
        .where(AuthorizationPackage.id == pid, System.deleted_at.is_(None))
    )
    if org is not None:
        stmt = stmt.where(AuthorizationPackage.organization_id == org)
    pkg = (await session.execute(stmt)).scalar_one_or_none()
    if pkg is None:
        raise RefusalError(404, "authorization package not found")
    return pkg


async def export_package(
    session: AsyncSession,
    org: int | None,
    *,
    actor: str,
    system_id: int,
    kind: str,
    label: str | None,
) -> AuthorizationPackage:
    """Capture the system's facts now and persist them as a package, through
    ``packages.service.create_package`` -- the API's own operation.

    The package is filed under the **system's** organization, never the
    caller's ``org_id`` (which is None for a global principal and would file
    it under no tenant). A package is immutable once written: the service has
    no operation that adds to, edits or removes a package's facts."""
    if kind not in PACKAGE_KINDS:
        raise RefusalError(422, f"kind must be one of {', '.join(PACKAGE_KINDS)}")
    stmt = select(System).where(System.id == system_id, System.deleted_at.is_(None))
    if org is not None:
        stmt = stmt.where(System.organization_id == org)
    system = (await session.execute(stmt)).scalar_one_or_none()
    if system is None:
        raise RefusalError(404, "system not found")
    return await package_service.create_package(
        session,
        org_id=system.organization_id,
        system_id=system.id,
        kind=kind,
        label=_clean(label),
        created_by=actor,
    )


async def replay_package(
    session: AsyncSession, pkg: AuthorizationPackage
) -> AuthorizationPackageReplayRun:
    """Re-derive the package's facts from current records and record the
    drift. Adds a replay run; never touches the package or its facts."""
    return await package_service.replay_package(session, org_id=pkg.organization_id, package=pkg)


async def compare_packages(
    session: AsyncSession, a: AuthorizationPackage, b: AuthorizationPackage
) -> AuthorizationPackageDiff:
    if a.id == b.id:
        raise RefusalError(422, "choose two different packages to compare")
    return await package_service.diff_packages(
        session, org_id=a.organization_id, from_id=a.id, to_id=b.id
    )


async def recent_comparisons(
    session: AsyncSession, org: int | None, *, limit: int = 10
) -> list[AuthorizationPackageDiff]:
    stmt = select(AuthorizationPackageDiff).order_by(AuthorizationPackageDiff.id.desc())
    if org is not None:
        stmt = stmt.where(AuthorizationPackageDiff.organization_id == org)
    return list((await session.execute(stmt.limit(limit))).scalars().all())


# ── Assessment schedule ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class _Window:
    key: str
    label: str


SCHEDULE_WINDOWS = (
    _Window("overdue", "Overdue"),
    _Window("due_30", "Due within 30 days"),
    _Window("due_90", "Due in 31-90 days"),
    _Window("later", "Due after 90 days"),
    _Window("unscheduled", "No assessment date"),
)


def schedule_window(due: date | None, today: date) -> str:
    if due is None:
        return "unscheduled"
    if due < today:
        return "overdue"
    if due <= today + timedelta(days=30):
        return "due_30"
    if due <= today + timedelta(days=90):
        return "due_90"
    return "later"


def control_test_due(test: ControlTest, today: date) -> tuple[str, date | None]:
    """``(state, next_due)`` for a control test under the runner's rules:
    ``no_schedule`` (no recognised frequency), ``never_run``, ``due`` or
    ``scheduled``."""
    days = TEST_FREQUENCY_DAYS.get((test.frequency or "").lower())
    if days is None:
        return "no_schedule", None
    if test.last_tested_at is None:
        return "never_run", None
    next_due = test.last_tested_at.date() + timedelta(days=days)
    return ("due" if next_due <= today else "scheduled"), next_due


async def assessment_schedule(
    session: AsyncSession, org: int | None, today: date, *, listed_limit: int = 200
) -> dict[str, Any]:
    live = posture.org_system_subq(org)
    impl_rows = (
        await session.execute(
            select(ControlImplementation, Control.identifier, System.name)
            .join(Control, Control.id == ControlImplementation.control_id)
            .join(System, System.id == ControlImplementation.system_id)
            .where(ControlImplementation.system_id.in_(live))
            .order_by(ControlImplementation.next_assessment_due.nulls_last(), Control.identifier)
        )
    ).all()
    counts = dict.fromkeys((w.key for w in SCHEDULE_WINDOWS), 0)
    listed = []
    for impl, identifier, system_name in impl_rows:
        window = schedule_window(impl.next_assessment_due, today)
        counts[window] += 1
        if window in ("overdue", "due_30", "due_90"):
            listed.append(
                {
                    "impl": impl,
                    "control": identifier,
                    "system": system_name,
                    "window": window,
                }
            )
    tests = (
        await session.execute(
            select(ControlTest, System.name)
            .join(System, System.id == ControlTest.system_id)
            .where(ControlTest.system_id.in_(live), ControlTest.active.is_(True))
            .order_by(ControlTest.control_id)
        )
    ).all()
    by_frequency: dict[str, dict[str, int]] = defaultdict(Counter)
    test_rows = []
    for t, system_name in tests:
        state, next_due = control_test_due(t, today)
        by_frequency[(t.frequency or "").lower() or "none"][state] += 1
        test_rows.append({"t": t, "system": system_name, "state": state, "next_due": next_due})
    order = {"due": 0, "never_run": 1, "scheduled": 2, "no_schedule": 3}
    test_rows.sort(key=lambda r: (order[r["state"]], r["next_due"] or date.max))
    return {
        "impl_counts": counts,
        "impl_total": len(impl_rows),
        "impl_rows": listed[:listed_limit],
        "impl_listed_total": len(listed),
        "tests": test_rows[:listed_limit],
        "tests_total": len(test_rows),
        "tests_by_frequency": {k: dict(v) for k, v in sorted(by_frequency.items())},
    }


# ── Compensating controls ────────────────────────────────────────────────────


async def compensating_in_scope(
    session: AsyncSession, cc_id: int, org: int | None
) -> CompensatingControl:
    stmt = select(CompensatingControl).where(CompensatingControl.id == cc_id)
    if org is not None:
        stmt = stmt.where(CompensatingControl.organization_id == org)
    cc = (await session.execute(stmt)).scalar_one_or_none()
    if cc is None:
        raise RefusalError(404, "compensating control not found")
    return cc


async def propose_compensating(
    session: AsyncSession,
    org: int | None,
    *,
    actor: str,
    system_id: int,
    control_identifier: str,
    measure: str,
    rationale: str,
    expires_on: date | None,
    today: date,
) -> CompensatingControl:
    stmt = select(System).where(System.id == system_id, System.deleted_at.is_(None))
    if org is not None:
        stmt = stmt.where(System.organization_id == org)
    system = (await session.execute(stmt)).scalar_one_or_none()
    if system is None:
        raise RefusalError(404, "system not found")
    raw = _clean(control_identifier)
    if raw is None:
        raise RefusalError(422, "name the control this measure compensates for")
    canon = canonicalize(raw)
    candidates = {raw} | ({canon.value} if canon is not None else set())
    identifier = (
        await session.execute(
            select(Control.identifier).where(Control.identifier.in_(candidates)).limit(1)
        )
    ).scalar_one_or_none()
    if identifier is None:
        raise RefusalError(422, f"{raw} is not a control in the catalog")
    measure_clean, rationale_clean = _clean(measure), _clean(rationale)
    if measure_clean is None or rationale_clean is None:
        raise RefusalError(422, "a compensating control needs both the measure and the rationale")
    if expires_on is not None and expires_on < today:
        raise RefusalError(422, "the expiry date is already past")
    cc = CompensatingControl(
        organization_id=system.organization_id,
        system_id=system.id,
        control_identifier=identifier,
        measure=measure_clean,
        rationale=rationale_clean,
        status="proposed",
        proposed_by=actor,
        expires_on=expires_on,
    )
    session.add(cc)
    await session.flush()
    return cc


def decide_compensating(
    cc: CompensatingControl, *, actor: str, approve: bool, now: datetime
) -> None:
    if cc.status != "proposed":
        raise RefusalError(409, f"this compensating control is already {cc.status}")
    if not may_sign_off(cc.proposed_by, actor):
        raise RefusalError(
            403,
            "separation of duties: whoever proposed a compensating control cannot "
            "decide it; another administrator must",
        )
    cc.status = "approved" if approve else "rejected"
    cc.decided_by = actor
    cc.decided_at = now


def retire_compensating(cc: CompensatingControl) -> None:
    if cc.status != "approved":
        raise RefusalError(
            409, f"only an approved compensating control can be retired, not {cc.status}"
        )
    cc.status = "retired"


async def compensating_controls(
    session: AsyncSession, org: int | None, *, status: str | None = None
) -> list[tuple[CompensatingControl, str]]:
    """With the system's name; a soft-deleted system's records are left out."""
    stmt = (
        select(CompensatingControl, System.name)
        .join(System, System.id == CompensatingControl.system_id)
        .where(System.deleted_at.is_(None))
        .order_by(CompensatingControl.id.desc())
    )
    if org is not None:
        stmt = stmt.where(CompensatingControl.organization_id == org)
    if status is not None:
        stmt = stmt.where(CompensatingControl.status == status)
    return [(cc, name) for cc, name in (await session.execute(stmt)).all()]


# ── Audit readiness ──────────────────────────────────────────────────────────


async def readiness(session: AsyncSession, org: int | None, today: date) -> list[dict[str, Any]]:
    """Per open engagement: PBC accepted ÷ requested, workpapers final ÷
    total, open findings by severity. Each ratio is None over nothing."""
    stmt = (
        select(AuditEngagement)
        .where(AuditEngagement.status != ENGAGEMENT_CLOSED)
        .order_by(AuditEngagement.target_on.nulls_last(), AuditEngagement.id)
    )
    if org is not None:
        stmt = stmt.where(AuditEngagement.organization_id == org)
    open_engagements = list((await session.execute(stmt)).scalars().all())
    ids = [e.id for e in open_engagements]
    if not ids:
        return []
    req: dict[int, Counter[str]] = defaultdict(Counter)
    for eid, status, due in (
        await session.execute(
            select(AuditRequest.engagement_id, AuditRequest.status, AuditRequest.due_on).where(
                AuditRequest.engagement_id.in_(ids)
            )
        )
    ).all():
        req[eid]["total"] += 1
        if status == REQUEST_DONE:
            req[eid]["accepted"] += 1
        elif due is not None and due < today:
            req[eid]["overdue"] += 1
    wps: dict[int, Counter[str]] = defaultdict(Counter)
    for eid, status, n in (
        await session.execute(
            select(AuditWorkpaper.engagement_id, AuditWorkpaper.status, func.count())
            .where(AuditWorkpaper.engagement_id.in_(ids))
            .group_by(AuditWorkpaper.engagement_id, AuditWorkpaper.status)
        )
    ).all():
        wps[eid][status] += int(n)
    sev: dict[int, Counter[str]] = defaultdict(Counter)
    for eid, severity, n in (
        await session.execute(
            select(AuditFinding.engagement_id, AuditFinding.severity, func.count())
            .where(
                AuditFinding.engagement_id.in_(ids),
                AuditFinding.status != FINDING_CLOSED,
                _finding_on_live_system(org),
            )
            .group_by(AuditFinding.engagement_id, AuditFinding.severity)
        )
    ).all():
        sev[eid][severity] += int(n)
    out = []
    for e in open_engagements:
        r, w, s = req[e.id], wps[e.id], sev[e.id]
        wp_total = sum(w.values())
        out.append(
            {
                "e": e,
                "pbc_accepted": r["accepted"],
                "pbc_total": r["total"],
                "pbc_overdue": r["overdue"],
                "pbc_pct": ratio(r["accepted"], r["total"]),
                "wp_final": w["final"],
                "wp_total": wp_total,
                "wp_pct": ratio(w["final"], wp_total),
                "findings": {k: s.get(k, 0) for k in SEVERITIES},
                "findings_other": sum(n for k, n in s.items() if k not in SEVERITIES),
                "findings_open": sum(s.values()),
            }
        )
    return out
