"""What a customer has to fix, in one answer.

The platform already recorded everything this reports: a scan writes a
``ControlTest`` per check with a ``ControlTestResult`` and a
``ControlTestResourceResult`` per resource, and a failing result opens a
remediation task. What it had no view for was the question an operator
actually asks -- *which controls are failing, on what, and what do I do* --
so the answer was spread across `/control-tests`, `/posture`, `/governance`
and `/poams`, and no page rolled it up.

Scoped to one organization throughout, and to **live** systems: a deleted
system's failures are not a customer's outstanding work, and analytics that
forgot that once put a deleted system's score in the executive headline.

A formally accepted finding is reported **separately, never as passing**. This
page answers "what is outstanding", and an acceptance is a decision about the
consequence, not about the evidence: the status stays ``fail``, the observation
stays, and `framework_posture` still counts the control as not operating --
which is correct there, because it measures whether a control works, not
whether somebody signed for it. What the report could not do before was tell
an operator which of its rows had already been decided, so an accepted risk sat
in the queue looking exactly like untouched work.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..governance.waivers import cover, is_active, waivers_for_tests
from ..models import System, Task
from ..models_grc import ControlTest, ControlTestResourceResult, ControlTestResult
from ..posture.types import ResourceFinding

#: How many failing resources to name per control. The full set is on the
#: control-test page; a rollup that printed 74 user principal names would bury
#: the control it is reporting.
EXAMPLES_PER_GAP = 4

#: Order gaps by how much is broken, not alphabetically: the control with 74
#: failing resources is the one to open first.
_WORST_FIRST = (ControlTestResult.failing.desc(), ControlTest.control_id.asc())


#: Verdicts that mean Concord assessed the control and could not confirm it.
#: Grouped, because what an operator does about them is identical -- go and look.
#: The same pairing `ccf.analytics.framework_posture` makes, deliberately: two
#: surfaces disagreeing about which bucket a `warn` belongs in is how one number
#: on a dashboard stops matching another.
_NEEDS_A_HUMAN: frozenset[str] = frozenset({"warn", "manual_review_required"})


async def compliance_gaps(
    session: AsyncSession, org_id: int | None, *, today: date | None = None
) -> dict[str, Any]:
    """Every assessed control for this organization, failures first.

    ``org_id`` of ``None`` returns the empty shape rather than every tenant's
    gaps: this drives a customer-facing page, and "no organization" is not a
    licence to show all of them.

    ``today`` decides which acceptances are in force and defaults to the local
    date. Pass it to test expiry; the pure coverage layer never reads a clock.
    """
    today = today or date.today()
    empty: dict[str, Any] = {
        "assessed": 0,
        "failing": 0,
        "open": 0,
        "accepted": 0,
        "passing": 0,
        "manual_review": 0,
        "not_in_scope": 0,
        "resources_evaluated": 0,
        "resources_failing": 0,
        "open_tasks": 0,
        "last_assessed": None,
        "gaps": [],
        "clean": [],
        "review": [],
        "systems_assessed": 0,
    }
    if org_id is None:
        return empty

    # The latest result per test, joined to its live system.
    latest = (
        select(
            ControlTestResult.control_test_id.label("test_id"),
            func.max(ControlTestResult.run_at).label("run_at"),
        )
        .group_by(ControlTestResult.control_test_id)
        .subquery()
    )
    rows = (
        await session.execute(
            select(ControlTest, ControlTestResult, System)
            .join(latest, latest.c.test_id == ControlTest.id)
            .join(
                ControlTestResult,
                (ControlTestResult.control_test_id == ControlTest.id)
                & (ControlTestResult.run_at == latest.c.run_at),
            )
            .join(System, System.id == ControlTest.system_id)
            .where(
                ControlTest.organization_id == org_id,
                System.deleted_at.is_(None),
            )
            .order_by(*_WORST_FIRST)
        )
    ).all()
    if not rows:
        return empty

    review: list[dict[str, Any]] = []
    not_in_scope = 0
    result_ids = [res.id for _t, res, _s in rows if res.status == "fail"]
    examples: dict[int, list[str]] = {}
    # Per-resource findings for the failing results, which is what `cover`
    # decides acceptance from. Every failing resource is loaded, not only the
    # `EXAMPLES_PER_GAP` shown: acceptance requires that *all* of them be
    # covered, so truncating here would report a partly accepted finding as
    # fully accepted -- the one mistake this must not make.
    findings: dict[int, list[ResourceFinding]] = {}
    if result_ids:
        for result_id, resource_id, resource_type, verdict, observed in (
            await session.execute(
                select(
                    ControlTestResourceResult.result_id,
                    ControlTestResourceResult.resource_id,
                    ControlTestResourceResult.resource_type,
                    ControlTestResourceResult.verdict,
                    ControlTestResourceResult.observed,
                )
                .where(ControlTestResourceResult.result_id.in_(result_ids))
                .order_by(ControlTestResourceResult.id)
            )
        ).all():
            findings.setdefault(result_id, []).append(
                ResourceFinding(
                    resource_id=resource_id,
                    resource_type=resource_type,
                    verdict=verdict,
                    observed=str(observed or ""),
                )
            )
            if verdict == "fail":
                bucket = examples.setdefault(result_id, [])
                if len(bucket) < EXAMPLES_PER_GAP:
                    bucket.append(str(observed))

    # Acceptances evaluated against today, not the counters the last scan
    # stored: a waiver approved after that run would otherwise leave the row
    # reading as untouched work until somebody happened to re-scan.
    candidates = await waivers_for_tests(
        session, [t for t, res, _s in rows if res.status == "fail"]
    )

    gaps: list[dict[str, Any]] = []
    clean: list[dict[str, Any]] = []
    accepted_count = 0
    evaluated = failing_resources = 0
    last_assessed: datetime | None = None
    systems: set[int] = set()

    for test, result, system in rows:
        evaluated += result.evaluated or 0
        failing_resources += result.failing or 0
        systems.add(system.id)
        if last_assessed is None or (result.run_at and result.run_at > last_assessed):
            last_assessed = result.run_at
        entry = {
            "control_id": test.control_id,
            "check": test.name,
            "system_id": system.id,
            "system": system.name,
            "status": result.status,
            "evaluated": result.evaluated or 0,
            "failing": result.failing or 0,
            "expected": result.expected,
            "detail": result.detail,
            "run_at": result.run_at,
            "test_id": test.id,
            "examples": examples.get(result.id, []),
        }
        if result.status == "fail":
            waivers = candidates.get(test.id, [])
            coverage = cover(findings.get(result.id, ()), waivers, today=today)
            active = [w for w in waivers if is_active(w, today=today)]
            # `suppress` is the same flag the scan uses to decide whether to
            # alert, so "accepted" here means exactly what it means there.
            entry["accepted"] = coverage.suppress
            entry["waived_resources"] = coverage.waived
            entry["uncovered_resources"] = len(coverage.uncovered)
            entry["requested_waivers"] = sum(1 for w in waivers if w.status == "requested")
            # The soonest expiry among the acceptances in force: the date this
            # row comes back. `None` when an acceptance is indefinite, which the
            # view has to render differently -- an acceptance that never lapses
            # is permitted and is worth seeing.
            expiries = [w.expires_on for w in active]
            entry["accepted_until"] = (
                min((e for e in expiries if e is not None), default=None) if active else None
            )
            entry["accepted_indefinitely"] = coverage.suppress and any(
                w.expires_on is None for w in active
            )
            if coverage.suppress:
                accepted_count += 1
            gaps.append(entry)
        elif result.status == "pass":
            clean.append(entry)
        elif result.status in _NEEDS_A_HUMAN:
            review.append(entry)
        else:
            # `not_applicable` / `not_tested`. Counted, not listed: there is
            # nothing to act on, and a list of them on the landing page would
            # compete with the ones there are.
            not_in_scope += 1

    # Outstanding work first. `_WORST_FIRST` already ordered by how much is
    # broken; this is a stable partition on top of it, so an accepted row keeps
    # its place relative to other accepted rows.
    gaps.sort(key=lambda g: g["accepted"])

    open_tasks = (
        await session.execute(
            select(func.count(Task.id)).where(
                Task.organization_id == org_id, Task.status == "open"
            )
        )
    ).scalar_one()

    return {
        "assessed": len(rows),
        # `failing` is unchanged: every control whose latest run failed. The
        # split is additive so no existing reader silently changes meaning.
        "failing": len(gaps),
        "open": len(gaps) - accepted_count,
        "accepted": accepted_count,
        # Only `pass`. This read `len(clean)` over everything that was not a
        # failure, so `manual_review_required`, `warn`, `not_applicable` and
        # `not_tested` were all reported as passing controls -- in green, on the
        # page an operator lands on at sign-in. Measured before the fix: five
        # control tests, one passing, four reported as passing.
        "passing": len(clean),
        # Concord looked and could not confirm. `warn` and
        # `manual_review_required` together, the grouping `framework_posture`
        # uses, because what is actionable about them is the same: a human has to
        # look. These are the controls an AWS account with Security Hub
        # half-enabled produces in bulk.
        "manual_review": len(review),
        # Nothing was in scope (`not_applicable`) or no test has run
        # (`not_tested`). Separated from `manual_review` because there is nothing
        # to schedule, and from `passing` because neither asserts the control is
        # satisfied.
        "not_in_scope": not_in_scope,
        "resources_evaluated": evaluated,
        "resources_failing": failing_resources,
        "open_tasks": open_tasks,
        "last_assessed": last_assessed,
        "gaps": gaps,
        "clean": clean,
        "review": review,
        "systems_assessed": len(systems),
    }


__all__ = ["EXAMPLES_PER_GAP", "compliance_gaps"]
