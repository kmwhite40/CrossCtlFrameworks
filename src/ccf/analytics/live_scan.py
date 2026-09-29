"""Current live-scan posture rollups for UI pages.

Several pages historically reported only implementation rows or formal tasks,
while posture scans write ``ControlTest`` / ``ControlTestResult`` records. These
helpers give pages one shared view of the latest scan state.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import System
from ..models_grc import ControlTest, ControlTestResult
from ..posture.latest import latest_result_ids
from ..posture.rollup import EXCLUDED_FROM_ROLLUP

ATTENTION_STATUSES = {"fail", "warn", "manual_review_required"}

#: Statuses that are not a judgement about the control, so they cannot sit in a
#: health denominator. Taken from the posture rollup rather than restated: a
#: second list of "verdicts that do not count" is how two views of one scan come
#: to disagree.
#:
#: This matters more than it looks. ``not_applicable`` is what a check returns
#: when nothing was in scope -- an unlicensed tenant makes every staleness
#: finding ``not_applicable`` -- so counting it made a system where nothing could
#: be assessed report **0% health**, which reads as catastrophic rather than as
#: "nothing was assessable". ``manual_review_required`` deliberately stays in the
#: denominator: the check should have produced a verdict and did not, and a
#: system is not demonstrably healthy on a control nobody could check.
_UNASSESSABLE = EXCLUDED_FROM_ROLLUP


def _empty(system_id: int | None = None) -> dict[str, Any]:
    return {
        "system_id": system_id,
        "total": 0,
        # Of `total`, the checks that actually judged the control -- the
        # denominator `health_pct` is out of. Exposed rather than left implicit
        # so "80%" can be read as "8 of 10 assessable" instead of inviting the
        # reader to divide by `total` and get a different number.
        "assessed": 0,
        "pass": 0,
        "fail": 0,
        "warn": 0,
        "manual_review_required": 0,
        "not_applicable": 0,
        "not_tested": 0,
        "other": 0,
        "attention": 0,
        "failing_resources": 0,
        "evaluated_resources": 0,
        "health_pct": None,
        "latest_run": None,
    }


def _add(summary: dict[str, Any], result: ControlTestResult) -> None:
    status = result.status
    summary["total"] += 1
    if status in summary:
        summary[status] += 1
    else:
        summary["other"] += 1
    if status not in _UNASSESSABLE:
        summary["assessed"] += 1
    if status in ATTENTION_STATUSES:
        summary["attention"] += 1
    summary["failing_resources"] += result.failing or 0
    summary["evaluated_resources"] += result.evaluated or 0
    if result.run_at is not None and (
        summary["latest_run"] is None or result.run_at > summary["latest_run"]
    ):
        summary["latest_run"] = result.run_at


def _finalize(summary: dict[str, Any]) -> dict[str, Any]:
    # `None`, not 0, when nothing was assessable. A system whose every check
    # returned `not_applicable` has not been found unhealthy; it has not been
    # measured, and 0% is the loudest possible way of saying the wrong thing.
    if summary["assessed"]:
        summary["health_pct"] = round((summary["pass"] / summary["assessed"]) * 100)
    return summary


async def live_scan_by_system(
    session: AsyncSession, *, org_id: int | None = None
) -> dict[int, dict[str, Any]]:
    """Latest generated/live control-test result summary per live system."""
    latest = latest_result_ids()
    stmt = (
        select(ControlTest.system_id, ControlTestResult)
        .join(latest, latest.c.control_test_id == ControlTest.id)
        .join(ControlTestResult, ControlTestResult.id == latest.c.result_id)
        .join(System, System.id == ControlTest.system_id)
        .where(
            ControlTest.system_id.is_not(None),
            ControlTest.check_key.is_not(None),
            System.deleted_at.is_(None),
        )
    )
    if org_id is not None:
        stmt = stmt.where(ControlTest.organization_id == org_id)

    out: dict[int, dict[str, Any]] = {}
    for system_id, result in (await session.execute(stmt)).all():
        sid = int(system_id)
        row = out.setdefault(sid, _empty(sid))
        _add(row, result)
    return {sid: _finalize(row) for sid, row in out.items()}


async def live_scan_for_system(
    session: AsyncSession, *, system_id: int, org_id: int | None = None
) -> dict[str, Any]:
    """Latest generated/live control-test result summary for one system."""
    return (await live_scan_by_system(session, org_id=org_id)).get(system_id, _empty(system_id))


async def live_scan_for_org(
    session: AsyncSession, *, org_id: int | None = None
) -> dict[str, Any]:
    """Latest generated/live control-test result summary for all live systems."""
    summary = _empty()
    for row in (await live_scan_by_system(session, org_id=org_id)).values():
        summary["total"] += row["total"]
        summary["assessed"] += row["assessed"]
        for key in (
            "pass",
            "fail",
            "warn",
            "manual_review_required",
            "not_applicable",
            "not_tested",
            "other",
        ):
            summary[key] += row[key]
        summary["attention"] += row["attention"]
        summary["failing_resources"] += row["failing_resources"]
        summary["evaluated_resources"] += row["evaluated_resources"]
        if row["latest_run"] is not None and (
            summary["latest_run"] is None or row["latest_run"] > summary["latest_run"]
        ):
            summary["latest_run"] = row["latest_run"]
    return _finalize(summary)
