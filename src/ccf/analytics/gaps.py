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
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import System, Task
from ..models_grc import ControlTest, ControlTestResult, ControlTestResourceResult

#: How many failing resources to name per control. The full set is on the
#: control-test page; a rollup that printed 74 user principal names would bury
#: the control it is reporting.
EXAMPLES_PER_GAP = 4

#: Order gaps by how much is broken, not alphabetically: the control with 74
#: failing resources is the one to open first.
_WORST_FIRST = (ControlTestResult.failing.desc(), ControlTest.control_id.asc())


async def compliance_gaps(session: AsyncSession, org_id: int | None) -> dict[str, Any]:
    """Every assessed control for this organization, failures first.

    ``org_id`` of ``None`` returns the empty shape rather than every tenant's
    gaps: this drives a customer-facing page, and "no organization" is not a
    licence to show all of them.
    """
    empty: dict[str, Any] = {
        "assessed": 0,
        "failing": 0,
        "passing": 0,
        "resources_evaluated": 0,
        "resources_failing": 0,
        "open_tasks": 0,
        "last_assessed": None,
        "gaps": [],
        "clean": [],
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

    result_ids = [res.id for _t, res, _s in rows if res.status == "fail"]
    examples: dict[int, list[str]] = {}
    if result_ids:
        for result_id, observed in (
            await session.execute(
                select(
                    ControlTestResourceResult.result_id,
                    ControlTestResourceResult.observed,
                )
                .where(
                    ControlTestResourceResult.result_id.in_(result_ids),
                    ControlTestResourceResult.verdict == "fail",
                )
                .order_by(ControlTestResourceResult.id)
            )
        ).all():
            bucket = examples.setdefault(result_id, [])
            if len(bucket) < EXAMPLES_PER_GAP:
                bucket.append(str(observed))

    gaps: list[dict[str, Any]] = []
    clean: list[dict[str, Any]] = []
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
        (gaps if result.status == "fail" else clean).append(entry)

    open_tasks = (
        await session.execute(
            select(func.count(Task.id)).where(
                Task.organization_id == org_id, Task.status == "open"
            )
        )
    ).scalar_one()

    return {
        "assessed": len(rows),
        "failing": len(gaps),
        "passing": len(clean),
        "resources_evaluated": evaluated,
        "resources_failing": failing_resources,
        "open_tasks": open_tasks,
        "last_assessed": last_assessed,
        "gaps": gaps,
        "clean": clean,
        "systems_assessed": len(systems),
    }


__all__ = ["EXAMPLES_PER_GAP", "compliance_gaps"]
