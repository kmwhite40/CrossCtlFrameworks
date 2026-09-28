"""Control-evaluation drilldowns for live audit results."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..constants import POAM_ACTIVE_STATUSES
from ..models import POAM
from ..models_grc import ControlTest, ControlTestResourceResult, ControlTestResult
from .latest import latest_result_ids
from .remediation import playbook_for


async def control_evaluations_for_system(
    session: AsyncSession, *, system_id: int, org_id: int | None
) -> list[dict[str, Any]]:
    """Latest scan-owned control evaluations for a system.

    This is the operator drilldown: expected state, observed latest result,
    failing resources, waiver references, and the POA&M opened from the failed
    control test when one exists.
    """
    latest = latest_result_ids()
    rows = (
        await session.execute(
            select(ControlTest, ControlTestResult)
            .join(latest, latest.c.control_test_id == ControlTest.id)
            .join(ControlTestResult, ControlTestResult.id == latest.c.result_id)
            .where(
                ControlTest.system_id == system_id,
                ControlTest.check_key.is_not(None),
            )
            .order_by(ControlTest.control_id, ControlTest.name)
        )
    ).all()

    out: list[dict[str, Any]] = []
    for test, result in rows:
        if org_id is not None and test.organization_id != org_id:
            continue
        resources = (
            await session.execute(
                select(ControlTestResourceResult)
                .where(ControlTestResourceResult.result_id == result.id)
                .order_by(
                    ControlTestResourceResult.verdict,
                    ControlTestResourceResult.resource_type,
                    ControlTestResourceResult.resource_id,
                )
            )
        ).scalars().all()
        poam = (
            await session.execute(
                select(POAM).where(
                    POAM.system_id == system_id,
                    POAM.source == "control_test",
                    POAM.source_ref == f"control_test:{test.id}",
                    POAM.status.in_(POAM_ACTIVE_STATUSES),
                )
            )
        ).scalar_one_or_none()
        playbook = playbook_for(test.check_key)
        out.append(
            {
                "control_test_id": test.id,
                "check_key": test.check_key,
                "control_id": test.control_id,
                "name": test.name,
                "connector": test.connector_type,
                "expected": result.expected or test.expected,
                "status": result.status,
                "detail": result.detail,
                "run_at": result.run_at,
                "evaluated": result.evaluated,
                "failing": result.failing,
                "waived": result.waived,
                "evidence_ref": result.evidence_ref,
                "resources": [
                    {
                        "resource_id": r.resource_id,
                        "resource_type": r.resource_type,
                        "verdict": r.verdict,
                        "observed": r.observed,
                        "detail": r.detail,
                        "waiver_id": r.waiver_id,
                    }
                    for r in resources
                ],
                "remediation": (
                    {
                        "actions": list(playbook.actions),
                        "evidence": list(playbook.evidence),
                        "milestones": list(playbook.milestones),
                    }
                    if playbook is not None
                    else None
                ),
                "poam": (
                    {
                        "id": poam.id,
                        "title": poam.title,
                        "status": poam.status,
                        "severity": poam.severity,
                        "due_on": poam.due_on,
                    }
                    if poam is not None
                    else None
                ),
            }
        )
    return out
