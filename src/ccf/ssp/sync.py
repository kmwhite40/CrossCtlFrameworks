"""Scan-derived SSP impact summary.

The SSP editor needs to show what live audit evidence means before an operator
regenerates statements or downloads the document: which controls have passing
machine evidence, which carry open findings/POA&Ms, and which still require
manual review. This module keeps that read model beside the rest of SSP logic
instead of burying another copy of the posture joins in a route handler.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..constants import POAM_ACTIVE_STATUSES
from ..models import POAM, SSPControlEntry, SSPProject
from ..models_grc import ControlTest, ControlTestResult
from .seed import entry_to_dict

_FINDING_STATUSES = {"fail", "warn"}
_MANUAL_REVIEW_STATUS = "manual_review_required"


def _dateish(value: object) -> str | None:
    if value is None:
        return None
    if hasattr(value, "date"):
        return value.date().isoformat()  # type: ignore[no-any-return, union-attr]
    return str(value)


async def project_scan_sync(
    session: AsyncSession, project: SSPProject
) -> dict[str, Any]:
    """Return scan evidence, open findings and SSP caveats for each project entry."""
    entries = (
        (
            await session.execute(
                select(SSPControlEntry)
                .where(SSPControlEntry.project_id == project.id)
                .order_by(SSPControlEntry.sort_order)
            )
        )
        .scalars()
        .all()
    )

    if project.system_id is None:
        return {
            "project_id": project.id,
            "system_id": None,
            "summary": {
                "controls": len(entries),
                "with_passing_evidence": 0,
                "with_open_findings": 0,
                "manual_review_required": 0,
                "ssp_blockers": len(entries),
            },
            "controls": [
                {
                    **entry_to_dict(entry),
                    "passing_evidence": [],
                    "open_findings": [],
                    "manual_review_required": [
                        {
                            "reason": "SSP project is not linked to a system",
                            "ssp_impact": "manual_evidence_required",
                        }
                    ],
                    "ssp_impact": "manual_evidence_required",
                }
                for entry in entries
            ],
        }

    latest_result_id = (
        select(ControlTestResult.id)
        .where(ControlTestResult.control_test_id == ControlTest.id)
        .order_by(ControlTestResult.run_at.desc(), ControlTestResult.id.desc())
        .limit(1)
        .correlate(ControlTest)
        .scalar_subquery()
    )
    result_rows = (
        await session.execute(
            select(ControlTest, ControlTestResult)
            .join(ControlTestResult, ControlTestResult.id == latest_result_id)
            .where(
                ControlTest.system_id == project.system_id,
                ControlTest.control_id.is_not(None),
            )
        )
    ).all()

    poam_by_test: dict[int, POAM] = {}
    for poam in (
        await session.execute(
            select(POAM).where(
                POAM.system_id == project.system_id,
                POAM.source == "control_test",
                POAM.source_ref.like("control_test:%"),
                POAM.status.in_(POAM_ACTIVE_STATUSES),
            )
        )
    ).scalars():
        ref = str(poam.source_ref or "")
        _, _, raw_test_id = ref.partition(":")
        if raw_test_id.isdigit():
            poam_by_test[int(raw_test_id)] = poam

    passing_by_control: dict[str, list[dict[str, Any]]] = {}
    findings_by_control: dict[str, list[dict[str, Any]]] = {}
    manual_by_control: dict[str, list[dict[str, Any]]] = {}
    for test, result in result_rows:
        control_id = str(test.control_id)
        row = {
            "test_id": test.id,
            "result_id": result.id,
            "check_key": test.check_key,
            "check": test.name,
            "connector": test.connector_type,
            "status": result.status,
            "detail": result.detail,
            "expected": result.expected or test.expected,
            "evidence_ref": result.evidence_ref,
            "evaluated": result.evaluated,
            "failing": result.failing,
            "waived": result.waived,
            "observed_on": _dateish(result.run_at or test.last_tested_at),
        }
        if result.status == "pass":
            passing_by_control.setdefault(control_id, []).append(row)
        elif result.status in _FINDING_STATUSES:
            poam = poam_by_test.get(test.id)
            if poam is not None:
                row["poam"] = {
                    "id": poam.id,
                    "status": poam.status,
                    "severity": poam.severity,
                    "title": poam.title,
                    "due_on": poam.due_on,
                }
            findings_by_control.setdefault(control_id, []).append(row)
        elif result.status == _MANUAL_REVIEW_STATUS:
            manual_by_control.setdefault(control_id, []).append(row)

    controls: list[dict[str, Any]] = []
    with_passing = with_findings = with_manual = blockers = 0
    for entry in entries:
        control_id = entry.control_id
        passing = passing_by_control.get(control_id, [])
        findings = findings_by_control.get(control_id, [])
        manual = manual_by_control.get(control_id, [])
        if passing:
            with_passing += 1
        if findings:
            with_findings += 1
        if manual:
            with_manual += 1
        if findings or manual:
            blockers += 1
        if findings:
            impact = "open_poam_or_finding"
        elif manual:
            impact = "manual_evidence_required"
        elif passing:
            impact = "automated_evidence_available"
        else:
            impact = "no_scan_evidence"
        controls.append(
            {
                **entry_to_dict(entry),
                "passing_evidence": passing,
                "open_findings": findings,
                "manual_review_required": manual,
                "ssp_impact": impact,
            }
        )

    return {
        "project_id": project.id,
        "system_id": project.system_id,
        "summary": {
            "controls": len(entries),
            "with_passing_evidence": with_passing,
            "with_open_findings": with_findings,
            "manual_review_required": with_manual,
            "ssp_blockers": blockers,
        },
        "controls": controls,
    }
