"""Seed + summarize per-control assessment results from the scoring matrix."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Assessment, AssessmentControlResult, ScoringControl

# Determination outcomes (NIST SP 800-171A language).
FINDINGS = ("not_assessed", "satisfied", "other_than_satisfied", "not_applicable")
_MET = {"satisfied", "not_applicable"}


def _objective_findings(rec: ScoringControl) -> list[dict[str, str]]:
    parts = list(rec.objective_parts or [])
    return [
        {"label": p.get("label", ""), "text": p.get("text", ""), "finding": "not_assessed"}
        for p in parts
    ]


async def seed_assessment_results(session: AsyncSession, assessment: Assessment) -> int:
    """Create a result row for every scoring control. Returns the count created."""
    controls = (
        (await session.execute(select(ScoringControl).order_by(ScoringControl.sort_order)))
        .scalars()
        .all()
    )
    existing = {
        r.control_id
        for r in (
            await session.execute(
                select(AssessmentControlResult).where(
                    AssessmentControlResult.assessment_id == assessment.id
                )
            )
        )
        .scalars()
        .all()
    }
    created = 0
    for order, rec in enumerate(controls):
        if rec.control_id in existing:
            continue
        session.add(
            AssessmentControlResult(
                assessment_id=assessment.id,
                control_id=rec.control_id,
                nist_id=rec.nist_id,
                domain=rec.domain,
                title=rec.title,
                requirement=rec.requirement,
                finding="not_assessed",
                objective_findings=_objective_findings(rec),
                sort_order=order,
            )
        )
        created += 1
    await session.commit()
    return created


def result_to_dict(r: AssessmentControlResult) -> dict[str, Any]:
    return {
        "control_id": r.control_id,
        "nist_id": r.nist_id,
        "domain": r.domain,
        "title": r.title,
        "requirement": r.requirement,
        "finding": r.finding,
        "objective_findings": list(r.objective_findings or []),
        "examine_note": r.examine_note,
        "interview_note": r.interview_note,
        "test_note": r.test_note,
        "assessor_note": r.assessor_note,
        "evidence_ref": r.evidence_ref,
        "reviewed": r.reviewed,
        "reviewer": r.reviewer,
    }


def summarize_results(results: Iterable[AssessmentControlResult]) -> dict[str, Any]:
    """Counts overall + per domain, plus assessment progress / review status."""
    by_finding: dict[str, int] = dict.fromkeys(FINDINGS, 0)
    by_domain: dict[str, dict[str, int]] = {}
    total = assessed = reviewed = 0
    for r in results:
        total += 1
        by_finding[r.finding] = by_finding.get(r.finding, 0) + 1
        if r.finding != "not_assessed":
            assessed += 1
        if r.reviewed:
            reviewed += 1
        dom = by_domain.setdefault(
            r.domain or "?", {"total": 0, "satisfied": 0, "other_than_satisfied": 0}
        )
        dom["total"] += 1
        if r.finding == "satisfied":
            dom["satisfied"] += 1
        elif r.finding == "other_than_satisfied":
            dom["other_than_satisfied"] += 1
    return {
        "total": total,
        "assessed": assessed,
        "reviewed": reviewed,
        "by_finding": by_finding,
        "by_domain": by_domain,
        "complete_pct": round(assessed / total * 100, 1) if total else 0.0,
    }
