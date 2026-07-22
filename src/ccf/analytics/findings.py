"""Cross-source finding-status rollup (ISSM-13 / DATA-05).

A control's finding/status lives in three places with three different
vocabularies — see ``ccf.constants`` for the full explanation:

- ``AssessmentResult.finding`` (DB enum)
- ``AssessmentControlResult.finding`` (free string)
- ``ScoringStatus.state`` (free string, SPRS implementation state)

This module is the "rollup" that combines finding counts *across* those
sources for a system: every raw value is passed through
``ccf.constants.normalize_finding`` before counting, so a mixed-vocabulary
set (e.g. one row storing ``"other_than_satisfied"`` and another storing
``"not_implemented"``) lands in the same canonical bucket instead of being
counted as two different things.

Per-source storage and per-source rollups (e.g.
``ccf.assessment.seed.summarize_results``, which reports
``AssessmentControlResult.finding`` counts as-is) are untouched — this module
only normalizes the *combined* view.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..constants import ALL_CANONICAL_FINDINGS, normalize_finding
from ..models import Assessment, AssessmentControlResult, AssessmentResult, ScoringStatus


def canonical_finding_counts(raw_values: Iterable[str | None]) -> dict[str, int]:
    """Normalize a mixed-vocabulary iterable of raw finding/state values.

    Pure function (no DB access) so the counting logic is independently
    testable; ``system_finding_rollup`` below is a thin DB-backed wrapper
    around it. Every canonical bucket is present in the result (zero-filled)
    even if no input value normalized to it, so callers can index the result
    without a ``KeyError``/``.get`` dance.
    """
    counts: dict[str, int] = dict.fromkeys(ALL_CANONICAL_FINDINGS, 0)
    for raw in raw_values:
        canon = normalize_finding(raw)
        counts[canon] = counts.get(canon, 0) + 1
    return counts


async def system_finding_rollup(session: AsyncSession, system_id: int) -> dict[str, Any]:
    """Combined canonical finding counts for one system, across all three sources.

    Pulls the raw values straight from each source's own column (no
    per-source transformation), then feeds the combined list through
    ``canonical_finding_counts``. Also reports the pre-normalization
    per-source counts alongside, purely for visibility/debugging — the
    per-source *behavior* elsewhere in the app is unaffected by this
    function existing.
    """
    assessment_result_findings = (
        await session.execute(
            select(AssessmentResult.finding)
            .join(Assessment, Assessment.id == AssessmentResult.assessment_id)
            .where(Assessment.system_id == system_id)
        )
    ).scalars().all()

    assessment_control_findings = (
        await session.execute(
            select(AssessmentControlResult.finding)
            .join(Assessment, Assessment.id == AssessmentControlResult.assessment_id)
            .where(Assessment.system_id == system_id)
        )
    ).scalars().all()

    scoring_states = (
        await session.execute(
            select(ScoringStatus.state).where(ScoringStatus.system_id == system_id)
        )
    ).scalars().all()

    combined = (
        list(assessment_result_findings)
        + list(assessment_control_findings)
        + list(scoring_states)
    )

    return {
        "system_id": system_id,
        "canonical": canonical_finding_counts(combined),
        "by_source": {
            "assessment_results": canonical_finding_counts(assessment_result_findings),
            "assessment_control_results": canonical_finding_counts(assessment_control_findings),
            "scoring_statuses": canonical_finding_counts(scoring_states),
        },
        "total": len(combined),
    }
