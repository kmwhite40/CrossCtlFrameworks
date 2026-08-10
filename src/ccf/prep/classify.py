"""Model-driven classification of prepared evidence units.

This is the only stage that asks a model to reason, so it runs through the AI
gateway with a strict JSON schema and records its output as data, never as prose.
The model's scope is bounded three ways: it sees one unit at a time, it chooses
from the candidate controls screening already surfaced, and it returns values
from a fixed vocabulary. What the classification *means* — whether a control is
satisfied — is decided later by application code and an assessor, never here.

Screening candidates bound the prompt because handing the model the whole 800-53
catalog would both cost more and invite invention. Screening (Task 9) also
collapses candidates to base control identifiers before ranking, so
``candidate_controls`` never contains an enhancement-level identifier (e.g.
``AC-6(2)``) — only base ones (``AC-6``). Because the classifier's own scope is
bounded by that same candidate set, it can never cite an enhancement either;
that is a deliberate, recorded tradeoff of the screening design, not a bug here.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..ai import gateway
from ..logging import get_logger
from ..models_prep import PrepClassification, PrepRun, PrepScreen, PrepUnit

log = get_logger(__name__)

ACTION_KEY = "classify_evidence_unit"

ARTIFACT_TYPES = (
    "policy",
    "procedure",
    "technical_implementation",
    "testing_evidence",
    "management_approval",
    "other",
)

EVIDENCE_STRENGTHS = ("strong", "moderate", "weak")

CLASSIFICATION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "control_identifiers": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Controls this passage supports, from the candidates offered.",
        },
        "artifact_type": {"type": "string", "enum": list(ARTIFACT_TYPES)},
        "evidence_strength": {"type": "string", "enum": list(EVIDENCE_STRENGTHS)},
        "explanation": {"type": "string"},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
    },
    "required": ["control_identifiers", "artifact_type", "evidence_strength", "confidence"],
    "additionalProperties": False,
}

_SYSTEM_PROMPT = (
    "You classify passages from security documentation against NIST SP 800-53 Rev 5 "
    "controls. You are not making a compliance determination and you do not decide "
    "whether a control is satisfied — an assessor does that later. Classify only what "
    "the passage actually says. If it does not support any of the candidate controls, "
    "return an empty control_identifiers array."
)


def build_prompt(unit_content: str, candidates: list[str]) -> str:
    """Build the classification prompt for one unit, bounded by its candidates."""
    offered = ", ".join(candidates) if candidates else "(none surfaced by screening)"
    return (
        f"Candidate controls: {offered}\n\n"
        f"Passage:\n{unit_content}\n\n"
        "Classify this passage. Choose control identifiers only from the candidates. "
        "artifact_type describes what kind of material this is. evidence_strength is how "
        "well it would support an assessment objective: 'strong' for a specific, dated, "
        "verifiable statement; 'moderate' for a clear but general one; 'weak' for a vague "
        "or aspirational one. This is a classification, not a determination."
    )


async def _candidates_for(session: AsyncSession, unit: PrepUnit) -> list[str]:
    row = (
        await session.execute(
            select(PrepScreen).where(PrepScreen.line_id == unit.trigger_line_id)
        )
    ).scalar_one_or_none()
    return [str(x) for x in row.candidate_controls] if row is not None else []


async def run_stage_classify(session: AsyncSession, run: PrepRun) -> int:
    """Classify every unit in the run. Returns the count classified."""
    run.stage_classify = "running"

    # Idempotent: clear prior output so a resumed run cannot double-write.
    await session.execute(
        delete(PrepClassification).where(PrepClassification.run_id == run.id)
    )

    units = (
        await session.execute(select(PrepUnit).where(PrepUnit.run_id == run.id))
    ).scalars().all()

    classified = 0
    for unit in units:
        candidates = await _candidates_for(session, unit)
        try:
            data = await gateway.generate_structured(
                session,
                run.organization_id,
                prompt=build_prompt(unit.content, candidates),
                schema=CLASSIFICATION_SCHEMA,
                purpose=ACTION_KEY,
                system=_SYSTEM_PROMPT,
            )
        except Exception as exc:  # any provider fault must leave the run resumable, not raise
            # A mid-run provider failure must not leave rows for the units already
            # classified this attempt while the run's own counter and status say
            # otherwise: clear that partial output and zero the counter so the
            # persisted rows agree with `units_classified` at every point after
            # this returns. The session factory runs with autoflush disabled, so
            # the classifications added earlier in this loop are still pending —
            # flush first so the delete actually finds and removes them, rather
            # than deleting zero rows and then flushing the "orphaned" partial
            # inserts back in afterward.
            await session.flush()
            await session.execute(
                delete(PrepClassification).where(PrepClassification.run_id == run.id)
            )
            run.units_classified = 0
            run.status = "failed"
            run.stage_classify = "failed"
            run.error_stage = "classify"
            run.error = f"classification failed: {exc}"
            await session.flush()
            log.warning("prep.classify_failed", run_id=run.id, error=str(exc))
            return 0

        # Trust the schema for shape, but never let the model widen its own scope
        # beyond the controls screening actually surfaced. When screening surfaced
        # no candidates at all, `allowed` is empty and every returned identifier is
        # dropped — an empty candidate set must never be treated as "unbounded".
        allowed = set(candidates)
        chosen = [c for c in data.get("control_identifiers", []) if c in allowed]

        session.add(
            PrepClassification(
                unit_id=unit.id,
                run_id=run.id,
                organization_id=run.organization_id,
                control_identifiers=chosen,
                artifact_type=data.get("artifact_type"),
                evidence_strength=data.get("evidence_strength"),
                explanation=data.get("explanation"),
                model_confidence=float(data.get("confidence", 0.0)),
            )
        )
        classified += 1

    run.units_classified = classified
    run.stage_classify = "complete"
    await session.flush()
    log.info("prep.classify_complete", run_id=run.id, units=classified)
    return classified
