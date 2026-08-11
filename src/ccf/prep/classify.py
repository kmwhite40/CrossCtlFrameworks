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

Every call is recorded with ``ccf.ai_actions.provenance.record_ai_run``: an
``ai_action_runs`` row (provider, model, prompt version, input/output SHA-256
hashes) with ``status="recorded"`` distinguishing it from an approval-gated
``run_action`` run, one ``ai_action_citations`` row for the unit itself, and a
link back on ``PrepClassification.ai_action_run_id``. This deliberately does
not route through ``ccf.ai_actions.run_action`` — that function takes an
entity and builds its own prompt, where this module's per-passage-bounded
prompt and candidate-validated output are themselves the safety property.
Recording never fails the classification it documents: ``record_ai_run``
writes inside its own savepoint and returns ``None`` on failure, leaving
``ai_action_run_id`` ``NULL`` rather than losing the classification. Evidence
classified before this recording existed keeps that ``NULL`` permanently —
historical rows are not retrofitted. When ``ai_store_prompts`` is off, only
the prompt's hash is kept, not its text.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..ai import gateway
from ..ai_actions.provenance import CitationRef, record_ai_run
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
        prompt = build_prompt(unit.content, candidates)
        try:
            result = await gateway.generate_structured_resolved(
                session,
                run.organization_id,
                prompt=prompt,
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

        data = result.data

        # Trust the schema for shape, but never let the model widen its own scope
        # beyond the controls screening actually surfaced. When screening surfaced
        # no candidates at all, `allowed` is empty and every returned identifier is
        # dropped — an empty candidate set must never be treated as "unbounded".
        allowed = set(candidates)
        chosen = [c for c in data.get("control_identifiers", []) if c in allowed]

        classification = PrepClassification(
            unit_id=unit.id,
            run_id=run.id,
            organization_id=run.organization_id,
            control_identifiers=chosen,
            artifact_type=data.get("artifact_type"),
            evidence_strength=data.get("evidence_strength"),
            explanation=data.get("explanation"),
            model_confidence=float(data.get("confidence", 0.0)),
        )
        session.add(classification)
        # Flush the classification now, before calling record_ai_run. The
        # session factory runs with autoflush disabled, so this INSERT is
        # still pending; record_ai_run flushes inside its own begin_nested()
        # savepoint, and an unflushed add is not tagged to any particular
        # savepoint -- it would simply go out with whichever flush reaches it
        # first. Flushing here first keeps this classification's INSERT in
        # the outer (per-run) transaction, so a provenance failure's
        # savepoint rollback -- scoped to record_ai_run's own writes -- has
        # no way to take it down too.
        await session.flush()

        try:
            # record_ai_run is documented to never raise -- it wraps its own
            # writes in a begin_nested() savepoint and returns None on
            # failure -- but this call site does not lean on that promise
            # holding forever. A provenance failure, however it happens, must
            # cost this unit its ai_action_run_id, never its classification.
            ai_run = await record_ai_run(
                session,
                action_key=ACTION_KEY,
                entity_type="prep_unit",
                entity_id=str(unit.id),
                organization_id=run.organization_id,
                provider=result.provider,
                model=result.model,
                prompt=prompt,
                output=data,
                citations=[CitationRef(source_type="prep_unit", source_id=str(unit.id))],
            )
        except Exception as exc:
            log.warning(
                "prep.classify_provenance_failed",
                run_id=run.id,
                unit_id=unit.id,
                error=str(exc),
            )
            ai_run = None

        classification.ai_action_run_id = ai_run.id if ai_run is not None else None
        # Flush this UPDATE immediately, for the same reason the insert above
        # was flushed early: the *next* unit's record_ai_run call opens its
        # own begin_nested() and flushes inside it, and with autoflush
        # disabled that flush would pull in any still-pending change here —
        # including this one. Left unflushed, a provenance failure on the
        # *next* unit would roll back this unit's already-decided
        # ai_action_run_id right along with it.
        await session.flush()
        classified += 1

    run.units_classified = classified
    run.stage_classify = "complete"
    await session.flush()
    log.info("prep.classify_complete", run_id=run.id, units=classified)
    return classified
