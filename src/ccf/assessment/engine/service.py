"""Orchestrate objective-level assessment for one control within one assessment.

This is the composition point for the engine: it reads a control's objectives
(T2), evaluates each against retrieved evidence (T3), and rolls the verdicts into
a *proposed* control finding (T4). Nothing here reaches ``AssessmentControlResult``
-- these rows are inert proposals until an assessor accepts them.

Two things make this orchestration, not just a loop:

* The organization is never trusted from a caller argument. It is derived from
  ``Assessment -> System -> Organization`` so a caller cannot open a proposal
  against someone else's tenant by naming its id.
* One pathological objective (a provider fault, a malformed response, anything
  ``evaluate_objective`` can raise) must not fail the whole control. Each
  objective's evaluation and write happen inside their own savepoint, so a
  failure there rolls back only that objective's row and the control still
  completes with a rollup drawn from the objectives that did evaluate.
"""

from __future__ import annotations

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...config import get_settings
from ...logging import get_logger
from ...models import Assessment, System
from ...models_assessment_engine import AssessmentControlProposal, AssessmentObjectiveProposal
from ...prep.screen import normalize_control_identifier
from .evaluate import evaluate_objective
from .objectives import objectives_for
from .rollup import roll_up

log = get_logger(__name__)


class ProposalError(RuntimeError):
    """A control proposal could not be opened or evaluated."""


async def open_control_proposal(
    session: AsyncSession, *, assessment_id: int, control_identifier: str
) -> AssessmentControlProposal:
    """Open (or return the existing) proposal for one control in an assessment.

    Idempotent on ``(assessment_id, control_identifier)`` -- the unique
    constraint that backs it. Deliberately takes no ``organization_id``: the
    org is derived from the assessment's own system, never from a caller
    argument, so a caller cannot name someone else's organization.
    """
    row = (
        await session.execute(
            select(System.organization_id, System.id)
            .join(Assessment, Assessment.system_id == System.id)
            .where(Assessment.id == assessment_id)
        )
    ).first()
    if row is None:
        raise ProposalError(f"assessment {assessment_id} not found")
    organization_id, system_id = int(row[0]), int(row[1])

    canonical = normalize_control_identifier(control_identifier)

    existing = (
        await session.execute(
            select(AssessmentControlProposal).where(
                AssessmentControlProposal.assessment_id == assessment_id,
                AssessmentControlProposal.control_identifier == canonical,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing

    proposal = AssessmentControlProposal(
        organization_id=organization_id,
        assessment_id=assessment_id,
        control_identifier=canonical,
    )
    session.add(proposal)
    await session.flush()
    log.info(
        "assessment.control_proposal_opened",
        assessment_id=assessment_id,
        control_identifier=canonical,
        system_id=system_id,
    )
    return proposal


async def evaluate_control_proposal(
    session: AsyncSession, proposal: AssessmentControlProposal
) -> AssessmentControlProposal:
    """Evaluate every objective of one control and roll the verdicts up.

    Reruns cleanly: prior objective proposals for this control are cleared
    before evaluating again, so a rerun does not double the row count.
    """
    settings = get_settings()
    proposal.state = "draft"
    proposal.config_snapshot = {
        "retrieval_limit": settings.assessment_engine_retrieval_limit,
        "max_objectives": settings.assessment_engine_max_objectives_per_control,
    }

    # The session factory runs with autoflush disabled (src/ccf/db.py). A DELETE
    # issued while an AssessmentObjectiveProposal for this control is still
    # pending (added but not yet flushed -- e.g. by a caller sharing this
    # session before calling in) matches nothing, because the bulk DELETE is a
    # Core statement that never sees unflushed ORM state. A later flush --
    # including one of this function's own per-objective flushes below --
    # would then persist that row right past the delete meant to remove it.
    # Flush first so the delete actually finds and removes it. This is the same
    # bug, with the same fix, as src/ccf/prep/classify.py's idempotency delete
    # -- it shipped twice in slice 1. See
    # test_flush_before_delete_removes_a_pending_unflushed_objective_row for a
    # reproduction: it fails if this flush is removed.
    await session.flush()
    await session.execute(
        delete(AssessmentObjectiveProposal).where(
            AssessmentObjectiveProposal.control_proposal_id == proposal.id
        )
    )

    objectives = await objectives_for(session, proposal.control_identifier)
    proposal.objectives_total = len(objectives)

    verdicts: list[str] = []
    for objective in objectives:
        try:
            async with session.begin_nested():
                evaluation = await evaluate_objective(
                    session,
                    org_id=proposal.organization_id,
                    control_identifier=proposal.control_identifier,
                    objective=objective,
                    system_id=None,
                )
                session.add(
                    AssessmentObjectiveProposal(
                        organization_id=proposal.organization_id,
                        control_proposal_id=proposal.id,
                        label=objective.label,
                        objective_text=objective.text,
                        objective_text_sha256=objective.text_sha256,
                        sort_order=objective.sort_order,
                        state="complete",
                        verdict=evaluation.verdict,
                        cited_unit_ids=evaluation.cited_unit_ids,
                        retrieved_unit_ids=evaluation.retrieved_unit_ids,
                        gaps=evaluation.gaps,
                        contradictions=evaluation.contradictions,
                        rationale=evaluation.rationale,
                        model_name=evaluation.model_name,
                        # Deliberate rename: ObjectiveEvaluation.confidence is a
                        # model's output, model_confidence is a column. Map
                        # explicitly rather than renaming either side.
                        model_confidence=evaluation.confidence,
                    )
                )
                await session.flush()
        except Exception as exc:  # any objective fault must leave the control resumable
            # A savepoint isolates this objective's write: the exception unwinds
            # the `async with` above and rolls back only its savepoint, so the
            # objectives already persisted this run -- and the outer proposal
            # row -- are untouched. One pathological objective must not fail
            # the control.
            log.warning(
                "assessment.objective_evaluation_failed",
                control_identifier=proposal.control_identifier,
                label=objective.label,
                error=str(exc),
            )
            session.add(
                AssessmentObjectiveProposal(
                    organization_id=proposal.organization_id,
                    control_proposal_id=proposal.id,
                    label=objective.label,
                    objective_text=objective.text,
                    objective_text_sha256=objective.text_sha256,
                    sort_order=objective.sort_order,
                    state="failed",
                    verdict=None,
                    error=str(exc),
                )
            )
            await session.flush()
            continue
        verdicts.append(evaluation.verdict)

    proposal.objectives_evaluated = len(verdicts)
    rollup = roll_up(verdicts)
    proposal.proposed_finding = rollup.finding
    proposal.rollup_rationale = rollup.rationale
    proposal.state = "complete"
    await session.flush()
    log.info(
        "assessment.control_proposal_evaluated",
        control_identifier=proposal.control_identifier,
        objectives_total=proposal.objectives_total,
        objectives_evaluated=proposal.objectives_evaluated,
        proposed_finding=proposal.proposed_finding,
    )
    return proposal


async def check_staleness(session: AsyncSession, proposal: AssessmentControlProposal) -> bool:
    """Recompute each stored objective's hash against the live catalog.

    A catalog re-ingest can change what a proposal was evaluated against in two
    ways: rewording an objective's text under an unchanged label, or removing
    or renaming a label outright (so a stored row has no live counterpart at
    all). Both make the stored verdict potentially wrong, not the evaluation
    code -- so this only detects and flags either as ``stale``; it does not
    re-evaluate.
    """
    live = await objectives_for(session, proposal.control_identifier)
    live_hashes = {o.label: o.text_sha256 for o in live}

    stored = (
        await session.execute(
            select(AssessmentObjectiveProposal).where(
                AssessmentObjectiveProposal.control_proposal_id == proposal.id
            )
        )
    ).scalars().all()

    # A stored label absent from the live catalog is structural drift in its own
    # right -- a bare rename with unchanged text, or an objective deleted from
    # the catalog outright -- and must count as stale independent of the hash
    # comparison. Requiring `row.label in live_hashes` before comparing hashes
    # would silently pass both cases through as not-stale.
    stale = any(
        row.label not in live_hashes or live_hashes[row.label] != row.objective_text_sha256
        for row in stored
    )
    if stale:
        proposal.state = "stale"
        await session.flush()
        log.info(
            "assessment.control_proposal_stale",
            control_identifier=proposal.control_identifier,
        )
    return stale
