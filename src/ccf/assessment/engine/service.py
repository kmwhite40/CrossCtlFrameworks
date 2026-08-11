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

from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ...config import get_settings
from ...ingest.scanners import SEVERITY_SLA_DAYS
from ...logging import get_logger
from ...models import POAM, Assessment, AssessmentControlResult, System
from ...models_ai_actions import AiActionRun
from ...models_assessment_engine import (
    CORRECTED_FINDINGS,
    AssessmentControlProposal,
    AssessmentObjectiveProposal,
)
from ...prep.screen import normalize_control_identifier
from .evaluate import evaluate_objective
from .objectives import objectives_for
from .rollup import roll_up

log = get_logger(__name__)


class ProposalError(RuntimeError):
    """A control proposal could not be opened or evaluated."""


class AcceptanceRefused(ProposalError):  # noqa: N818 -- interface name fixed by the task brief
    """A proposal exists but is not fit to be accepted as a control finding.

    Three conditions refuse acceptance, all enforced here rather than in the
    schema: the proposal is not ``complete`` (a draft or a failed run), the
    proposal is ``stale`` (the catalog objective text moved under the stored
    verdict), or the rollup could not settle on a real finding at all
    (``insufficient_evidence`` -- the engine could not tell, which is not the
    same thing as the control failing, and writing it as a finding would
    manufacture a POA&M out of missing evidence).
    """


class RejectionRefused(ProposalError):  # noqa: N818 -- sibling of AcceptanceRefused, same reasoning
    """A proposal exists but is not fit to be rejected as an assessor correction.

    Four conditions refuse rejection, all enforced here rather than in the
    schema: the proposal is already ``accepted`` (a human already signed off on
    it -- a rejection cannot retroactively undo that), the proposal is already
    ``rejected`` (no re-rejecting a terminal state), ``corrected_finding`` is
    ``insufficient_evidence`` (that is a proposal-only state meaning the engine
    could not tell; an assessor correcting a verdict is asserting what is
    *true*, not declining to say), or ``note`` is blank (a rejection without a
    reason tells calibration the engine was wrong but not how, and "how" is
    what makes the metric actionable).
    """


async def open_control_proposal(
    session: AsyncSession, *, assessment_id: int, control_identifier: str
) -> AssessmentControlProposal:
    """Open (or return the existing) first-pass proposal for one control in an
    assessment.

    Idempotent on ``(assessment_id, control_identifier)`` for first-pass
    proposals -- the ``uq_control_proposal_first_pass`` partial unique index
    that backs it (``source_poam_id IS NULL``). Deliberately takes no
    ``organization_id``: the org is derived from the assessment's own
    system, never from a caller argument, so a caller cannot name someone
    else's organization.

    Filters ``source_poam_id IS NULL`` explicitly: a closure-triggered
    re-evaluation proposal for this same ``(assessment_id,
    control_identifier)`` pair may already coexist with the first-pass row,
    and an unfiltered lookup would find both and raise
    ``MultipleResultsFound`` from ``scalar_one_or_none``.
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
                AssessmentControlProposal.source_poam_id.is_(None),
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


async def open_reevaluation_proposal(
    session: AsyncSession, *, result: AssessmentControlResult, source_poam_id: int
) -> AssessmentControlProposal:
    """Open (or return the existing) re-evaluation proposal for a remediated control.

    Idempotent on ``source_poam_id`` (``uq_control_proposal_source_poam``,
    migration 0058) -- closing the same POA&M twice returns the same
    proposal rather than violating that index with a second insert.
    Deliberately does not call :func:`open_control_proposal`: that
    function's own idempotency (``uq_control_proposal_first_pass``) is now
    scoped to ``source_poam_id IS NULL`` rows only, precisely so a fresh row
    here for the same ``(assessment_id, control_identifier)`` does not
    collide with the already-accepted first-pass proposal still sitting on
    that pair.
    """
    existing = (
        await session.execute(
            select(AssessmentControlProposal).where(
                AssessmentControlProposal.source_poam_id == source_poam_id
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing

    row = (
        await session.execute(
            select(System.organization_id, System.id)
            .join(Assessment, Assessment.system_id == System.id)
            .where(Assessment.id == result.assessment_id)
        )
    ).first()
    if row is None:
        raise ProposalError(f"assessment {result.assessment_id} not found")
    organization_id = int(row[0])

    canonical = normalize_control_identifier(result.control_id)
    proposal = AssessmentControlProposal(
        organization_id=organization_id,
        assessment_id=result.assessment_id,
        control_identifier=canonical,
        source_poam_id=source_poam_id,
    )
    session.add(proposal)
    await session.flush()
    log.info(
        "assessment.reevaluation_proposal_opened",
        assessment_id=result.assessment_id,
        control_identifier=canonical,
        source_poam_id=source_poam_id,
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

    system_id = (
        await session.execute(
            select(Assessment.system_id).where(Assessment.id == proposal.assessment_id)
        )
    ).scalar_one_or_none()

    verdicts: list[str] = []
    failed_count = 0
    for objective in objectives:
        try:
            async with session.begin_nested():
                evaluation = await evaluate_objective(
                    session,
                    org_id=proposal.organization_id,
                    control_identifier=proposal.control_identifier,
                    objective=objective,
                    system_id=system_id,
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
                        # Set inside this same per-objective savepoint:
                        # evaluate_objective already recorded (or, on a
                        # provenance failure, tried and got None back for) the
                        # AI run before returning here, so this is a plain
                        # field assignment, not a second provenance attempt.
                        ai_action_run_id=evaluation.ai_action_run_id,
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
            failed_count += 1
            try:
                # The recovery insert gets its own savepoint too: it can fail
                # for the same reasons the primary insert can (most notably a
                # colliding `label` -- confirmed live on AC-1, which carries
                # two sub-clause rows under the same ap_acronym, "AC-01a"; see
                # objectives_for's own de-duplication, which closes that
                # specific case, but this savepoint is what stops *any*
                # failure here -- that one included, and whatever else might
                # violate a constraint on this row -- from propagating out of
                # evaluate_control_proposal and aborting the whole control.
                # Without it, the previous `session.add` + `flush()` ran
                # outside any savepoint, so a colliding recovery insert raised
                # straight out of this function, directly contradicting the
                # module docstring's promise that one pathological objective
                # cannot fail the whole control.
                async with session.begin_nested():
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
            except Exception as recovery_exc:
                log.error(
                    "assessment.objective_recovery_failed",
                    control_identifier=proposal.control_identifier,
                    label=objective.label,
                    error=str(recovery_exc),
                )
            continue
        verdicts.append(evaluation.verdict)

    proposal.objectives_evaluated = len(verdicts)
    rollup = roll_up(verdicts, failed=failed_count)
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


async def _ensure_poam_for_other_than_satisfied(
    session: AsyncSession,
    *,
    proposal: AssessmentControlProposal,
    result: AssessmentControlResult,
) -> None:
    """Create a POA&M for an accepted other_than_satisfied finding, idempotently.

    Only ``other_than_satisfied`` creates one. ``satisfied``, ``not_applicable``
    and (unreachable here -- acceptance already refuses it) ``insufficient_evidence``
    do not: manufacturing tracked remediation work out of the engine's own
    uncertainty would be worse than not creating anything.

    Idempotent on ``source_ref = f"assessment_control_result:{result.id}"``,
    not on title -- ``ui.py``'s inline duplicate dedupes on title alone and
    would collide across two systems assessing the same control. An existing
    POA&M with that source_ref is found and left alone: re-accepting a
    proposal (the result row upserts) must not silently overwrite a POA&M a
    human has since edited, assigned, or partially remediated.

    Runs in its own savepoint and never raises: acceptance writes the
    authoritative AssessmentControlResult, and losing the derived POA&M is
    recoverable while discarding a human's accepted finding because a
    derived row would not insert is not. AsyncSession.rollback() is NOT
    savepoint-scoped -- it would unwind this whole accept_control_proposal
    call, which is exactly the trap slice 3 hit with record_ai_run. This
    uses begin_nested() instead, which rolls back only this savepoint on
    failure and leaves the surrounding acceptance intact.
    """
    if result.finding != "other_than_satisfied":
        return
    source_ref = f"assessment_control_result:{result.id}"
    try:
        async with session.begin_nested():
            existing = (
                await session.execute(select(POAM.id).where(POAM.source_ref == source_ref))
            ).scalar_one_or_none()
            if existing is not None:
                return
            system_id = (
                await session.execute(
                    select(Assessment.system_id).where(Assessment.id == proposal.assessment_id)
                )
            ).scalar_one()
            severity = "moderate"
            today = datetime.now(UTC).date()
            due_on = today + timedelta(days=SEVERITY_SLA_DAYS.get(severity, 90))
            session.add(
                POAM(
                    system_id=system_id,
                    title=f"{proposal.control_identifier} — other than satisfied",
                    weakness=(
                        proposal.rollup_rationale
                        or f"{proposal.control_identifier} assessed other than satisfied."
                    ),
                    severity=severity,
                    status="open",
                    identified_on=today,
                    due_on=due_on,
                    original_due_on=due_on,
                    source="assessment",
                    source_ref=source_ref,
                )
            )
            await session.flush()
    except Exception as exc:  # a derived-row failure must not cost the acceptance
        log.warning(
            "assessment.poam_bridge_failed",
            proposal_id=proposal.id,
            result_id=result.id,
            error=str(exc),
        )


async def accept_control_proposal(
    session: AsyncSession, proposal_id: int, *, accepted_by: str
) -> AssessmentControlResult:
    """The human gate: project an accepted proposal into ``AssessmentControlResult``.

    This is the only path by which engine output reaches the existing SAR
    generator or an auto-created POA&M -- both read ``AssessmentControlResult``,
    not the proposal tables. Upserts on ``(assessment_id, control_id)`` (the
    ``uq_assess_ctrl`` constraint on that table), so accepting a re-evaluated
    proposal a second time updates the one existing row rather than violating
    the constraint with a duplicate.

    Refuses -- raising :class:`AcceptanceRefused` and writing nothing -- when
    the proposal is stale, is not ``complete``, or settled on
    ``insufficient_evidence``. All three checks are application code; nothing
    in the schema stops a bad write on its own.
    """
    proposal = (
        await session.execute(
            select(AssessmentControlProposal).where(AssessmentControlProposal.id == proposal_id)
        )
    ).scalar_one_or_none()
    if proposal is None:
        raise ProposalError(f"control proposal {proposal_id} not found")

    # Recompute staleness here rather than trusting whatever state the
    # proposal already carries: check_staleness was previously only ever
    # called by tests, never by production code, so a catalog re-ingest that
    # reworded an objective under an already-``complete`` proposal was never
    # actually detected before acceptance -- the guard below existed but was
    # unreachable in practice. This call is what makes it reachable; the
    # state check immediately after is unchanged and still does the refusing.
    await check_staleness(session, proposal)

    if proposal.state == "stale":
        raise AcceptanceRefused(
            f"control proposal {proposal_id} is stale -- the catalog objective text "
            "changed since evaluation; re-evaluate before accepting"
        )
    if proposal.state != "complete":
        raise AcceptanceRefused(
            f"control proposal {proposal_id} is {proposal.state!r}, not complete"
        )
    proposed_finding = proposal.proposed_finding
    if proposed_finding is None:
        raise AcceptanceRefused(f"control proposal {proposal_id} has no proposed finding")
    if proposed_finding == "insufficient_evidence":
        raise AcceptanceRefused(
            f"control proposal {proposal_id} settled on insufficient_evidence -- "
            "the engine could not tell, which is not an acceptable finding"
        )

    objectives = (
        (
            await session.execute(
                select(AssessmentObjectiveProposal)
                .where(AssessmentObjectiveProposal.control_proposal_id == proposal.id)
                .order_by(AssessmentObjectiveProposal.sort_order)
            )
        )
        .scalars()
        .all()
    )

    # autoflush is disabled on this session factory (src/ccf/db.py). A newly
    # added result row would not be visible to the select below without an
    # explicit flush first -- but there is nothing pending here to flush past;
    # this call exists so the select below sees any proposal/objective writes
    # already made on this session before this function ran.
    await session.flush()
    result = (
        await session.execute(
            select(AssessmentControlResult).where(
                AssessmentControlResult.assessment_id == proposal.assessment_id,
                AssessmentControlResult.control_id == proposal.control_identifier,
            )
        )
    ).scalar_one_or_none()
    if result is None:
        result = AssessmentControlResult(
            assessment_id=proposal.assessment_id,
            control_id=proposal.control_identifier,
        )
        session.add(result)

    result.objective_findings = [
        {"label": o.label, "text": o.objective_text, "finding": o.verdict or "not_assessed"}
        for o in objectives
    ]
    result.finding = proposed_finding
    result.nist_id = proposal.control_identifier
    result.assessor_note = proposal.rollup_rationale
    result.reviewed = True
    result.reviewer = accepted_by

    now = datetime.now(UTC)
    proposal.state = "accepted"
    proposal.accepted_by = accepted_by
    proposal.accepted_at = now

    # Stamp every AiActionRun linked to this control's objectives: before
    # acceptance nothing authoritative has been written from a run's output,
    # so mutation_applied=True is truthful only from this point on -- Task 1
    # recorded it False for exactly that reason. `objectives` was already
    # loaded above (and is unaffected by the flush right before it, which
    # exists for the `result` select's benefit, not this one), so its
    # ai_action_run_id values are read straight off the ORM rows rather than
    # re-queried. A NULL id -- a provenance-recording failure on that one
    # objective -- is skipped, not an error: the audit gap must not block the
    # assessment itself. One bulk UPDATE covers every linked run regardless of
    # objective count, rather than one round trip per row.
    run_ids = {o.ai_action_run_id for o in objectives if o.ai_action_run_id is not None}
    if run_ids:
        await session.execute(
            update(AiActionRun)
            .where(AiActionRun.id.in_(run_ids))
            .values(
                reviewer=accepted_by,
                disposition="accepted",
                decided_at=now,
                mutation_applied=True,
            )
        )

    await session.flush()
    await _ensure_poam_for_other_than_satisfied(session, proposal=proposal, result=result)
    log.info(
        "assessment.control_proposal_accepted",
        assessment_id=proposal.assessment_id,
        control_identifier=proposal.control_identifier,
        accepted_by=accepted_by,
    )
    return result


async def reject_control_proposal(
    session: AsyncSession,
    proposal_id: int,
    *,
    rejected_by: str,
    corrected_finding: str,
    note: str,
) -> AssessmentControlProposal:
    """The human gate's other outcome: record that an assessor disagrees.

    Unlike acceptance, this never writes an ``AssessmentControlResult`` --
    the engine's wrong answer must not reach the SAR or an auto-created POA&M
    with a human's name attached. It only stamps the proposal itself with the
    assessor's corrected finding and reason, and mirrors acceptance's
    ``AiActionRun`` stamping so the audit trail records disagreement as
    faithfully as it records agreement -- except ``mutation_applied`` stays
    ``False``, because nothing authoritative was written.

    Refuses -- raising :class:`RejectionRefused` and writing nothing -- when
    the proposal is already ``accepted`` or already ``rejected`` (terminal
    states, neither re-enterable), when ``corrected_finding`` is
    ``insufficient_evidence`` (proposal-only; an assessor asserts what is
    true), or when ``note`` is blank. All four checks are application code;
    nothing in the schema stops a bad write on its own.
    """
    proposal = (
        await session.execute(
            select(AssessmentControlProposal).where(AssessmentControlProposal.id == proposal_id)
        )
    ).scalar_one_or_none()
    if proposal is None:
        raise ProposalError(f"control proposal {proposal_id} not found")

    if proposal.state == "accepted":
        raise RejectionRefused(
            f"control proposal {proposal_id} is already accepted and cannot be rejected"
        )
    if proposal.state == "rejected":
        raise RejectionRefused(f"control proposal {proposal_id} is already rejected")

    if corrected_finding not in CORRECTED_FINDINGS:
        raise RejectionRefused(
            f"corrected_finding {corrected_finding!r} is not a valid correction -- "
            f"must be one of {CORRECTED_FINDINGS}; insufficient_evidence is proposal-only "
            "and cannot be asserted as a correction"
        )
    if not note or not note.strip():
        raise RejectionRefused(
            f"control proposal {proposal_id} cannot be rejected without a note explaining why"
        )

    objectives = (
        (
            await session.execute(
                select(AssessmentObjectiveProposal).where(
                    AssessmentObjectiveProposal.control_proposal_id == proposal.id
                )
            )
        )
        .scalars()
        .all()
    )

    now = datetime.now(UTC)
    proposal.state = "rejected"
    proposal.corrected_finding = corrected_finding
    proposal.rejected_by = rejected_by
    proposal.rejected_at = now
    proposal.rejection_note = note

    # Mirrors accept_control_proposal's run-stamping exactly, except
    # mutation_applied is omitted from the values() below -- it stays at its
    # existing value (False, per Task 1) because nothing authoritative was
    # written here. See that function's own comment for why a NULL run id is
    # skipped, not an error, and why one bulk UPDATE covers every linked run.
    run_ids = {o.ai_action_run_id for o in objectives if o.ai_action_run_id is not None}
    if run_ids:
        await session.execute(
            update(AiActionRun)
            .where(AiActionRun.id.in_(run_ids))
            .values(
                reviewer=rejected_by,
                disposition="rejected",
                decided_at=now,
            )
        )

    await session.flush()
    log.info(
        "assessment.control_proposal_rejected",
        assessment_id=proposal.assessment_id,
        control_identifier=proposal.control_identifier,
        rejected_by=rejected_by,
        corrected_finding=corrected_finding,
    )
    return proposal
