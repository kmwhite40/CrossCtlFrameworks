"""Control-proposal orchestration -- evaluate a control's objectives, roll up."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import delete, select

from ccf.ai_actions.provenance import record_ai_run
from ccf.assessment.engine import service
from ccf.assessment.engine.evaluate import ObjectiveEvaluation
from ccf.assessment.engine.objectives import Objective, objective_sha256, objectives_for
from ccf.assessment.engine.service import (
    check_staleness,
    evaluate_control_proposal,
    open_control_proposal,
)
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Assessment, AssessmentControlResult, Control, Organization, System
from ccf.models_ai_actions import AiActionRun
from ccf.models_assessment_engine import AssessmentControlProposal, AssessmentObjectiveProposal

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = "ZQ-90"


@pytest.fixture(autouse=True)
async def _catalog_rows():
    """Seed one addressable control plus three sub-clause objective rows.

    Mirrors tests/test_assessment_objectives.py's fixture shape: a parent row
    with a bare "Determine if:" header, and three sub-clause rows carrying the
    actual objective text with control_name NULL.
    """
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == _SEQ))
        s.add(
            Control(
                identifier=_SEQ,
                sequence_control=_SEQ,
                control_name="Test Policy And Procedures",
                assessment_objective="Determine if:",
                source_row=1,
            )
        )
        s.add(
            Control(
                identifier=f"{_SEQ}-ao1",
                sequence_control=_SEQ,
                ap_acronym="ZQ-90a",
                assessment_objective="personnel to whom the policy is disseminated are defined;",
                source_row=2,
            )
        )
        s.add(
            Control(
                identifier=f"{_SEQ}-ao2",
                sequence_control=_SEQ,
                ap_acronym="ZQ-90b",
                assessment_objective="an official to manage the policy is defined;",
                source_row=3,
            )
        )
        s.add(
            Control(
                identifier=f"{_SEQ}-ao3",
                sequence_control=_SEQ,
                ap_acronym="ZQ-90c",
                assessment_objective="the review frequency is defined;",
                source_row=4,
            )
        )
    yield
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == _SEQ))


async def _assessment(name: str) -> tuple[int, int]:
    """Create an org + system + assessment. Returns (org_id, assessment_id)."""
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name=f"{name}-system")
        s.add(system)
        await s.flush()
        assessment = Assessment(system_id=system.id, name=f"{name}-assessment", kind="self")
        s.add(assessment)
        await s.flush()
        return int(org.id), int(assessment.id)


def _fake_evaluate_always(verdict: str = "satisfied"):
    async def _fake(session: Any, **kwargs: Any) -> ObjectiveEvaluation:
        return ObjectiveEvaluation(verdict=verdict, rationale="ok", confidence=0.5)

    return _fake


async def test_open_derives_org_from_the_assessment_not_an_argument() -> None:
    """A caller cannot name someone else's organization."""
    org_id, assessment_id = await _assessment("svc-open-org")
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier="ZQ-90"
        )
        organization_id = proposal.organization_id
    assert organization_id == org_id


async def test_open_is_idempotent_on_assessment_and_control() -> None:
    _, assessment_id = await _assessment("svc-open-idempotent")
    async with session_scope() as s:
        first = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier="ZQ-90"
        )
        first_id = int(first.id)
    async with session_scope() as s:
        second = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier="ZQ-90"
        )
        second_id = int(second.id)
    assert second_id == first_id
    async with session_scope() as s:
        rows = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.assessment_id == assessment_id
                )
            )
        ).scalars().all()
    assert len(rows) == 1


async def test_open_normalizes_the_control_identifier() -> None:
    """open(..., "ZQ-090") and open(..., "ZQ-90") resolve to one proposal."""
    _, assessment_id = await _assessment("svc-open-normalize")
    async with session_scope() as s:
        padded = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier="ZQ-090"
        )
        padded_id = int(padded.id)
    async with session_scope() as s:
        unpadded = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier="ZQ-90"
        )
        unpadded_id = int(unpadded.id)
    assert unpadded_id == padded_id


async def test_evaluate_writes_one_objective_proposal_per_catalog_objective(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(service, "evaluate_objective", _fake_evaluate_always())
    _, assessment_id = await _assessment("svc-eval-count")
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier="ZQ-90"
        )
        proposal = await evaluate_control_proposal(s, proposal)
        proposal_id = int(proposal.id)
        objectives_total = proposal.objectives_total
        objectives_evaluated = proposal.objectives_evaluated

    async with session_scope() as s:
        rows = (
            await s.execute(
                select(AssessmentObjectiveProposal)
                .where(AssessmentObjectiveProposal.control_proposal_id == proposal_id)
                .order_by(AssessmentObjectiveProposal.sort_order)
            )
        ).scalars().all()

    assert [r.label for r in rows] == ["ZQ-90a", "ZQ-90b", "ZQ-90c"]
    assert objectives_total == 3
    assert objectives_evaluated == 3
    # ObjectiveEvaluation.confidence must round-trip onto model_confidence --
    # the deliberate rename in the brief. Read back from the database, not
    # from the in-memory ORM object, so a dropped mapping line is caught.
    assert [r.model_confidence for r in rows] == [0.5, 0.5, 0.5]


async def test_evaluate_rolls_up_and_stores_the_config_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verdict_sequence = iter(["satisfied", "satisfied", "not_satisfied"])

    async def _fake(session: Any, **kwargs: Any) -> ObjectiveEvaluation:
        return ObjectiveEvaluation(verdict=next(verdict_sequence), rationale="ok", confidence=0.5)

    monkeypatch.setattr(service, "evaluate_objective", _fake)
    _, assessment_id = await _assessment("svc-eval-rollup")
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier="ZQ-90"
        )
        proposal = await evaluate_control_proposal(s, proposal)
        proposed_finding = proposal.proposed_finding
        config_snapshot = dict(proposal.config_snapshot)

    settings = get_settings()
    assert proposed_finding == "other_than_satisfied"
    assert config_snapshot["retrieval_limit"] == settings.assessment_engine_retrieval_limit


async def test_one_failing_objective_does_not_fail_the_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A per-objective savepoint: objective 2 raises, 1 and 3 still persist --
    but with one objective unevaluated, the control's finding must be
    insufficient_evidence, never satisfied (CRITICAL 1). Previously this test
    asserted the bug: satisfied with 1 of 3 objectives failed. A rationale
    reading "1 satisfied -- every applicable objective met" while 1/3 of the
    control was never evaluated is exactly the false coverage claim a
    Security Assessment Report cannot carry.
    """

    async def _fake(session: Any, *, objective: Any, **kwargs: Any) -> ObjectiveEvaluation:
        if objective.label == "ZQ-90b":
            raise RuntimeError("provider fault on objective 2")
        return ObjectiveEvaluation(verdict="satisfied", rationale="ok", confidence=0.5)

    monkeypatch.setattr(service, "evaluate_objective", _fake)
    _, assessment_id = await _assessment("svc-eval-partial-fail")
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier="ZQ-90"
        )
        proposal = await evaluate_control_proposal(s, proposal)
        proposal_id = int(proposal.id)
        state = proposal.state
        proposed_finding = proposal.proposed_finding
        objectives_total = proposal.objectives_total
        objectives_evaluated = proposal.objectives_evaluated
        rollup_rationale = proposal.rollup_rationale

    async with session_scope() as s:
        rows = (
            await s.execute(
                select(AssessmentObjectiveProposal)
                .where(AssessmentObjectiveProposal.control_proposal_id == proposal_id)
                .order_by(AssessmentObjectiveProposal.sort_order)
            )
        ).scalars().all()

    by_label = {r.label: r for r in rows}
    assert state == "complete"
    assert objectives_total == 3
    assert objectives_evaluated == 2
    assert proposed_finding == "insufficient_evidence"
    # The rationale must state coverage explicitly -- an assessor reading it
    # alone must be able to tell this was a partial evaluation, not merely
    # infer it from separate objectives_total/objectives_evaluated columns.
    assert "2 of 3 objectives evaluated, 1 failed" in rollup_rationale
    assert by_label["ZQ-90b"].state == "failed"
    assert by_label["ZQ-90b"].error is not None
    assert by_label["ZQ-90b"].verdict is None
    assert by_label["ZQ-90a"].state == "complete"
    assert by_label["ZQ-90c"].state == "complete"


async def test_a_control_with_any_failed_objective_can_never_be_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end proof for CRITICAL 1: partial evaluation cannot reach
    acceptance. This does not merely re-check the rollup policy in isolation
    (test_assessment_rollup.py already does) -- it drives the real
    evaluate_control_proposal -> accept_control_proposal path the way a
    caller actually would, so a future change that reintroduces the bug at
    any point in that path (not just in roll_up itself) fails here too.
    """

    async def _fake(session: Any, *, objective: Any, **kwargs: Any) -> ObjectiveEvaluation:
        if objective.label == "ZQ-90c":
            raise RuntimeError("provider fault on objective 3")
        return ObjectiveEvaluation(verdict="satisfied", rationale="ok", confidence=0.5)

    monkeypatch.setattr(service, "evaluate_objective", _fake)
    _, assessment_id = await _assessment("svc-eval-partial-fail-accept")
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier="ZQ-90"
        )
        proposal = await evaluate_control_proposal(s, proposal)
        proposal_id = int(proposal.id)
        assert proposal.proposed_finding == "insufficient_evidence"

    async with session_scope() as s:
        with pytest.raises(service.AcceptanceRefused):
            await service.accept_control_proposal(s, proposal_id, accepted_by="assessor@test")

    async with session_scope() as s:
        leaked = (
            await s.execute(
                select(AssessmentControlResult).where(
                    AssessmentControlResult.assessment_id == assessment_id
                )
            )
        ).scalar_one_or_none()
        assert leaked is None, (
            "a partially-evaluated control must never reach AssessmentControlResult"
        )


async def test_evaluate_passes_the_assessments_real_system_id_to_evaluate_objective(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """I4: retrieval must be scoped to the assessment's own system, not
    hardcoded None -- an org with two authorization boundaries must not have
    system B's evidence cited in system A's findings.
    """
    seen: dict[str, Any] = {}

    async def _fake(session: Any, **kwargs: Any) -> ObjectiveEvaluation:
        seen["system_id"] = kwargs.get("system_id")
        return ObjectiveEvaluation(verdict="satisfied", rationale="ok", confidence=0.5)

    monkeypatch.setattr(service, "evaluate_objective", _fake)
    async with session_scope() as s:
        org = Organization(name="svc-system-id-passthrough")
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name="svc-system-id-passthrough-system")
        s.add(system)
        await s.flush()
        assessment = Assessment(
            system_id=system.id, name="svc-system-id-passthrough-assessment", kind="self"
        )
        s.add(assessment)
        await s.flush()
        assessment_id, system_id = int(assessment.id), int(system.id)

    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier="ZQ-90"
        )
        await evaluate_control_proposal(s, proposal)

    assert seen["system_id"] == system_id


async def test_evaluate_is_idempotent_on_rerun(monkeypatch: pytest.MonkeyPatch) -> None:
    """Re-running deletes prior objective proposals first -- 3 rows, not 6."""
    monkeypatch.setattr(service, "evaluate_objective", _fake_evaluate_always())
    _, assessment_id = await _assessment("svc-eval-rerun")
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier="ZQ-90"
        )
        proposal = await evaluate_control_proposal(s, proposal)
        proposal = await evaluate_control_proposal(s, proposal)
        proposal_id = int(proposal.id)

    async with session_scope() as s:
        rows = (
            await s.execute(
                select(AssessmentObjectiveProposal).where(
                    AssessmentObjectiveProposal.control_proposal_id == proposal_id
                )
            )
        ).scalars().all()
    assert len(rows) == 3


async def test_flush_before_delete_removes_a_pending_unflushed_objective_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A row added to the session but not yet flushed before evaluation starts
    must not survive the idempotency delete -- proves the flush-before-delete
    ordering is load bearing, not defensive dressing with nothing behind it.

    Without the flush, the bulk DELETE (a Core statement) runs while this row
    is still only pending ORM state and never sees it; the row then survives
    into the DB via a later flush inside the per-objective loop, right next to
    the fresh rows this evaluation writes. Removing the leading
    ``await session.flush()`` in evaluate_control_proposal makes this fail.
    """
    monkeypatch.setattr(service, "evaluate_objective", _fake_evaluate_always())
    _, assessment_id = await _assessment("svc-eval-flush-guard")
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier="ZQ-90"
        )
        s.add(
            AssessmentObjectiveProposal(
                organization_id=proposal.organization_id,
                control_proposal_id=proposal.id,
                label="ZQ-90-stray",
                objective_text="a row pending on the session before evaluation runs",
                objective_text_sha256="c" * 64,
                sort_order=99,
            )
        )
        proposal = await evaluate_control_proposal(s, proposal)
        proposal_id = int(proposal.id)

    async with session_scope() as s:
        rows = (
            await s.execute(
                select(AssessmentObjectiveProposal).where(
                    AssessmentObjectiveProposal.control_proposal_id == proposal_id
                )
            )
        ).scalars().all()
    labels = {r.label for r in rows}
    assert "ZQ-90-stray" not in labels
    assert len(rows) == 3


async def test_a_reworded_objective_marks_the_proposal_stale(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(service, "evaluate_objective", _fake_evaluate_always())
    _, assessment_id = await _assessment("svc-eval-stale")
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier="ZQ-90"
        )
        proposal = await evaluate_control_proposal(s, proposal)
        proposal_id = int(proposal.id)

    async with session_scope() as s:
        control = (
            await s.execute(select(Control).where(Control.identifier == f"{_SEQ}-ao1"))
        ).scalar_one()
        control.assessment_objective = "a completely reworded objective statement;"

    async with session_scope() as s:
        live = await objectives_for(s, "ZQ-90")
        live_hash = next(o.text_sha256 for o in live if o.label == "ZQ-90a")

    async with session_scope() as s:
        stored = (
            await s.execute(
                select(AssessmentObjectiveProposal).where(
                    AssessmentObjectiveProposal.control_proposal_id == proposal_id,
                    AssessmentObjectiveProposal.label == "ZQ-90a",
                )
            )
        ).scalar_one()
        stored_hash = stored.objective_text_sha256

        proposal = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.id == proposal_id
                )
            )
        ).scalar_one()
        is_stale = await check_staleness(s, proposal)
        state = proposal.state

    assert live_hash != stored_hash
    assert is_stale is True
    assert state == "stale"


async def test_an_objective_removed_from_the_catalog_marks_the_proposal_stale(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stored label with no live counterpart at all -- an objective removed
    (or renamed) in the catalog -- must be flagged stale in its own right,
    independent of any hash comparison. check_staleness must not silently pass
    a stored row through just because it has nothing left to compare against.
    """
    monkeypatch.setattr(service, "evaluate_objective", _fake_evaluate_always())
    _, assessment_id = await _assessment("svc-eval-stale-removed")
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier="ZQ-90"
        )
        proposal = await evaluate_control_proposal(s, proposal)
        proposal_id = int(proposal.id)

    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.identifier == f"{_SEQ}-ao1"))

    async with session_scope() as s:
        live = await objectives_for(s, "ZQ-90")
    assert "ZQ-90a" not in {o.label for o in live}

    async with session_scope() as s:
        proposal = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.id == proposal_id
                )
            )
        ).scalar_one()
        is_stale = await check_staleness(s, proposal)
        state = proposal.state

    assert is_stale is True
    assert state == "stale"


async def test_a_failing_recovery_insert_does_not_abort_the_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CRITICAL 3, second half: the failure-recovery insert (the
    AssessmentObjectiveProposal row written when evaluate_objective itself
    raises) must be savepointed too. objectives_for now de-duplicates labels
    upstream (see test_assessment_objectives.py), so this test forces the
    collision directly -- two Objective values sharing a label, bypassing
    objectives_for entirely -- to reach exactly the point this savepoint
    guards, rather than relying on the upstream fix alone. Before this fix,
    the recovery insert ran outside any savepoint, so a colliding recovery
    insert (uq_objective_proposal_label) propagated straight out of
    evaluate_control_proposal and aborted the whole control -- directly
    contradicting the module's own documented guarantee.
    """
    colliding_label = "ZQ-90-collide"

    async def _fake_objectives_for(session: Any, control_identifier: str) -> list[Any]:
        text_a = "first colliding objective;"
        text_b = "second colliding objective;"
        return [
            Objective(
                label=colliding_label,
                text=text_a,
                text_sha256=objective_sha256(text_a),
                sort_order=0,
            ),
            Objective(
                label=colliding_label,
                text=text_b,
                text_sha256=objective_sha256(text_b),
                sort_order=1,
            ),
        ]

    async def _always_raise(session: Any, **kwargs: Any) -> ObjectiveEvaluation:
        raise RuntimeError("provider fault -- forces the recovery path for both objectives")

    monkeypatch.setattr(service, "objectives_for", _fake_objectives_for)
    monkeypatch.setattr(service, "evaluate_objective", _always_raise)
    _, assessment_id = await _assessment("svc-recovery-collision")

    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier="ZQ-90"
        )
        # Must not raise -- proves the second objective's colliding recovery
        # insert does not abort the control.
        proposal = await evaluate_control_proposal(s, proposal)
        proposal_id = int(proposal.id)
        state = proposal.state

    assert state == "complete"

    async with session_scope() as s:
        rows = (
            await s.execute(
                select(AssessmentObjectiveProposal).where(
                    AssessmentObjectiveProposal.control_proposal_id == proposal_id
                )
            )
        ).scalars().all()
    # Only one of the two colliding rows can actually persist -- the point is
    # that the control still completes, not that both survive.
    assert len(rows) == 1
    assert rows[0].label == colliding_label
    assert rows[0].state == "failed"


async def test_the_objective_proposal_links_to_its_run(monkeypatch: pytest.MonkeyPatch) -> None:
    """The stored ai_action_run_id must point at the real AiActionRun
    record_ai_run wrote for this objective -- not merely be non-null. The fake
    evaluate_objective calls record_ai_run itself (as the real one does) so
    this exercises the actual FK, not a fabricated integer.
    """

    async def _fake(
        session: Any, *, objective: Any, org_id: int, **kwargs: Any
    ) -> ObjectiveEvaluation:
        ai_run = await record_ai_run(
            session,
            action_key="evaluate_assessment_objective",
            entity_type="assessment_objective",
            entity_id=objective.label,
            organization_id=org_id,
            provider="anthropic",
            model="fake-model",
            prompt=f"evaluate {objective.label}",
            output={"verdict": "satisfied"},
            citations=[],
        )
        assert ai_run is not None
        return ObjectiveEvaluation(
            verdict="satisfied", rationale="ok", confidence=0.5, ai_action_run_id=ai_run.id
        )

    monkeypatch.setattr(service, "evaluate_objective", _fake)
    _, assessment_id = await _assessment("svc-provenance-link")
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier="ZQ-90"
        )
        proposal = await evaluate_control_proposal(s, proposal)
        proposal_id = int(proposal.id)

    async with session_scope() as s:
        row = (
            await s.execute(
                select(AssessmentObjectiveProposal).where(
                    AssessmentObjectiveProposal.control_proposal_id == proposal_id,
                    AssessmentObjectiveProposal.label == "ZQ-90a",
                )
            )
        ).scalar_one()
        assert row.ai_action_run_id is not None

        ai_run = (
            await s.execute(select(AiActionRun).where(AiActionRun.id == row.ai_action_run_id))
        ).scalar_one()

    assert ai_run.action_key == "evaluate_assessment_objective"
    assert ai_run.entity_type == "assessment_objective"
    assert ai_run.entity_id == "ZQ-90a"


async def test_a_provenance_failure_leaves_the_verdict_intact_with_a_null_run_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """record_ai_run's failure must cost only its own objective its
    ai_action_run_id -- the verdict itself, and every objective evaluated
    before (and after) the failure in the same run, must survive untouched.
    ``ai_action_runs.provider`` is VARCHAR(24); ZQ-90b's fake hands it an
    overlong provider on purpose so record_ai_run's own INSERT fails inside
    its own ``begin_nested()`` savepoint, exercising the real failure path
    rather than simulating it by monkeypatching record_ai_run itself. That is
    exactly the failure this test is built to catch: a regression that
    swapped record_ai_run's savepoint for a bare ``session.rollback()`` would
    unwind to the outermost transaction and take ZQ-90a's already-flushed
    objective proposal down with it, not just ZQ-90b's.
    """

    async def _fake(
        session: Any, *, objective: Any, org_id: int, **kwargs: Any
    ) -> ObjectiveEvaluation:
        provider = "way-too-long-a-provider-name" if objective.label == "ZQ-90b" else "anthropic"
        ai_run = await record_ai_run(
            session,
            action_key="evaluate_assessment_objective",
            entity_type="assessment_objective",
            entity_id=objective.label,
            organization_id=org_id,
            provider=provider,
            model="fake-model",
            prompt=f"evaluate {objective.label}",
            output={"verdict": "satisfied"},
            citations=[],
        )
        return ObjectiveEvaluation(
            verdict="satisfied",
            rationale="ok",
            confidence=0.5,
            ai_action_run_id=ai_run.id if ai_run is not None else None,
        )

    monkeypatch.setattr(service, "evaluate_objective", _fake)
    _, assessment_id = await _assessment("svc-provenance-failure")
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier="ZQ-90"
        )
        proposal = await evaluate_control_proposal(s, proposal)
        proposal_id = int(proposal.id)
        state = proposal.state
        objectives_evaluated = proposal.objectives_evaluated

    async with session_scope() as s:
        rows = (
            await s.execute(
                select(AssessmentObjectiveProposal)
                .where(AssessmentObjectiveProposal.control_proposal_id == proposal_id)
                .order_by(AssessmentObjectiveProposal.sort_order)
            )
        ).scalars().all()

    by_label = {r.label: r for r in rows}
    assert state == "complete"
    # A provenance failure is not an objective failure: all three still count
    # as evaluated, and every verdict is "satisfied" -- unaffected by whether
    # its own provenance write succeeded.
    assert objectives_evaluated == 3
    assert [r.verdict for r in rows] == ["satisfied", "satisfied", "satisfied"]
    assert by_label["ZQ-90b"].ai_action_run_id is None

    # The objective evaluated *before* the failure -- ZQ-90a -- must keep its
    # own real ai_action_run_id: not merely non-null, but pointing at a row
    # that actually exists and belongs to it.
    async with session_scope() as s:
        ai_run_a = (
            await s.execute(
                select(AiActionRun).where(AiActionRun.id == by_label["ZQ-90a"].ai_action_run_id)
            )
        ).scalar_one()
    assert ai_run_a.entity_id == "ZQ-90a"

    # And the objective evaluated *after* the failure -- ZQ-90c -- must be
    # unaffected too: the failing savepoint only ever wraps ZQ-90b's own writes.
    async with session_scope() as s:
        ai_run_c = (
            await s.execute(
                select(AiActionRun).where(AiActionRun.id == by_label["ZQ-90c"].ai_action_run_id)
            )
        ).scalar_one()
    assert ai_run_c.entity_id == "ZQ-90c"
