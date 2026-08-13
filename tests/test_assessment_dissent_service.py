"""Wiring the challenger's output into the evaluate stage:
primary_verdict/challenger_verdict/challenger_rationale/challenger_ai_action_run_id
land on AssessmentObjectiveProposal, dissent_count aggregates on
AssessmentControlProposal, and the whole thing forces the rollup consequence
the design exists to produce -- a contested control that
accept_control_proposal then refuses.
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import delete, select

from ccf.ai_actions.provenance import record_ai_run
from ccf.assessment.engine import service
from ccf.assessment.engine.evaluate import ObjectiveEvaluation
from ccf.assessment.engine.service import (
    AcceptanceRefused,
    accept_control_proposal,
    evaluate_control_proposal,
    open_control_proposal,
)
from ccf.db import session_scope
from ccf.models import Assessment, Control, Organization, System
from ccf.models_assessment_engine import AssessmentControlProposal, AssessmentObjectiveProposal

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = "ZQ-97"


@pytest.fixture(autouse=True)
async def _catalog_rows() -> Any:
    """Two sub-clause objectives -- ...a and ...b -- so a control can carry
    one dissenting and one agreeing objective at once: an asymmetric fixture
    a naive "any dissent forces dissent_count to objectives_total"
    implementation would fail (only one of the two dissents here).
    """
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == _SEQ))
        s.add(
            Control(
                identifier=_SEQ, sequence_control=_SEQ, control_name="Dissent Wiring Fixture",
                assessment_objective="Determine if:", source_row=1,
            )
        )
        s.add(
            Control(
                identifier=f"{_SEQ}-ao1", sequence_control=_SEQ, ap_acronym=f"{_SEQ}a",
                assessment_objective="the first fixture objective is met;", source_row=2,
            )
        )
        s.add(
            Control(
                identifier=f"{_SEQ}-ao2", sequence_control=_SEQ, ap_acronym=f"{_SEQ}b",
                assessment_objective="the second fixture objective is met;", source_row=3,
            )
        )
    yield
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == _SEQ))


async def _assessment(name: str) -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name=f"{name}-sys")
        s.add(system)
        await s.flush()
        a = Assessment(system_id=system.id, name=f"{name}-a", kind="self")
        s.add(a)
        await s.flush()
        return int(org.id), int(a.id)


def _by_label(results: dict[str, ObjectiveEvaluation]) -> Any:
    async def _fake(
        session: Any, *, org_id: int, control_identifier: str, objective: Any,
        system_id: int | None,
    ) -> ObjectiveEvaluation:
        return results[objective.label]

    return _fake


async def _record_run(session: Any, *, org_id: int, label: str, action_key: str) -> int:
    """A real AiActionRun row -- challenger_ai_action_run_id carries a live FK
    to ai_action_runs.id, so a fabricated integer that names no row would
    fail the INSERT below with a ForeignKeyViolationError rather than
    exercising the field mapping this test is meant to check.
    """
    run = await record_ai_run(
        session,
        action_key=action_key,
        entity_type="assessment_objective",
        entity_id=label,
        organization_id=org_id,
        provider="anthropic",
        model="fake-model",
        prompt=f"{action_key} {label}",
        output={"verdict": "satisfied"},
        citations=[],
    )
    assert run is not None
    return int(run.id)


async def _agreeing(session: Any, org_id: int, label: str) -> ObjectiveEvaluation:
    run_id = await _record_run(
        session, org_id=org_id, label=label, action_key="challenge_assessment_objective"
    )
    return ObjectiveEvaluation(
        verdict="satisfied", rationale="primary agrees", confidence=0.9,
        primary_verdict="satisfied",
        challenger_verdict="satisfied", challenger_rationale="challenger agrees too",
        challenger_ai_action_run_id=run_id,
    )


async def _dissenting(session: Any, org_id: int, label: str) -> ObjectiveEvaluation:
    run_id = await _record_run(
        session, org_id=org_id, label=label, action_key="challenge_assessment_objective"
    )
    return ObjectiveEvaluation(
        verdict="insufficient_evidence", rationale="primary said satisfied",
        confidence=0.9, primary_verdict="satisfied",
        challenger_verdict="not_satisfied",
        challenger_rationale="challenger disagrees, with a citation",
        challenger_ai_action_run_id=run_id,
    )


async def _objective_row(proposal_id: int, label: str) -> AssessmentObjectiveProposal:
    async with session_scope() as s:
        return (
            await s.execute(
                select(AssessmentObjectiveProposal).where(
                    AssessmentObjectiveProposal.control_proposal_id == proposal_id,
                    AssessmentObjectiveProposal.label == label,
                )
            )
        ).scalar_one()


async def test_challenger_fields_land_on_the_objective_proposal_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id, assessment_id = await _assessment("dissent-wiring-fields")
    async with session_scope() as s:
        dissenting = await _dissenting(s, org_id, f"{_SEQ}a")
        agreeing = await _agreeing(s, org_id, f"{_SEQ}b")
    dissenting_run_id, agreeing_run_id = (
        dissenting.challenger_ai_action_run_id,
        agreeing.challenger_ai_action_run_id,
    )
    assert dissenting_run_id != agreeing_run_id  # distinct ids catch a transposition

    monkeypatch.setattr(
        service, "evaluate_objective",
        _by_label({f"{_SEQ}a": dissenting, f"{_SEQ}b": agreeing}),
    )
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier=_SEQ
        )
        proposal = await evaluate_control_proposal(s, proposal)
        proposal_id = int(proposal.id)

    # Each field asserted separately and against a value distinct from its
    # sibling fields' values, so a transposition (e.g. rationale written into
    # the wrong column) is caught rather than passing by coincidence.
    dissenting_row = await _objective_row(proposal_id, f"{_SEQ}a")
    assert dissenting_row.verdict == "insufficient_evidence"
    assert dissenting_row.primary_verdict == "satisfied"
    assert dissenting_row.challenger_verdict == "not_satisfied"
    assert dissenting_row.challenger_rationale == "challenger disagrees, with a citation"
    assert dissenting_row.challenger_ai_action_run_id == dissenting_run_id

    agreeing_row = await _objective_row(proposal_id, f"{_SEQ}b")
    assert agreeing_row.verdict == "satisfied"
    assert agreeing_row.primary_verdict == "satisfied"
    assert agreeing_row.challenger_verdict == "satisfied"
    assert agreeing_row.challenger_rationale == "challenger agrees too"
    assert agreeing_row.challenger_ai_action_run_id == agreeing_run_id


async def test_dissent_count_counts_the_dissenting_objective_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Asymmetric fixture: one of the two objectives dissents, the other
    agrees -- dissent_count must land on exactly 1, not 0 (missed it
    entirely) and not 2 (counted the agreeing one too).
    """
    org_id, assessment_id = await _assessment("dissent-wiring-count")
    async with session_scope() as s:
        dissenting = await _dissenting(s, org_id, f"{_SEQ}a")
        agreeing = await _agreeing(s, org_id, f"{_SEQ}b")
    monkeypatch.setattr(
        service, "evaluate_objective",
        _by_label({f"{_SEQ}a": dissenting, f"{_SEQ}b": agreeing}),
    )
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier=_SEQ
        )
        proposal = await evaluate_control_proposal(s, proposal)
        assert proposal.dissent_count == 1


async def test_dissent_count_resets_on_a_clean_reevaluation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """evaluate_control_proposal reruns cleanly (existing behaviour, this
    slice does not change it) -- dissent_count must reset to 0 on a rerun
    that no longer dissents, not carry the prior run's count forward.
    """
    org_id, assessment_id = await _assessment("dissent-wiring-reset")
    async with session_scope() as s:
        dissenting = await _dissenting(s, org_id, f"{_SEQ}a")
        agreeing_b = await _agreeing(s, org_id, f"{_SEQ}b")
    monkeypatch.setattr(
        service, "evaluate_objective",
        _by_label({f"{_SEQ}a": dissenting, f"{_SEQ}b": agreeing_b}),
    )
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier=_SEQ
        )
        proposal = await evaluate_control_proposal(s, proposal)
        assert proposal.dissent_count == 1
        proposal_id = int(proposal.id)

    async with session_scope() as s:
        agreeing_a = await _agreeing(s, org_id, f"{_SEQ}a")
        agreeing_b2 = await _agreeing(s, org_id, f"{_SEQ}b")
    monkeypatch.setattr(
        service, "evaluate_objective",
        _by_label({f"{_SEQ}a": agreeing_a, f"{_SEQ}b": agreeing_b2}),
    )
    async with session_scope() as s:
        proposal = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.id == proposal_id
                )
            )
        ).scalar_one()
        proposal = await evaluate_control_proposal(s, proposal)
        assert proposal.dissent_count == 0, "a clean rerun must not carry the prior dissent forward"


async def test_agreeing_challenge_stays_distinguishable_from_no_challenge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """"Challenged and agreed" (objective ...a) must persist challenger_verdict
    with dissent_count unchanged; a genuinely un-challenged objective (...b,
    no challenger fields set at all on the ObjectiveEvaluation) must leave
    all four dissent columns NULL. If these collapsed into each other, a
    later calibration reading could not tell a reviewed-and-confirmed verdict
    from one nobody ever double-checked.
    """
    org_id, assessment_id = await _assessment("dissent-wiring-distinguish")
    async with session_scope() as s:
        agreeing = await _agreeing(s, org_id, f"{_SEQ}a")
    not_challenged = ObjectiveEvaluation(
        verdict="satisfied", rationale="primary only, no challenge ran", confidence=0.9,
    )
    monkeypatch.setattr(
        service, "evaluate_objective",
        _by_label({f"{_SEQ}a": agreeing, f"{_SEQ}b": not_challenged}),
    )
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier=_SEQ
        )
        proposal = await evaluate_control_proposal(s, proposal)
        assert proposal.dissent_count == 0
        proposal_id = int(proposal.id)

    agreed_row = await _objective_row(proposal_id, f"{_SEQ}a")
    assert agreed_row.challenger_verdict == "satisfied"
    assert agreed_row.primary_verdict == "satisfied"

    unchallenged_row = await _objective_row(proposal_id, f"{_SEQ}b")
    assert unchallenged_row.primary_verdict is None
    assert unchallenged_row.challenger_verdict is None
    assert unchallenged_row.challenger_rationale is None
    assert unchallenged_row.challenger_ai_action_run_id is None


async def test_a_contested_control_rolls_up_to_insufficient_evidence_and_acceptance_refuses_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The end-to-end property the whole slice exists to produce: one
    contested objective, among several agreeing ones, still forces the
    *whole* control to insufficient_evidence (rollup.py's existing
    counts["insufficient_evidence"] branch -- no rollup code change), and
    accept_control_proposal then refuses it. Asserted against this specific
    assessment/control, not a table-wide count.
    """
    org_id, assessment_id = await _assessment("dissent-wiring-rollup")
    async with session_scope() as s:
        dissenting = await _dissenting(s, org_id, f"{_SEQ}a")
        agreeing = await _agreeing(s, org_id, f"{_SEQ}b")
    monkeypatch.setattr(
        service, "evaluate_objective",
        _by_label({f"{_SEQ}a": dissenting, f"{_SEQ}b": agreeing}),
    )
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier=_SEQ
        )
        proposal = await evaluate_control_proposal(s, proposal)
        assert proposal.proposed_finding == "insufficient_evidence", (
            f"control {_SEQ} in assessment {assessment_id} must roll up to "
            "insufficient_evidence with one dissenting objective among two"
        )
        proposal_id = int(proposal.id)

    async with session_scope() as s:
        with pytest.raises(AcceptanceRefused):
            await accept_control_proposal(s, proposal_id, accepted_by="assessor@x.test")
