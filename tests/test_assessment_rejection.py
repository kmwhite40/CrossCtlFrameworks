"""Rejection -- the human gate's other outcome: recording that an assessor
*disagrees* with the engine's proposed finding, without ever letting that
disagreement reach ``AssessmentControlResult`` (and therefore the SAR or an
auto-created POA&M) the way acceptance does.

Mirrors ``tests/test_assessment_acceptance.py``'s fixtures and helpers, with
its own catalog sequence codes (``ZR-90``/``ZR-91``) so the two modules never
collide even if a prior run's teardown were somehow skipped.
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
    RejectionRefused,
    accept_control_proposal,
    evaluate_control_proposal,
    open_control_proposal,
    reject_control_proposal,
)
from ccf.db import session_scope
from ccf.models import Assessment, AssessmentControlResult, Control, Organization, System
from ccf.models_ai_actions import AiActionRun
from ccf.models_assessment_engine import AssessmentControlProposal, AssessmentObjectiveProposal

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = "ZR-90"


@pytest.fixture(autouse=True)
async def _catalog_rows():
    """Seed one addressable control plus three sub-clause objective rows.

    Mirrors test_assessment_acceptance.py's fixture shape exactly, under a
    disjoint sequence code so the two modules cannot collide.
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
                ap_acronym="ZR-90a",
                assessment_objective="personnel to whom the policy is disseminated are defined;",
                source_row=2,
            )
        )
        s.add(
            Control(
                identifier=f"{_SEQ}-ao2",
                sequence_control=_SEQ,
                ap_acronym="ZR-90b",
                assessment_objective="an official to manage the policy is defined;",
                source_row=3,
            )
        )
        s.add(
            Control(
                identifier=f"{_SEQ}-ao3",
                sequence_control=_SEQ,
                ap_acronym="ZR-90c",
                assessment_objective="the review frequency is defined;",
                source_row=4,
            )
        )
    yield
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == _SEQ))


_SEQ2 = "ZR-91"


@pytest.fixture
async def _second_catalog_rows():
    """A second addressable control, for tests that need two proposals in the
    same assessment.
    """
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == _SEQ2))
        s.add(
            Control(
                identifier=_SEQ2,
                sequence_control=_SEQ2,
                control_name="Test Policy And Procedures Two",
                assessment_objective="Determine if:",
                source_row=1,
            )
        )
        s.add(
            Control(
                identifier=f"{_SEQ2}-ao1",
                sequence_control=_SEQ2,
                ap_acronym="ZR-91a",
                assessment_objective="a second control's objective is defined;",
                source_row=2,
            )
        )
    yield
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == _SEQ2))


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


def _fake_evaluate_with_provenance(
    verdict: str = "satisfied", *, null_run_label: str | None = None
):
    """Like ``_fake_evaluate_always``, but calls ``record_ai_run`` for real, the
    same way ``evaluate_objective`` itself does, so run-stamping tests exercise
    a real ``AiActionRun`` FK rather than a fabricated integer.
    """

    async def _fake(
        session: Any, *, objective: Any, org_id: int, **kwargs: Any
    ) -> ObjectiveEvaluation:
        if objective.label == null_run_label:
            return ObjectiveEvaluation(verdict=verdict, rationale="ok", confidence=0.5)
        ai_run = await record_ai_run(
            session,
            action_key="evaluate_assessment_objective",
            entity_type="assessment_objective",
            entity_id=objective.label,
            organization_id=org_id,
            provider="anthropic",
            model="fake-model",
            prompt=f"evaluate {objective.label}",
            output={"verdict": verdict},
            citations=[],
        )
        assert ai_run is not None
        return ObjectiveEvaluation(
            verdict=verdict, rationale="ok", confidence=0.5, ai_action_run_id=ai_run.id
        )

    return _fake


async def _evaluated_proposal(
    name: str, monkeypatch: pytest.MonkeyPatch, verdict: str = "satisfied"
) -> int:
    """Open + evaluate a proposal against the ZR-90 fixture. Returns its id."""
    monkeypatch.setattr(service, "evaluate_objective", _fake_evaluate_always(verdict))
    _, assessment_id = await _assessment(name)
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier="ZR-90"
        )
        proposal = await evaluate_control_proposal(s, proposal)
        return int(proposal.id)


async def _evaluated_proposal_with_runs(
    name: str,
    monkeypatch: pytest.MonkeyPatch,
    verdict: str = "satisfied",
    *,
    control_identifier: str = "ZR-90",
    null_run_label: str | None = None,
) -> int:
    """Like ``_evaluated_proposal``, but every objective's evaluation records a
    real ``AiActionRun`` (unless ``null_run_label`` names one to skip).
    """
    fake = _fake_evaluate_with_provenance(verdict, null_run_label=null_run_label)
    monkeypatch.setattr(service, "evaluate_objective", fake)
    _, assessment_id = await _assessment(name)
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier=control_identifier
        )
        proposal = await evaluate_control_proposal(s, proposal)
        return int(proposal.id)


async def _run_ids_for_proposal(proposal_id: int) -> list[int]:
    """The non-NULL ``ai_action_run_id`` values linked to one proposal's objectives."""
    async with session_scope() as s:
        ids = (
            await s.execute(
                select(AssessmentObjectiveProposal.ai_action_run_id).where(
                    AssessmentObjectiveProposal.control_proposal_id == proposal_id
                )
            )
        ).scalars().all()
    return [i for i in ids if i is not None]


async def _runs(run_ids: list[int]) -> list[AiActionRun]:
    async with session_scope() as s:
        result = await s.execute(select(AiActionRun).where(AiActionRun.id.in_(run_ids)))
        return list(result.scalars())


async def _proposal(proposal_id: int) -> AssessmentControlProposal:
    async with session_scope() as s:
        return (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.id == proposal_id
                )
            )
        ).scalar_one()


async def test_rejection_records_all_four_columns(monkeypatch: pytest.MonkeyPatch) -> None:
    """state, corrected_finding, rejected_by, rejected_at and note, each asserted."""
    proposal_id = await _evaluated_proposal("rej-columns", monkeypatch)
    async with session_scope() as s:
        await reject_control_proposal(
            s,
            proposal_id,
            rejected_by="assessor@example.com",
            corrected_finding="other_than_satisfied",
            note="Evidence shows the policy was never disseminated to staff.",
        )

    proposal = await _proposal(proposal_id)
    assert proposal.state == "rejected"
    assert proposal.corrected_finding == "other_than_satisfied"
    assert proposal.rejected_by == "assessor@example.com"
    assert proposal.rejected_at is not None
    assert proposal.rejection_note == "Evidence shows the policy was never disseminated to staff."


async def test_rejection_writes_no_assessment_control_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The engine's wrong answer must not reach the SAR with a human's name on it.

    Asserts zero rows for THIS test's own (assessment_id, control_id) pair --
    not merely an empty table, which could pass for unrelated reasons (e.g. no
    other test in the suite happened to have written to it yet).
    """
    proposal_id = await _evaluated_proposal("rej-no-result", monkeypatch)
    proposal_before = await _proposal(proposal_id)
    assessment_id = proposal_before.assessment_id
    control_id = proposal_before.control_identifier

    # Prove the table is reachable and not simply empty by construction: write
    # an unrelated result row for a different assessment first.
    async with session_scope() as s:
        _, other_assessment_id = await _assessment("rej-no-result-control")
        s.add(
            AssessmentControlResult(
                assessment_id=other_assessment_id, control_id="unrelated-control"
            )
        )

    async with session_scope() as s:
        await reject_control_proposal(
            s,
            proposal_id,
            rejected_by="assessor@example.com",
            corrected_finding="other_than_satisfied",
            note="Disagree with the engine's satisfied verdict.",
        )

    async with session_scope() as s:
        rows = (
            await s.execute(
                select(AssessmentControlResult).where(
                    AssessmentControlResult.assessment_id == assessment_id,
                    AssessmentControlResult.control_id == control_id,
                )
            )
        ).scalars().all()
    assert rows == []


async def test_rejection_stamps_linked_runs_as_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """disposition == 'rejected', reviewer == rejected_by, decided_at set,
    and mutation_applied still False.
    """
    proposal_id = await _evaluated_proposal_with_runs("rej-run-stamp", monkeypatch)
    run_ids = await _run_ids_for_proposal(proposal_id)
    assert len(run_ids) == 3

    async with session_scope() as s:
        await reject_control_proposal(
            s,
            proposal_id,
            rejected_by="assessor@example.com",
            corrected_finding="not_applicable",
            note="Control does not apply to this system's boundary.",
        )

    runs = await _runs(run_ids)
    assert len(runs) == 3
    for run in runs:
        assert run.disposition == "rejected"
        assert run.reviewer == "assessor@example.com"
        assert run.decided_at is not None
        assert run.mutation_applied is False


async def test_a_note_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty or whitespace-only note raises RejectionRefused."""
    proposal_id = await _evaluated_proposal("rej-empty-note", monkeypatch)
    async with session_scope() as s:
        with pytest.raises(RejectionRefused, match="note"):
            await reject_control_proposal(
                s,
                proposal_id,
                rejected_by="assessor@example.com",
                corrected_finding="other_than_satisfied",
                note="",
            )

    proposal_id_2 = await _evaluated_proposal("rej-blank-note", monkeypatch)
    async with session_scope() as s:
        with pytest.raises(RejectionRefused, match="note"):
            await reject_control_proposal(
                s,
                proposal_id_2,
                rejected_by="assessor@example.com",
                corrected_finding="other_than_satisfied",
                note="   ",
            )


async def test_insufficient_evidence_is_not_a_valid_correction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """raises RejectionRefused -- an assessor asserts what is true."""
    proposal_id = await _evaluated_proposal("rej-insufficient", monkeypatch)
    async with session_scope() as s:
        with pytest.raises(RejectionRefused, match="insufficient_evidence"):
            await reject_control_proposal(
                s,
                proposal_id,
                rejected_by="assessor@example.com",
                corrected_finding="insufficient_evidence",
                note="The engine could not tell either way.",
            )


async def test_an_already_accepted_proposal_cannot_be_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proposal_id = await _evaluated_proposal("rej-already-accepted", monkeypatch)
    async with session_scope() as s:
        await accept_control_proposal(s, proposal_id, accepted_by="first@example.com")

    async with session_scope() as s:
        with pytest.raises(RejectionRefused, match="already accepted"):
            await reject_control_proposal(
                s,
                proposal_id,
                rejected_by="second@example.com",
                corrected_finding="other_than_satisfied",
                note="Too late -- already accepted.",
            )

    proposal = await _proposal(proposal_id)
    assert proposal.state == "accepted"
    assert proposal.rejected_by is None


async def test_an_already_rejected_proposal_cannot_be_rejected_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proposal_id = await _evaluated_proposal("rej-already-rejected", monkeypatch)
    async with session_scope() as s:
        await reject_control_proposal(
            s,
            proposal_id,
            rejected_by="first@example.com",
            corrected_finding="other_than_satisfied",
            note="First rejection.",
        )

    async with session_scope() as s:
        with pytest.raises(RejectionRefused, match="already rejected"):
            await reject_control_proposal(
                s,
                proposal_id,
                rejected_by="second@example.com",
                corrected_finding="not_applicable",
                note="Second attempt should not land.",
            )

    proposal = await _proposal(proposal_id)
    assert proposal.rejected_by == "first@example.com"
    assert proposal.corrected_finding == "other_than_satisfied"
    assert proposal.rejection_note == "First rejection."

    # An already-rejected proposal must not be acceptable either -- the same
    # terminal state, the sibling guard.
    async with session_scope() as s:
        with pytest.raises(AcceptanceRefused):
            await accept_control_proposal(s, proposal_id, accepted_by="second@example.com")


async def test_rejecting_one_proposal_does_not_stamp_another_proposals_runs(
    monkeypatch: pytest.MonkeyPatch, _second_catalog_rows: None
) -> None:
    """Two proposals in one assessment; only the rejected one's runs are stamped."""
    monkeypatch.setattr(service, "evaluate_objective", _fake_evaluate_with_provenance())
    _, assessment_id = await _assessment("rej-cross-proposal")
    async with session_scope() as s:
        proposal_a = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier="ZR-90"
        )
        proposal_a = await evaluate_control_proposal(s, proposal_a)
        proposal_a_id = int(proposal_a.id)

        proposal_b = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier="ZR-91"
        )
        proposal_b = await evaluate_control_proposal(s, proposal_b)
        proposal_b_id = int(proposal_b.id)

    run_ids_a = await _run_ids_for_proposal(proposal_a_id)
    run_ids_b = await _run_ids_for_proposal(proposal_b_id)
    assert len(run_ids_a) == 3
    assert len(run_ids_b) == 1

    async with session_scope() as s:
        await reject_control_proposal(
            s,
            proposal_a_id,
            rejected_by="assessor@example.com",
            corrected_finding="other_than_satisfied",
            note="Only proposal A is rejected here.",
        )

    for run in await _runs(run_ids_a):
        assert run.disposition == "rejected"
        assert run.reviewer == "assessor@example.com"
        assert run.mutation_applied is False

    for run in await _runs(run_ids_b):
        assert run.disposition is None
        assert run.reviewer is None
        assert run.decided_at is None
        assert run.mutation_applied is False


async def test_an_org_a_caller_cannot_reject_an_org_b_proposal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Asserted at the service layer as an attack, matching the acceptance
    tests' ``test_accepting_one_organizations_proposal_does_not_stamp_anothers_run``:
    two organizations, each with its own assessment, proposal, and linked run
    (``_assessment`` creates a fresh ``Organization`` per call, so these are
    unrelated tenants). Rejecting org A's proposal must leave org B's proposal
    and run completely untouched -- cross-tenant stamping would record one
    organization's assessor as having taken a position on another
    organization's finding, an audit-integrity failure.
    """
    proposal_a_id = await _evaluated_proposal_with_runs("rej-org-a", monkeypatch)
    proposal_b_id = await _evaluated_proposal_with_runs("rej-org-b", monkeypatch)

    run_ids_b = await _run_ids_for_proposal(proposal_b_id)
    assert len(run_ids_b) == 3

    async with session_scope() as s:
        await reject_control_proposal(
            s,
            proposal_a_id,
            rejected_by="assessor-a@example.com",
            corrected_finding="other_than_satisfied",
            note="Org A's assessor disagrees with the engine.",
        )

    proposal_b = await _proposal(proposal_b_id)
    assert proposal_b.state == "complete"
    assert proposal_b.rejected_by is None
    assert proposal_b.corrected_finding is None
    assert proposal_b.rejection_note is None

    for run in await _runs(run_ids_b):
        assert run.disposition is None
        assert run.reviewer is None
        assert run.decided_at is None
        assert run.mutation_applied is False
