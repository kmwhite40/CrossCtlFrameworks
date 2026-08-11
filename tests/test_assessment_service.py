"""Control-proposal orchestration -- evaluate a control's objectives, roll up."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import delete, select

from ccf.assessment.engine import service
from ccf.assessment.engine.evaluate import ObjectiveEvaluation
from ccf.assessment.engine.objectives import objectives_for
from ccf.assessment.engine.service import (
    check_staleness,
    evaluate_control_proposal,
    open_control_proposal,
)
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Assessment, Control, Organization, System
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
    """A per-objective savepoint: objective 2 raises, 1 and 3 still persist."""

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
    assert objectives_evaluated == 2
    assert proposed_finding == "satisfied"
    assert by_label["ZQ-90b"].state == "failed"
    assert by_label["ZQ-90b"].error is not None
    assert by_label["ZQ-90b"].verdict is None
    assert by_label["ZQ-90a"].state == "complete"
    assert by_label["ZQ-90c"].state == "complete"


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
