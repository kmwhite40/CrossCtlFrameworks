"""Acceptance's other effect: an accepted other_than_satisfied finding
creates a POA&M, idempotently, without a human triggering it.

``insufficient_evidence`` is not exercised as a "creates none" case here:
``accept_control_proposal`` already refuses to accept an
``insufficient_evidence`` finding at all (``AcceptanceRefused``), so there is
no reachable path where the bridge could even run against one -- it is
untestable via the real acceptance path and asserting it in isolation would
just re-test the guard Task 2 of the calibration-harness slice already
covers.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import delete, select

from ccf.assessment.engine import service
from ccf.assessment.engine.evaluate import ObjectiveEvaluation
from ccf.assessment.engine.service import (
    accept_control_proposal,
    evaluate_control_proposal,
    open_control_proposal,
)
from ccf.db import session_scope
from ccf.ingest.scanners import SEVERITY_SLA_DAYS
from ccf.models import POAM, Assessment, Control, Organization, System
from ccf.models_assessment_engine import AssessmentControlProposal

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = "ZQ-95"


@pytest.fixture(autouse=True)
async def _catalog_rows() -> Any:
    """One addressable control plus one sub-clause objective row -- mirrors
    test_assessment_acceptance.py's fixture shape.
    """
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == _SEQ))
        s.add(
            Control(
                identifier=_SEQ,
                sequence_control=_SEQ,
                control_name="Bridge Fixture Control",
                assessment_objective="Determine if:",
                source_row=1,
            )
        )
        s.add(
            Control(
                identifier=f"{_SEQ}-ao1",
                sequence_control=_SEQ,
                ap_acronym=f"{_SEQ}a",
                assessment_objective="the bridge fixture objective is met;",
                source_row=2,
            )
        )
    yield
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == _SEQ))


async def _assessment(name: str) -> int:
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
        return int(a.id)


def _fake_evaluate(verdict: str) -> Any:
    async def _fake(session: Any, **kwargs: Any) -> ObjectiveEvaluation:
        return ObjectiveEvaluation(verdict=verdict, rationale="ok", confidence=0.5)

    return _fake


async def _accept(
    name: str, monkeypatch: pytest.MonkeyPatch, verdict: str, *, accepted_by: str = "a@x.test"
) -> tuple[int, int]:
    """Open, evaluate, and accept a proposal. Returns (proposal_id, result_id)."""
    monkeypatch.setattr(service, "evaluate_objective", _fake_evaluate(verdict))
    assessment_id = await _assessment(name)
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier=_SEQ
        )
        proposal = await evaluate_control_proposal(s, proposal)
        result = await accept_control_proposal(s, int(proposal.id), accepted_by=accepted_by)
        return int(proposal.id), int(result.id)


async def _poams_for_result(result_id: int) -> list[POAM]:
    async with session_scope() as s:
        rows = (
            await s.execute(
                select(POAM).where(POAM.source_ref == f"assessment_control_result:{result_id}")
            )
        ).scalars().all()
        return list(rows)


async def test_an_accepted_other_than_satisfied_finding_creates_one_poam(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, result_id = await _accept("bridge-ots", monkeypatch, "not_satisfied")
    poams = await _poams_for_result(result_id)
    assert len(poams) == 1
    poam = poams[0]
    assert poam.source == "assessment"
    assert poam.source_ref == f"assessment_control_result:{result_id}"
    assert poam.severity == "moderate"
    assert poam.status == "open"
    assert poam.identified_on is not None
    assert poam.due_on == poam.identified_on + timedelta(days=SEVERITY_SLA_DAYS["moderate"])


async def test_a_satisfied_finding_creates_no_poam(monkeypatch: pytest.MonkeyPatch) -> None:
    _, result_id = await _accept("bridge-satisfied", monkeypatch, "satisfied")
    assert await _poams_for_result(result_id) == []


async def test_a_not_applicable_finding_creates_no_poam(monkeypatch: pytest.MonkeyPatch) -> None:
    _, result_id = await _accept("bridge-na", monkeypatch, "not_applicable")
    assert await _poams_for_result(result_id) == []


async def test_reaccepting_is_idempotent_and_does_not_overwrite_an_edited_poam(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Accepting twice must yield one POA&M -- and a human's edit to it
    between the two acceptances must survive, not merely the count staying
    one. Re-evaluating under a different verdict and re-accepting exercises
    accept_control_proposal's own uq_assess_ctrl upsert path (see
    test_assessment_acceptance.py::test_accepting_twice_does_not_duplicate_the_result_row)
    while the POA&M bridge must stay a no-op the second time.
    """
    monkeypatch.setattr(service, "evaluate_objective", _fake_evaluate("not_satisfied"))
    assessment_id = await _assessment("bridge-idempotent")
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier=_SEQ
        )
        proposal = await evaluate_control_proposal(s, proposal)
        proposal_id = int(proposal.id)
        result = await accept_control_proposal(s, proposal_id, accepted_by="first@x.test")
        result_id = int(result.id)

    poams = await _poams_for_result(result_id)
    assert len(poams) == 1
    poam_id = poams[0].id

    # A human edits the POA&M between the two acceptances.
    async with session_scope() as s:
        poam = (await s.execute(select(POAM).where(POAM.id == poam_id))).scalar_one()
        poam.title = "Edited by a human, must survive re-acceptance"

    # Re-evaluate (still other_than_satisfied via a different verdict word,
    # so this is a genuine second evaluate+accept cycle, not a no-op) and
    # accept again.
    monkeypatch.setattr(service, "evaluate_objective", _fake_evaluate("not_satisfied"))
    async with session_scope() as s:
        proposal = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.id == proposal_id
                )
            )
        ).scalar_one()
        proposal = await evaluate_control_proposal(s, proposal)
        await accept_control_proposal(s, proposal_id, accepted_by="second@x.test")

    poams = await _poams_for_result(result_id)
    assert len(poams) == 1, "re-acceptance must not create a second POA&M"
    assert poams[0].id == poam_id
    assert poams[0].title == "Edited by a human, must survive re-acceptance"


async def test_a_poam_write_failure_does_not_fail_acceptance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Force a real DB-level failure (VARCHAR(512) truncation, not a plain
    Python exception the bridge's own try/except could trivially swallow
    without needing begin_nested) inside the bridge's savepoint, and confirm
    the AssessmentControlResult and the acceptance itself still persist.
    """

    class _OversizedTitlePOAM(service.POAM):  # type: ignore[misc,valid-type]
        def __init__(self, **kwargs: Any) -> None:
            kwargs["title"] = "x" * 600
            super().__init__(**kwargs)

    monkeypatch.setattr(service, "POAM", _OversizedTitlePOAM)
    monkeypatch.setattr(service, "evaluate_objective", _fake_evaluate("not_satisfied"))
    assessment_id = await _assessment("bridge-write-fails")
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier=_SEQ
        )
        proposal = await evaluate_control_proposal(s, proposal)
        proposal_id = int(proposal.id)
        result = await accept_control_proposal(s, proposal_id, accepted_by="a@x.test")
        assert result.finding == "other_than_satisfied"
        result_id = int(result.id)

    async with session_scope() as s:
        proposal = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.id == proposal_id
                )
            )
        ).scalar_one()
        assert proposal.state == "accepted", "the acceptance itself must survive"

    assert await _poams_for_result(result_id) == [], "the failed POA&M write must not persist"
