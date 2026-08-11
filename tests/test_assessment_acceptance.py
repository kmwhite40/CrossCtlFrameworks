"""Acceptance -- the human gate that projects a proposal into the existing
``AssessmentControlResult`` shape the SAR generator and POA&M path already read.
"""

from __future__ import annotations

import io
from typing import Any

import pytest
from docx import Document
from sqlalchemy import delete, select

from ccf.assessment.engine import service
from ccf.assessment.engine.evaluate import ObjectiveEvaluation
from ccf.assessment.engine.service import (
    AcceptanceRefused,
    accept_control_proposal,
    check_staleness,
    evaluate_control_proposal,
    open_control_proposal,
)
from ccf.assessment.sar import generate_sar_docx
from ccf.assessment.seed import result_to_dict, summarize_results
from ccf.db import session_scope
from ccf.models import Assessment, AssessmentControlResult, Control, Organization, System
from ccf.models_assessment_engine import AssessmentControlProposal

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = "ZQ-90"


@pytest.fixture(autouse=True)
async def _catalog_rows():
    """Seed one addressable control plus three sub-clause objective rows.

    Mirrors tests/test_assessment_service.py's fixture shape: a parent row with
    a bare "Determine if:" header, and three sub-clause rows carrying the actual
    objective text with control_name NULL.
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


async def _evaluated_proposal(
    name: str, monkeypatch: pytest.MonkeyPatch, verdict: str = "satisfied"
) -> int:
    """Open + evaluate a proposal against the ZQ-90 fixture. Returns its id."""
    monkeypatch.setattr(service, "evaluate_objective", _fake_evaluate_always(verdict))
    _, assessment_id = await _assessment(name)
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier="ZQ-90"
        )
        proposal = await evaluate_control_proposal(s, proposal)
        return int(proposal.id)


def _docx_text(data: bytes) -> str:
    doc = Document(io.BytesIO(data))
    chunks = [p.text for p in doc.paragraphs]
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                chunks.append(cell.text)
    return "\n".join(chunks)


async def test_acceptance_projects_objectives_into_the_existing_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """objective_findings must match what ccf.assessment.sar already renders."""
    proposal_id = await _evaluated_proposal("acc-shape", monkeypatch)
    async with session_scope() as s:
        result = await accept_control_proposal(s, proposal_id, accepted_by="assessor@example.com")
        objective_findings = list(result.objective_findings)

    assert objective_findings == [
        {
            "label": "ZQ-90a",
            "text": "personnel to whom the policy is disseminated are defined;",
            "finding": "satisfied",
        },
        {
            "label": "ZQ-90b",
            "text": "an official to manage the policy is defined;",
            "finding": "satisfied",
        },
        {
            "label": "ZQ-90c",
            "text": "the review frequency is defined;",
            "finding": "satisfied",
        },
    ]


async def test_acceptance_sets_the_control_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    proposal_id = await _evaluated_proposal("acc-finding", monkeypatch, verdict="satisfied")
    async with session_scope() as s:
        proposal = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.id == proposal_id
                )
            )
        ).scalar_one()
        result = await accept_control_proposal(s, proposal_id, accepted_by="assessor@example.com")
        assert result.finding == proposal.proposed_finding == "satisfied"


async def test_acceptance_records_actor_and_timestamp(monkeypatch: pytest.MonkeyPatch) -> None:
    proposal_id = await _evaluated_proposal("acc-actor", monkeypatch)
    async with session_scope() as s:
        await accept_control_proposal(s, proposal_id, accepted_by="assessor@example.com")

    async with session_scope() as s:
        proposal = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.id == proposal_id
                )
            )
        ).scalar_one()
        assert proposal.state == "accepted"
        assert proposal.accepted_by == "assessor@example.com"
        assert proposal.accepted_at is not None


async def test_an_insufficient_evidence_proposal_cannot_be_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """'The engine could not tell' must never become a finding."""
    proposal_id = await _evaluated_proposal(
        "acc-insufficient", monkeypatch, verdict="insufficient_evidence"
    )
    async with session_scope() as s:
        proposal = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.id == proposal_id
                )
            )
        ).scalar_one()
        assert proposal.proposed_finding == "insufficient_evidence"
        assessment_id = proposal.assessment_id
        with pytest.raises(AcceptanceRefused):
            await accept_control_proposal(s, proposal_id, accepted_by="assessor@example.com")

    async with session_scope() as s:
        rows = (
            await s.execute(
                select(AssessmentControlResult).where(
                    AssessmentControlResult.assessment_id == assessment_id
                )
            )
        ).scalars().all()
    assert rows == []


async def test_a_stale_proposal_cannot_be_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    proposal_id = await _evaluated_proposal("acc-stale", monkeypatch)

    async with session_scope() as s:
        control = (
            await s.execute(select(Control).where(Control.identifier == f"{_SEQ}-ao1"))
        ).scalar_one()
        control.assessment_objective = "a completely reworded objective statement;"

    async with session_scope() as s:
        proposal = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.id == proposal_id
                )
            )
        ).scalar_one()
        is_stale = await check_staleness(s, proposal)
        assert is_stale is True

        # Match on wording unique to the stale-specific branch, not merely the
        # "not complete" superset -- "stale" != "complete" would also refuse,
        # so an exact-exception-type check alone cannot tell them apart.
        with pytest.raises(AcceptanceRefused, match="catalog objective text changed"):
            await accept_control_proposal(s, proposal_id, accepted_by="assessor@example.com")


async def test_accepting_an_already_accepted_proposal_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A second immediate accept, with no re-evaluation in between, must still
    be refused. The proposal's ``proposed_finding`` is still set from the
    first evaluation and is not ``insufficient_evidence``, and its state is
    ``"stale"``'s sibling ``"accepted"`` rather than ``"complete"`` -- so only
    the ``state != "complete"`` branch catches this; every other guard passes
    it through. Task 11 wires this path to a POST endpoint a client can call
    twice, so a repeated request must not silently re-accept.
    """
    proposal_id = await _evaluated_proposal("acc-double-immediate", monkeypatch)
    async with session_scope() as s:
        await accept_control_proposal(s, proposal_id, accepted_by="first@example.com")

    async with session_scope() as s:
        with pytest.raises(AcceptanceRefused, match="not complete"):
            await accept_control_proposal(s, proposal_id, accepted_by="second@example.com")


async def test_accepting_twice_does_not_duplicate_the_result_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """uq_assess_ctrl on (assessment_id, control_id) -- second call updates."""
    monkeypatch.setattr(service, "evaluate_objective", _fake_evaluate_always("satisfied"))
    _, assessment_id = await _assessment("acc-twice")
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier="ZQ-90"
        )
        proposal = await evaluate_control_proposal(s, proposal)
        proposal_id = int(proposal.id)
        result = await accept_control_proposal(s, proposal_id, accepted_by="first@example.com")
        assert result.finding == "satisfied"

    # Re-evaluate under a different verdict and accept again -- must update the
    # one existing row, not violate uq_assess_ctrl with a second insert.
    monkeypatch.setattr(service, "evaluate_objective", _fake_evaluate_always("not_satisfied"))
    async with session_scope() as s:
        proposal = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.id == proposal_id
                )
            )
        ).scalar_one()
        proposal = await evaluate_control_proposal(s, proposal)
        result = await accept_control_proposal(s, proposal_id, accepted_by="second@example.com")
        assert result.finding == "other_than_satisfied"

    async with session_scope() as s:
        rows = (
            await s.execute(
                select(AssessmentControlResult).where(
                    AssessmentControlResult.assessment_id == assessment_id
                )
            )
        ).scalars().all()
    assert len(rows) == 1
    assert rows[0].finding == "other_than_satisfied"
    assert rows[0].reviewer == "second@example.com"


async def test_the_generated_sar_renders_the_projected_objectives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The whole point of reusing AssessmentControlResult."""
    proposal_id = await _evaluated_proposal("acc-sar", monkeypatch, verdict="satisfied")
    async with session_scope() as s:
        result = await accept_control_proposal(s, proposal_id, accepted_by="assessor@example.com")
        result_dict = result_to_dict(result)
        summary = summarize_results([result])

    meta = {
        "customer_name": "Acme Corp",
        "system_name": "Acme System",
        "assessment_name": "acc-sar-assessment",
        "kind": "self",
        "assessor": "assessor@example.com",
        "period": "2026-01-01 to ongoing",
        "date": "08/11/2026",
    }
    data = generate_sar_docx(meta, summary, [result_dict])
    text = _docx_text(data)

    assert "ZQ-90a" in text
    assert "personnel to whom the policy is disseminated are defined;" in text
