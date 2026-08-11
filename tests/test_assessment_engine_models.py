"""Assessment-engine proposal tables — round-trip, cascade, and org scoping."""

from __future__ import annotations

import pytest
from sqlalchemy import select, text

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Assessment, Organization, System
from ccf.models_assessment_engine import (
    OBJECTIVE_VERDICTS,
    AssessmentControlProposal,
    AssessmentJob,
    AssessmentObjectiveProposal,
)

pytestmark = pytest.mark.usefixtures("fresh_engine")


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


def test_verdict_vocabulary_is_fixed() -> None:
    assert OBJECTIVE_VERDICTS == (
        "satisfied",
        "not_satisfied",
        "not_applicable",
        "insufficient_evidence",
    )


async def test_control_proposal_defaults_to_draft() -> None:
    org_id, assessment_id = await _assessment("ae-defaults")
    async with session_scope() as s:
        proposal = AssessmentControlProposal(
            organization_id=org_id,
            assessment_id=assessment_id,
            control_identifier="AC-2",
        )
        s.add(proposal)
        await s.flush()
        assert proposal.state == "draft"
        assert proposal.proposed_finding is None
        assert proposal.accepted_at is None


async def test_objective_proposal_records_citations_and_text_hash() -> None:
    org_id, assessment_id = await _assessment("ae-citations")
    async with session_scope() as s:
        control = AssessmentControlProposal(
            organization_id=org_id, assessment_id=assessment_id, control_identifier="AC-2"
        )
        s.add(control)
        await s.flush()
        objective = AssessmentObjectiveProposal(
            organization_id=org_id,
            control_proposal_id=control.id,
            label="AC-02a",
            objective_text="personnel or roles to whom the policy is disseminated are defined;",
            objective_text_sha256="a" * 64,
            verdict="satisfied",
            cited_unit_ids=[11, 12],
            gaps=["no dated review record"],
            contradictions=[],
            rationale="Policy section 3 names the roles.",
            model_confidence=0.81,
        )
        s.add(objective)
        await s.flush()
        assert objective.cited_unit_ids == [11, 12]
        assert objective.gaps == ["no dated review record"]
        assert objective.state == "complete"


async def test_deleting_a_control_proposal_cascades_to_objectives() -> None:
    org_id, assessment_id = await _assessment("ae-cascade")
    async with session_scope() as s:
        control = AssessmentControlProposal(
            organization_id=org_id, assessment_id=assessment_id, control_identifier="CP-9"
        )
        s.add(control)
        await s.flush()
        s.add(
            AssessmentObjectiveProposal(
                organization_id=org_id,
                control_proposal_id=control.id,
                label="CP-09a",
                objective_text="backups are conducted;",
                objective_text_sha256="b" * 64,
                verdict="satisfied",
            )
        )
        await s.flush()
        control_id = int(control.id)

    async with session_scope() as s:
        control = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.id == control_id
                )
            )
        ).scalar_one()
        await s.delete(control)

    async with session_scope() as s:
        remaining = (
            await s.execute(
                select(AssessmentObjectiveProposal).where(
                    AssessmentObjectiveProposal.control_proposal_id == control_id
                )
            )
        ).first()
        assert remaining is None


async def test_assessment_job_defaults() -> None:
    org_id, assessment_id = await _assessment("ae-job")
    async with session_scope() as s:
        control = AssessmentControlProposal(
            organization_id=org_id, assessment_id=assessment_id, control_identifier="AU-2"
        )
        s.add(control)
        await s.flush()
        job = AssessmentJob(organization_id=org_id, control_proposal_id=control.id)
        s.add(job)
        await s.flush()
        assert job.status == "pending"
        assert job.attempts == 0


async def test_server_default_timestamps_are_not_null_in_live_schema() -> None:
    """Slice 1 shipped nullable timestamps the ORM declared non-null. Not again."""
    expected = {
        ("assessment_control_proposals", "created_at"),
        ("assessment_control_proposals", "updated_at"),
        ("assessment_objective_proposals", "created_at"),
        ("assessment_jobs", "created_at"),
        ("assessment_jobs", "updated_at"),
    }
    async with session_scope() as s:
        rows = (
            await s.execute(
                text(
                    "SELECT table_name, column_name, is_nullable "
                    "FROM information_schema.columns "
                    "WHERE table_schema = 'ccf' AND table_name LIKE 'assessment\\_%'"
                )
            )
        ).all()
    nullability = {(t, c): n for t, c, n in rows}
    for key in expected:
        assert nullability.get(key) == "NO", f"{key} must be NOT NULL, got {nullability.get(key)}"


def test_engine_settings_defaults() -> None:
    s = get_settings()
    assert s.assessment_engine_enabled is False
    assert s.assessment_engine_batch_size == 5
    assert s.assessment_engine_max_objectives_per_control == 150
    assert s.assessment_engine_retrieval_limit == 8


def test_default_max_objectives_exceeds_the_real_catalogs_largest_control() -> None:
    """AC-4 is the real catalog's largest control at 98 sub-clause objectives --
    measured by replaying etl/pipeline.py's ingest semantics against
    data/NIST Cross Mappings Rev. 1.1.xlsx on 2026-08-10 (300 control groups,
    p50 10, p90 27, max 98). The old default of 60 sat below that, silently
    making AC-4 -- and six other real controls, including AC-2, the design
    spec's own worked example -- impossible to evaluate. The guard must stay
    comfortably above the observed ceiling, not just above some assumed one.
    """
    measured_real_catalog_max = 98
    assert get_settings().assessment_engine_max_objectives_per_control > measured_real_catalog_max
