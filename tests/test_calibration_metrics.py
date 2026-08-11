"""Calibration metrics -- the two error directions are never conflated."""

from __future__ import annotations

import pytest

from ccf.assessment.engine.calibration import compute_metrics, control_family
from ccf.db import session_scope
from ccf.models import Assessment, Organization, System
from ccf.models_assessment_engine import AssessmentControlProposal

pytestmark = pytest.mark.usefixtures("fresh_engine")


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


async def _decided(
    org_id: int, assessment_id: int, control: str, proposed: str,
    *, accepted: bool, corrected: str | None = None,
) -> None:
    async with session_scope() as s:
        s.add(
            AssessmentControlProposal(
                organization_id=org_id,
                assessment_id=assessment_id,
                control_identifier=control,
                state="accepted" if accepted else "rejected",
                proposed_finding=proposed,
                corrected_finding=corrected,
                rejected_by=None if accepted else "assessor@example.com",
                rejection_note=None if accepted else "wrong",
            )
        )


def test_control_family_folds_padded_and_unpadded() -> None:
    assert control_family("AC-02") == "AC"
    assert control_family("AC-2") == "AC"
    assert control_family("CP-9") == "CP"


def test_control_family_survives_a_cmmc_style_identifier() -> None:
    """Must not corrupt the grouping or raise."""
    assert control_family("AC.L2-3.1.1") == "AC"


async def test_zero_decisions_does_not_divide_by_zero() -> None:
    org_id, _ = await _assessment("cal-empty")
    async with session_scope() as s:
        m = await compute_metrics(s, organization_id=org_id)
    assert m.decided == 0
    assert m.agreement_rate == 0.0


async def test_an_accepted_proposal_counts_as_agreement() -> None:
    org_id, aid = await _assessment("cal-agree")
    await _decided(org_id, aid, "AC-2", "satisfied", accepted=True)
    async with session_scope() as s:
        m = await compute_metrics(s, organization_id=org_id)
    assert m.decided == 1
    assert m.agreed == 1
    assert m.agreement_rate == 1.0
    assert m.missed_findings == 0


async def test_a_control_passing_that_should_not_is_a_missed_finding() -> None:
    """The dangerous direction: proposed satisfied, corrected to other_than_satisfied."""
    org_id, aid = await _assessment("cal-missed")
    await _decided(
        org_id, aid, "AC-2", "satisfied", accepted=False, corrected="other_than_satisfied"
    )
    async with session_scope() as s:
        m = await compute_metrics(s, organization_id=org_id)
    assert m.missed_findings == 1
    assert m.false_alarms == 0
    assert m.agreed == 0


async def test_wasted_remediation_effort_is_a_false_alarm() -> None:
    org_id, aid = await _assessment("cal-false")
    await _decided(
        org_id, aid, "AC-2", "other_than_satisfied", accepted=False, corrected="satisfied"
    )
    async with session_scope() as s:
        m = await compute_metrics(s, organization_id=org_id)
    assert m.false_alarms == 1
    assert m.missed_findings == 0


async def test_the_two_error_directions_are_never_conflated() -> None:
    """One of each must not collapse into a single '2 errors' figure."""
    org_id, aid = await _assessment("cal-both")
    await _decided(
        org_id, aid, "AC-2", "satisfied", accepted=False, corrected="other_than_satisfied"
    )
    await _decided(
        org_id, aid, "SC-7", "other_than_satisfied", accepted=False, corrected="satisfied"
    )
    async with session_scope() as s:
        m = await compute_metrics(s, organization_id=org_id)
    assert m.missed_findings == 1
    assert m.false_alarms == 1
    assert m.decided == 2
    assert m.agreed == 0


async def test_a_correction_to_not_applicable_is_neither_direction() -> None:
    org_id, aid = await _assessment("cal-other")
    await _decided(
        org_id, aid, "AC-2", "satisfied", accepted=False, corrected="not_applicable"
    )
    async with session_scope() as s:
        m = await compute_metrics(s, organization_id=org_id)
    assert m.other_disagreements == 1
    assert m.missed_findings == 0
    assert m.false_alarms == 0


async def test_per_family_split_separates_a_weak_family_from_a_strong_one() -> None:
    """A model reliable on AC and unreliable on SC is a different problem
    from one uniformly mediocre -- the split is what tells them apart."""
    org_id, aid = await _assessment("cal-family")
    await _decided(org_id, aid, "AC-2", "satisfied", accepted=True)
    await _decided(org_id, aid, "AC-3", "satisfied", accepted=True)
    await _decided(
        org_id, aid, "SC-7", "satisfied", accepted=False, corrected="other_than_satisfied"
    )
    async with session_scope() as s:
        m = await compute_metrics(s, organization_id=org_id)
    assert m.by_family["AC"].agreed == 2
    assert m.by_family["AC"].missed_findings == 0
    assert m.by_family["SC"].missed_findings == 1
    assert m.by_family["SC"].agreed == 0


async def test_undecided_proposals_are_excluded() -> None:
    """A draft or complete proposal is not a decision and must not dilute the rate."""
    org_id, aid = await _assessment("cal-undecided")
    async with session_scope() as s:
        s.add(
            AssessmentControlProposal(
                organization_id=org_id, assessment_id=aid,
                control_identifier="AC-2", state="complete", proposed_finding="satisfied",
            )
        )
    async with session_scope() as s:
        m = await compute_metrics(s, organization_id=org_id)
    assert m.decided == 0


async def test_metrics_are_scoped_to_one_organization() -> None:
    org_a, aid_a = await _assessment("cal-org-a")
    org_b, aid_b = await _assessment("cal-org-b")
    await _decided(org_a, aid_a, "AC-2", "satisfied", accepted=True)
    await _decided(
        org_b, aid_b, "AC-2", "satisfied", accepted=False, corrected="other_than_satisfied"
    )
    async with session_scope() as s:
        m = await compute_metrics(s, organization_id=org_a)
    assert m.decided == 1
    assert m.missed_findings == 0, "org B's rejection must not appear in org A's metrics"
