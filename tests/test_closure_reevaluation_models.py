"""``source_poam_id`` and the constraint change that lets a re-evaluation
proposal coexist with the first-pass proposal it re-evaluates.

The old ``uq_control_proposal_assessment_control`` constraint was a flat
unique index on ``(assessment_id, control_identifier)`` -- exactly the pair a
closure-triggered re-evaluation needs a *second* row for, alongside the
already-accepted first-pass row still sitting on that same pair. Replaced by
two partial unique indexes: first-pass idempotency now applies only to rows
with ``source_poam_id IS NULL``, and a second index caps re-evaluation at one
proposal per POA&M.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from ccf.assessment.engine.service import open_control_proposal
from ccf.db import session_scope
from ccf.models import POAM, Assessment, Organization, System
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


async def _poam_for(assessment_id: int) -> int:
    async with session_scope() as s:
        system_id = (
            await s.execute(select(Assessment.system_id).where(Assessment.id == assessment_id))
        ).scalar_one()
        poam = POAM(
            system_id=system_id,
            title="closure-reevaluation fixture",
            severity="moderate",
            status="open",
            source="assessment",
        )
        s.add(poam)
        await s.flush()
        return int(poam.id)


async def test_source_poam_id_defaults_to_null() -> None:
    org_id, assessment_id = await _assessment("close-defaults")
    async with session_scope() as s:
        p = AssessmentControlProposal(
            organization_id=org_id, assessment_id=assessment_id, control_identifier="AC-2"
        )
        s.add(p)
        await s.flush()
        assert p.source_poam_id is None


async def test_source_poam_id_round_trips() -> None:
    org_id, assessment_id = await _assessment("close-roundtrip")
    poam_id = await _poam_for(assessment_id)
    async with session_scope() as s:
        p = AssessmentControlProposal(
            organization_id=org_id,
            assessment_id=assessment_id,
            control_identifier="AC-2",
            source_poam_id=poam_id,
        )
        s.add(p)
        await s.flush()
        pid = int(p.id)
    async with session_scope() as s:
        p = (
            await s.execute(
                select(AssessmentControlProposal).where(AssessmentControlProposal.id == pid)
            )
        ).scalar_one()
        assert p.source_poam_id == poam_id


async def test_two_first_pass_proposals_for_the_same_control_still_collide() -> None:
    """uq_control_proposal_first_pass -- what the flat constraint used to
    enforce directly -- still blocks two source_poam_id-NULL rows for the
    same (assessment_id, control_identifier). First-pass idempotency must
    survive the constraint swap unchanged.
    """
    org_id, assessment_id = await _assessment("close-first-pass-collide")
    async with session_scope() as s:
        s.add(
            AssessmentControlProposal(
                organization_id=org_id, assessment_id=assessment_id, control_identifier="AC-2"
            )
        )
        await s.flush()
    with pytest.raises(IntegrityError):
        async with session_scope() as s:
            s.add(
                AssessmentControlProposal(
                    organization_id=org_id, assessment_id=assessment_id, control_identifier="AC-2"
                )
            )
            await s.flush()


async def test_a_reevaluation_proposal_coexists_with_the_first_pass_row() -> None:
    """The whole point of the constraint swap: a second row for the same
    (assessment_id, control_identifier), distinguished only by carrying a
    source_poam_id, must be insertable alongside the first-pass row.
    """
    org_id, assessment_id = await _assessment("close-coexist")
    poam_id = await _poam_for(assessment_id)
    async with session_scope() as s:
        s.add(
            AssessmentControlProposal(
                organization_id=org_id, assessment_id=assessment_id, control_identifier="AC-2"
            )
        )
        s.add(
            AssessmentControlProposal(
                organization_id=org_id,
                assessment_id=assessment_id,
                control_identifier="AC-2",
                source_poam_id=poam_id,
            )
        )
        await s.flush()  # must not raise
    async with session_scope() as s:
        rows = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.assessment_id == assessment_id
                )
            )
        ).scalars().all()
    assert len(rows) == 2


async def test_only_one_proposal_per_source_poam_id() -> None:
    """uq_control_proposal_source_poam. Uses two *different* control
    identifiers (AC-2, AC-3) sharing the same source_poam_id, so a failure
    here can only be the source_poam_id index firing -- not a coincidental
    collision with uq_control_proposal_first_pass, which these two rows
    don't otherwise share.
    """
    org_id, assessment_id = await _assessment("close-one-per-poam")
    poam_id = await _poam_for(assessment_id)
    async with session_scope() as s:
        s.add(
            AssessmentControlProposal(
                organization_id=org_id,
                assessment_id=assessment_id,
                control_identifier="AC-2",
                source_poam_id=poam_id,
            )
        )
        await s.flush()
    with pytest.raises(IntegrityError):
        async with session_scope() as s:
            s.add(
                AssessmentControlProposal(
                    organization_id=org_id,
                    assessment_id=assessment_id,
                    control_identifier="AC-3",
                    source_poam_id=poam_id,
                )
            )
            await s.flush()


async def test_the_old_flat_unique_constraint_is_gone() -> None:
    async with session_scope() as s:
        row = (
            await s.execute(
                text(
                    "SELECT conname FROM pg_constraint "
                    "WHERE conname = 'uq_control_proposal_assessment_control'"
                )
            )
        ).scalar_one_or_none()
    assert row is None


async def test_open_control_proposal_returns_the_first_pass_row_not_both() -> None:
    """The consequence of the constraint swap, on the read side.

    Once a re-evaluation row coexists with a first-pass row for the same
    (assessment_id, control_identifier), an unfiltered lookup finds two and
    ``scalar_one_or_none`` raises ``MultipleResultsFound``. The schema tests
    above all passed with that filter deleted -- this is the one that does
    not, so the filter is not left as an untested comment.

    The re-evaluation row is given a distinct state so the assertion pins
    *which* row came back rather than merely that one did.
    """
    org_id, assessment_id = await _assessment("close-openfilter")
    poam_id = await _poam_for(assessment_id)
    async with session_scope() as s:
        s.add(
            AssessmentControlProposal(
                organization_id=org_id,
                assessment_id=assessment_id,
                control_identifier="AC-2",
                state="accepted",
            )
        )
        s.add(
            AssessmentControlProposal(
                organization_id=org_id,
                assessment_id=assessment_id,
                control_identifier="AC-2",
                source_poam_id=poam_id,
                state="draft",
            )
        )
        await s.flush()

    async with session_scope() as s:
        found = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier="AC-2"
        )

    assert found.source_poam_id is None, "must return the first-pass row"
    assert found.state == "accepted", "the first-pass row, not the re-evaluation"
