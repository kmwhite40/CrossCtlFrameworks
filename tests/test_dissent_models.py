"""The four AI-dissent-path columns (migration 0063): four nullable
columns on assessment_objective_proposals (primary_verdict, and the three
challenger columns), and a NOT NULL dissent_count rollup on
assessment_control_proposals.

NULL rather than a sentinel on the dissent-path columns, so "not challenged"
and "challenged and agreed" stay distinguishable -- the calibration
measurement depends on that distinction (see ccf.assessment.engine.evaluate).
primary_verdict is recorded rather than inferred from the fact of a
challenge: today's satisfied-only challenge policy would make the primary
verdict inferable, but that policy is expected to broaden, and the moment it
does, every previously contested row becomes unreadable without this column.
dissent_count is NOT NULL with a default of 0: every existing control
proposal, and every un-challenged one going forward, gets a real, comparable
zero rather than a NULL a reader would need to special-case.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from ccf.db import session_scope
from ccf.models import Assessment, Organization, System
from ccf.models_ai_actions import AiActionRun
from ccf.models_assessment_engine import AssessmentControlProposal, AssessmentObjectiveProposal

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


async def _control_proposal(org_id: int, assessment_id: int, control: str = "AC-2") -> int:
    async with session_scope() as s:
        p = AssessmentControlProposal(
            organization_id=org_id, assessment_id=assessment_id, control_identifier=control
        )
        s.add(p)
        await s.flush()
        return int(p.id)


async def _ai_run(org_id: int) -> int:
    async with session_scope() as s:
        run = AiActionRun(
            organization_id=org_id,
            action_key="challenge_assessment_objective",
            entity_type="assessment_objective",
            entity_id="AC-2a",
            status="recorded",
            provider="anthropic",
        )
        s.add(run)
        await s.flush()
        return int(run.id)


async def test_dissent_columns_default_to_null() -> None:
    org_id, assessment_id = await _assessment("dissent-defaults")
    proposal_id = await _control_proposal(org_id, assessment_id)
    async with session_scope() as s:
        o = AssessmentObjectiveProposal(
            organization_id=org_id,
            control_proposal_id=proposal_id,
            label="AC-2a",
            objective_text="x",
            objective_text_sha256="0" * 64,
        )
        s.add(o)
        await s.flush()
        assert o.primary_verdict is None
        assert o.challenger_verdict is None
        assert o.challenger_rationale is None
        assert o.challenger_ai_action_run_id is None


async def test_dissent_columns_round_trip() -> None:
    org_id, assessment_id = await _assessment("dissent-roundtrip")
    proposal_id = await _control_proposal(org_id, assessment_id)
    run_id = await _ai_run(org_id)
    async with session_scope() as s:
        o = AssessmentObjectiveProposal(
            organization_id=org_id,
            control_proposal_id=proposal_id,
            label="AC-2a",
            objective_text="x",
            objective_text_sha256="0" * 64,
            primary_verdict="satisfied",
            challenger_verdict="not_satisfied",
            challenger_rationale="the challenger's own argument",
            challenger_ai_action_run_id=run_id,
        )
        s.add(o)
        await s.flush()
        oid = int(o.id)
    async with session_scope() as s:
        row = (
            await s.execute(
                select(AssessmentObjectiveProposal).where(AssessmentObjectiveProposal.id == oid)
            )
        ).scalar_one()
        assert row.primary_verdict == "satisfied"
        assert row.challenger_verdict == "not_satisfied"
        assert row.challenger_rationale == "the challenger's own argument"
        assert row.challenger_ai_action_run_id == run_id


async def test_deleting_the_challenger_ai_run_sets_the_link_null_not_cascade() -> None:
    """ON DELETE SET NULL: the objective proposal is a record of what
    happened and must survive its provenance row being cleaned up -- exactly
    matching this same table's existing ai_action_run_id FK (migration 0060).
    """
    org_id, assessment_id = await _assessment("dissent-fk-set-null")
    proposal_id = await _control_proposal(org_id, assessment_id)
    run_id = await _ai_run(org_id)
    async with session_scope() as s:
        o = AssessmentObjectiveProposal(
            organization_id=org_id,
            control_proposal_id=proposal_id,
            label="AC-2a",
            objective_text="x",
            objective_text_sha256="0" * 64,
            primary_verdict="satisfied",
            challenger_verdict="satisfied",
            challenger_ai_action_run_id=run_id,
        )
        s.add(o)
        await s.flush()
        oid = int(o.id)
    async with session_scope() as s:
        await s.execute(text("DELETE FROM ccf.ai_action_runs WHERE id = :id"), {"id": run_id})
    async with session_scope() as s:
        row = (
            await s.execute(
                select(AssessmentObjectiveProposal).where(AssessmentObjectiveProposal.id == oid)
            )
        ).scalar_one()
        assert row.challenger_ai_action_run_id is None
        assert row.challenger_verdict == "satisfied", "the verdict itself must survive"
        assert row.primary_verdict == "satisfied", "the primary verdict itself must survive"


async def test_dissent_count_defaults_to_zero_not_null() -> None:
    org_id, assessment_id = await _assessment("dissent-count-default")
    async with session_scope() as s:
        p = AssessmentControlProposal(
            organization_id=org_id, assessment_id=assessment_id, control_identifier="AC-2"
        )
        s.add(p)
        await s.flush()
        assert p.dissent_count == 0


async def test_dissent_count_column_is_not_nullable() -> None:
    """Guards migration 0063 declaring nullable=False in the migration
    itself, not just relying on the ORM's Mapped[int] -- a migration that
    forgot nullable=False would let a raw INSERT (bypassing the ORM's own
    Python-side default entirely) slip a NULL past it.
    """
    async with session_scope() as s:
        is_nullable = (
            await s.execute(
                text(
                    "SELECT is_nullable FROM information_schema.columns "
                    "WHERE table_schema = 'ccf' AND table_name = 'assessment_control_proposals' "
                    "AND column_name = 'dissent_count'"
                )
            )
        ).scalar_one()
    assert is_nullable == "NO"


async def test_dissent_count_round_trips() -> None:
    org_id, assessment_id = await _assessment("dissent-count-roundtrip")
    async with session_scope() as s:
        p = AssessmentControlProposal(
            organization_id=org_id,
            assessment_id=assessment_id,
            control_identifier="AC-2",
            dissent_count=3,
        )
        s.add(p)
        await s.flush()
        pid = int(p.id)
    async with session_scope() as s:
        row = (
            await s.execute(
                select(AssessmentControlProposal).where(AssessmentControlProposal.id == pid)
            )
        ).scalar_one()
        assert row.dissent_count == 3


async def test_inserting_dissent_count_null_directly_is_rejected() -> None:
    """Belt-and-braces alongside test_dissent_count_column_is_not_nullable:
    a raw INSERT that explicitly supplies NULL (rather than omitting the
    column, which the ORM's Python-side default of 0 would silently fill)
    must be rejected by the database itself, not merely by application code.
    """
    org_id, assessment_id = await _assessment("dissent-count-null-insert")
    async with session_scope() as s:
        with pytest.raises(IntegrityError):
            await s.execute(
                text(
                    "INSERT INTO ccf.assessment_control_proposals "
                    "(organization_id, assessment_id, control_identifier, dissent_count) "
                    "VALUES (:org_id, :assessment_id, 'AC-3', NULL)"
                ),
                {"org_id": org_id, "assessment_id": assessment_id},
            )
