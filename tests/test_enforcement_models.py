"""The plan row: defaults, the status vocabulary, and what outlives what."""

from __future__ import annotations

import itertools

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from ccf.db import session_scope
from ccf.models import Organization, System
from ccf.models_enforcement import PLAN_STATUSES, RemediationPlan
from ccf.models_grc import ControlTest, ControlTestResult

_SEQ = itertools.count()


async def _system(session) -> System:
    org = Organization(name=f"EnforceOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"EnforceSys-{next(_SEQ)}")
    session.add(sys_)
    await session.flush()
    return sys_


def _plan(sys_, **kw) -> RemediationPlan:
    base = dict(
        organization_id=sys_.organization_id,
        system_id=sys_.id,
        check_key="m365.identity.stale_accounts",
        provider_key="m365_account",
    )
    base.update(kw)
    return RemediationPlan(**base)


async def test_a_plan_round_trips() -> None:
    async with session_scope() as session:
        sys_ = await _system(session)
        plan = _plan(
            sys_,
            steps=[{"resource_id": "u@acme.gov", "current_state": {"enabled": True}}],
            resource_count=1,
            requested_by="isso@acme.gov",
        )
        session.add(plan)
        await session.flush()
        got = (
            await session.execute(
                select(RemediationPlan).where(RemediationPlan.id == plan.id)
            )
        ).scalar_one()
        assert got.check_key == "m365.identity.stale_accounts"
        assert got.steps[0]["current_state"] == {"enabled": True}


async def test_a_new_plan_is_a_draft_that_has_done_nothing() -> None:
    async with session_scope() as session:
        sys_ = await _system(session)
        plan = _plan(sys_)
        session.add(plan)
        await session.flush()
        assert plan.status == "draft"
        assert plan.steps == []
        assert plan.outcomes == []
        assert plan.resource_count == 0
        assert plan.approved_by is None
        assert plan.applied_at is None


async def test_the_status_vocabulary_is_enforced_by_the_database() -> None:
    """The application must not be the only thing keeping a plan's state
    meaningful."""
    async with session_scope() as session:
        sys_ = await _system(session)
        session.add(_plan(sys_, status="yolo"))
        with pytest.raises(IntegrityError):
            await session.flush()
        await session.rollback()


def test_the_python_vocabulary_matches_the_constraint() -> None:
    assert sorted(PLAN_STATUSES) == [
        "applied", "approved", "draft", "failed", "pending_approval",
        "refused", "rejected", "reversed",
    ]


async def test_pruning_the_result_keeps_the_record_of_what_was_done() -> None:
    """Retention prunes observations; what was *done about* one must outlive it."""
    async with session_scope() as session:
        sys_ = await _system(session)
        test = ControlTest(
            organization_id=sys_.organization_id,
            system_id=sys_.id,
            control_id="AC-2",
            name="Stale accounts",
            method="connector",
        )
        session.add(test)
        await session.flush()
        result = ControlTestResult(control_test_id=test.id, status="fail")
        session.add(result)
        await session.flush()
        plan = _plan(sys_, result_id=result.id, status="applied")
        session.add(plan)
        await session.flush()
        plan_id, result_id = plan.id, result.id

        await session.execute(
            text("DELETE FROM ccf.control_test_results WHERE id = :i"), {"i": result_id}
        )
        await session.flush()
        session.expire(plan)
        kept = (
            await session.execute(
                select(RemediationPlan).where(RemediationPlan.id == plan_id)
            )
        ).scalar_one()
        assert kept.status == "applied"
        assert kept.result_id is None
