"""Policy, campaign and wave rows, and the constraints that keep them honest."""

from __future__ import annotations

import itertools
from datetime import date, timedelta

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from ccf.db import session_scope
from ccf.models import Organization, System
from ccf.models_enforcement import RemediationPlan
from ccf.models_patching import (
    CAMPAIGN_STATUSES,
    WAVE_STATUSES,
    PatchCampaign,
    PatchWave,
    RemediationPolicy,
)
from ccf.patching.sla import FEDRAMP_TIMEFRAMES

_SEQ = itertools.count()
TODAY = date(2026, 9, 15)


async def _system(session) -> System:
    org = Organization(name=f"PatchOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"PatchSys-{next(_SEQ)}")
    session.add(sys_)
    await session.flush()
    return sys_


def _campaign(sys_, **kw) -> PatchCampaign:
    base = dict(
        organization_id=sys_.organization_id,
        system_id=sys_.id,
        name="September criticals",
        window_start=TODAY,
        window_end=TODAY + timedelta(days=7),
    )
    base.update(kw)
    return PatchCampaign(**base)


# ── the policy ───────────────────────────────────────────────────────────────


async def test_a_policy_defaults_to_the_fedramp_timeframes() -> None:
    """A deployment that never sets one is still measured against the numbers
    an assessor expects, rather than against nothing."""
    async with session_scope() as session:
        org = Organization(name=f"PolicyOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        policy = RemediationPolicy(organization_id=org.id)
        session.add(policy)
        await session.flush()
        assert policy.critical_days == FEDRAMP_TIMEFRAMES["critical"]
        assert policy.high_days == FEDRAMP_TIMEFRAMES["high"]
        assert policy.moderate_days == FEDRAMP_TIMEFRAMES["moderate"]
        assert policy.low_days == FEDRAMP_TIMEFRAMES["low"]


async def test_one_policy_per_organization() -> None:
    """Two policies would make the measured timeframe depend on row order."""
    async with session_scope() as session:
        org = Organization(name=f"PolicyOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        session.add_all([RemediationPolicy(organization_id=org.id) for _ in range(2)])
        with pytest.raises(IntegrityError):
            await session.flush()
        await session.rollback()


async def test_a_zero_day_window_is_refused() -> None:
    """Zero days is not a policy, it is a guarantee of breach."""
    async with session_scope() as session:
        org = Organization(name=f"PolicyOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        session.add(RemediationPolicy(organization_id=org.id, critical_days=0))
        with pytest.raises(IntegrityError):
            await session.flush()
        await session.rollback()


# ── the campaign ─────────────────────────────────────────────────────────────


async def test_a_campaign_round_trips_as_planned() -> None:
    async with session_scope() as session:
        sys_ = await _system(session)
        c = _campaign(sys_, created_by="isso@acme.gov")
        session.add(c)
        await session.flush()
        got = (
            await session.execute(select(PatchCampaign).where(PatchCampaign.id == c.id))
        ).scalar_one()
        assert got.status == "planned"
        assert got.completed_at is None


async def test_a_backwards_window_is_refused() -> None:
    async with session_scope() as session:
        sys_ = await _system(session)
        session.add(
            _campaign(sys_, window_start=TODAY, window_end=TODAY - timedelta(days=1))
        )
        with pytest.raises(IntegrityError):
            await session.flush()
        await session.rollback()


async def test_a_single_day_window_is_allowed() -> None:
    """Start equals end is a valid one-day window, not a backwards one."""
    async with session_scope() as session:
        sys_ = await _system(session)
        session.add(_campaign(sys_, window_start=TODAY, window_end=TODAY))
        await session.flush()


async def test_the_campaign_status_vocabulary_is_enforced_by_the_database() -> None:
    async with session_scope() as session:
        sys_ = await _system(session)
        session.add(_campaign(sys_, status="whenever"))
        with pytest.raises(IntegrityError):
            await session.flush()
        await session.rollback()


def test_the_python_status_vocabularies_match_the_constraints() -> None:
    assert sorted(CAMPAIGN_STATUSES) == ["cancelled", "completed", "in_progress", "planned"]
    assert sorted(WAVE_STATUSES) == ["completed", "pending", "skipped"]


# ── the waves ────────────────────────────────────────────────────────────────


async def test_two_waves_cannot_claim_one_position() -> None:
    """Order is the control; an ambiguous order defeats it."""
    async with session_scope() as session:
        sys_ = await _system(session)
        c = _campaign(sys_)
        session.add(c)
        await session.flush()
        session.add_all(
            [PatchWave(campaign_id=c.id, sequence=1) for _ in range(2)]
        )
        with pytest.raises(IntegrityError):
            await session.flush()
        await session.rollback()


async def test_a_wave_starts_pending_with_nothing_recorded() -> None:
    async with session_scope() as session:
        sys_ = await _system(session)
        c = _campaign(sys_)
        session.add(c)
        await session.flush()
        w = PatchWave(campaign_id=c.id, sequence=1, poam_ids=[1, 2])
        session.add(w)
        await session.flush()
        assert w.status == "pending"
        assert w.completed_at is None
        assert w.completed_by is None
        assert w.evidence_ref is None


async def test_deleting_the_enforcement_plan_keeps_the_record_that_a_wave_ran() -> None:
    """The plan is how it was applied; the wave is that it was."""
    async with session_scope() as session:
        sys_ = await _system(session)
        c = _campaign(sys_)
        session.add(c)
        plan = RemediationPlan(
            organization_id=sys_.organization_id,
            system_id=sys_.id,
            check_key="demo.check",
            provider_key="demo",
        )
        session.add(plan)
        await session.flush()
        w = PatchWave(
            campaign_id=c.id,
            sequence=1,
            status="completed",
            remediation_plan_id=plan.id,
        )
        session.add(w)
        await session.flush()
        wave_id, plan_id = w.id, plan.id

        await session.execute(
            text("DELETE FROM ccf.remediation_plans WHERE id = :i"), {"i": plan_id}
        )
        await session.flush()
        session.expire(w)
        kept = (
            await session.execute(select(PatchWave).where(PatchWave.id == wave_id))
        ).scalar_one()
        assert kept.status == "completed"
        assert kept.remediation_plan_id is None


async def test_deleting_a_campaign_removes_its_waves() -> None:
    """A wave has no meaning without its campaign, unlike evidence of a change."""
    async with session_scope() as session:
        sys_ = await _system(session)
        c = _campaign(sys_)
        session.add(c)
        await session.flush()
        session.add(PatchWave(campaign_id=c.id, sequence=1))
        await session.flush()
        campaign_id = c.id
        await session.execute(
            text("DELETE FROM ccf.patch_campaigns WHERE id = :i"), {"i": campaign_id}
        )
        await session.flush()
        remaining = (
            await session.execute(
                select(PatchWave).where(PatchWave.campaign_id == campaign_id)
            )
        ).scalars().all()
        assert remaining == []
