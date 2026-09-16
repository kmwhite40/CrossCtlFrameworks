"""Campaigns: waving open flaws, and every refusal."""

from __future__ import annotations

import itertools
from datetime import date, timedelta

import pytest
from sqlalchemy import select

from ccf.db import session_scope
from ccf.models import POAM, AuditLog, Organization, System
from ccf.models_enforcement import RemediationPlan
from ccf.models_patching import RemediationPolicy
from ccf.patching.service import (
    PatchingError,
    complete_wave,
    create_campaign,
    measure_system,
    plan_waves,
    resolve_window,
    waves_for,
)

_SEQ = itertools.count()
TODAY = date(2026, 9, 15)


async def _system(session) -> System:
    org = Organization(name=f"PatchSvcOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"PatchSvcSys-{next(_SEQ)}")
    session.add(sys_)
    await session.flush()
    return sys_


async def _flaws(session, sys_, n: int, *, severity: str = "high", age: int = 10,
                 source: str = "scan", status: str = "open") -> list[POAM]:
    out = []
    for i in range(n):
        p = POAM(
            system_id=sys_.id,
            title=f"flaw-{next(_SEQ)}-{i}",
            severity=severity,
            status=status,
            source=source,
            identified_on=TODAY - timedelta(days=age),
        )
        session.add(p)
        out.append(p)
    await session.flush()
    return out


# ── plan_waves, pure ─────────────────────────────────────────────────────────


def test_the_first_wave_is_a_canary_of_one() -> None:
    """A first wave the same size as the rest gives up most of the protection
    that sequencing exists to provide."""
    assert plan_waves([1, 2, 3, 4, 5, 6, 7], wave_size=3) == [[1], [2, 3, 4], [5, 6, 7]]


def test_a_single_finding_is_one_wave_not_a_canary_and_an_empty_batch() -> None:
    assert plan_waves([1], wave_size=3) == [[1]]


def test_no_findings_is_no_waves() -> None:
    assert plan_waves([], wave_size=3) == []


def test_a_wave_size_below_one_is_refused() -> None:
    """Zero would loop forever building empty batches."""
    with pytest.raises(PatchingError):
        plan_waves([1, 2], wave_size=0)


def test_every_finding_lands_in_exactly_one_wave() -> None:
    ids = list(range(1, 24))
    batches = plan_waves(ids, wave_size=5)
    flat = [i for b in batches for i in b]
    assert sorted(flat) == ids
    assert len(flat) == len(set(flat))


# ── the window ───────────────────────────────────────────────────────────────


async def test_no_policy_falls_back_to_the_fedramp_defaults() -> None:
    """Measuring against nothing would report every flaw as compliant."""
    async with session_scope() as session:
        sys_ = await _system(session)
        window = await resolve_window(session, sys_.organization_id)
        assert window.days_for("critical") == 30
        assert window.days_for("low") == 180


async def test_a_policy_overrides_the_defaults() -> None:
    async with session_scope() as session:
        sys_ = await _system(session)
        session.add(
            RemediationPolicy(
                organization_id=sys_.organization_id, critical_days=7, high_days=14
            )
        )
        await session.flush()
        window = await resolve_window(session, sys_.organization_id)
        assert window.days_for("critical") == 7
        assert window.days_for("high") == 14


async def test_another_organizations_policy_is_not_used() -> None:
    """Two policies exist; the filter must exclude, not merely include."""
    async with session_scope() as session:
        mine = await _system(session)
        theirs = await _system(session)
        session.add(
            RemediationPolicy(organization_id=theirs.organization_id, critical_days=1)
        )
        await session.flush()
        window = await resolve_window(session, mine.organization_id)
        assert window.days_for("critical") == 30


async def test_measuring_a_system_uses_its_own_policy() -> None:
    async with session_scope() as session:
        sys_ = await _system(session)
        await _flaws(session, sys_, 1, severity="high", age=20)
        assert (await measure_system(session, system_id=sys_.id, today=TODAY)).buckets[
            "within_sla"
        ] == 1
        session.add(
            RemediationPolicy(organization_id=sys_.organization_id, high_days=10)
        )
        await session.flush()
        assert (await measure_system(session, system_id=sys_.id, today=TODAY)).buckets[
            "breached"
        ] == 1


async def test_measuring_an_unknown_system_is_refused() -> None:
    async with session_scope() as session:
        with pytest.raises(PatchingError, match="unknown system"):
            await measure_system(session, system_id=9_999_999, today=TODAY)


# ── creating a campaign ──────────────────────────────────────────────────────


async def test_a_campaign_waves_the_open_scan_findings() -> None:
    async with session_scope() as session:
        sys_ = await _system(session)
        await _flaws(session, sys_, 7)
        campaign = await create_campaign(
            session,
            system_id=sys_.id,
            name="September",
            window_start=TODAY,
            window_end=TODAY + timedelta(days=7),
            actor="isso@acme.gov",
            wave_size=3,
        )
        waves = await waves_for(session, campaign.id)
        assert [len(w.poam_ids) for w in waves] == [1, 3, 3]
        assert waves[0].name.endswith("(canary)")
        assert campaign.status == "planned"


async def test_a_campaign_with_no_open_findings_is_refused() -> None:
    """An empty campaign someone later completes is a false record of work."""
    async with session_scope() as session:
        sys_ = await _system(session)
        with pytest.raises(PatchingError, match="no open scan-sourced findings"):
            await create_campaign(
                session, system_id=sys_.id, name="empty", window_start=TODAY,
                window_end=TODAY, actor="isso@acme.gov",
            )


async def test_closed_findings_are_not_waved() -> None:
    async with session_scope() as session:
        sys_ = await _system(session)
        await _flaws(session, sys_, 2, status="completed")
        with pytest.raises(PatchingError, match="no open scan-sourced findings"):
            await create_campaign(
                session, system_id=sys_.id, name="closed", window_start=TODAY,
                window_end=TODAY, actor="isso@acme.gov",
            )


async def test_assessment_sourced_poams_are_not_waved() -> None:
    """They are control deficiencies, not flaws a patch fixes."""
    async with session_scope() as session:
        sys_ = await _system(session)
        await _flaws(session, sys_, 3, source="assessment")
        with pytest.raises(PatchingError, match="no open scan-sourced findings"):
            await create_campaign(
                session, system_id=sys_.id, name="assessment", window_start=TODAY,
                window_end=TODAY, actor="isso@acme.gov",
            )


async def test_only_this_systems_findings_are_waved() -> None:
    """Two systems with flaws; the filter must exclude."""
    async with session_scope() as session:
        mine = await _system(session)
        theirs = await _system(session)
        mine_flaws = await _flaws(session, mine, 2)
        await _flaws(session, theirs, 5)
        campaign = await create_campaign(
            session, system_id=mine.id, name="mine", window_start=TODAY,
            window_end=TODAY, actor="isso@acme.gov", wave_size=5,
        )
        waved = {i for w in await waves_for(session, campaign.id) for i in w.poam_ids}
        assert waved == {p.id for p in mine_flaws}


# ── overlapping windows ──────────────────────────────────────────────────────


async def test_an_overlapping_window_on_one_system_is_refused() -> None:
    """Two campaigns patching the same assets in one window is how a
    maintenance window becomes an outage."""
    async with session_scope() as session:
        sys_ = await _system(session)
        await _flaws(session, sys_, 4)
        await create_campaign(
            session, system_id=sys_.id, name="first", window_start=TODAY,
            window_end=TODAY + timedelta(days=7), actor="isso@acme.gov",
        )
        with pytest.raises(PatchingError, match="already covers"):
            await create_campaign(
                session, system_id=sys_.id, name="second",
                window_start=TODAY + timedelta(days=3),
                window_end=TODAY + timedelta(days=10), actor="isso@acme.gov",
            )


async def test_a_window_touching_on_the_edge_is_refused() -> None:
    """A campaign ending the day another begins is still two sets of patches
    landing on the same assets that day."""
    async with session_scope() as session:
        sys_ = await _system(session)
        await _flaws(session, sys_, 4)
        await create_campaign(
            session, system_id=sys_.id, name="first", window_start=TODAY,
            window_end=TODAY + timedelta(days=7), actor="isso@acme.gov",
        )
        with pytest.raises(PatchingError, match="already covers"):
            await create_campaign(
                session, system_id=sys_.id, name="touching",
                window_start=TODAY + timedelta(days=7),
                window_end=TODAY + timedelta(days=9), actor="isso@acme.gov",
            )


async def test_a_separated_window_on_the_same_system_is_allowed() -> None:
    async with session_scope() as session:
        sys_ = await _system(session)
        await _flaws(session, sys_, 4)
        await create_campaign(
            session, system_id=sys_.id, name="first", window_start=TODAY,
            window_end=TODAY + timedelta(days=7), actor="isso@acme.gov",
        )
        later = await create_campaign(
            session, system_id=sys_.id, name="later",
            window_start=TODAY + timedelta(days=8),
            window_end=TODAY + timedelta(days=12), actor="isso@acme.gov",
        )
        assert later.id is not None


async def test_another_system_may_be_patched_in_the_same_window() -> None:
    async with session_scope() as session:
        a, b = await _system(session), await _system(session)
        await _flaws(session, a, 2)
        await _flaws(session, b, 2)
        await create_campaign(
            session, system_id=a.id, name="a", window_start=TODAY,
            window_end=TODAY + timedelta(days=7), actor="isso@acme.gov",
        )
        other = await create_campaign(
            session, system_id=b.id, name="b", window_start=TODAY,
            window_end=TODAY + timedelta(days=7), actor="isso@acme.gov",
        )
        assert other.id is not None


async def test_a_completed_campaign_does_not_block_a_new_window() -> None:
    async with session_scope() as session:
        sys_ = await _system(session)
        await _flaws(session, sys_, 2)
        first = await create_campaign(
            session, system_id=sys_.id, name="first", window_start=TODAY,
            window_end=TODAY + timedelta(days=7), actor="isso@acme.gov", wave_size=5,
        )
        for w in await waves_for(session, first.id):
            await complete_wave(session, w, actor="ao@acme.gov", evidence_ref="CHG-1")
        assert first.status == "completed"
        again = await create_campaign(
            session, system_id=sys_.id, name="second", window_start=TODAY,
            window_end=TODAY + timedelta(days=7), actor="isso@acme.gov",
        )
        assert again.id is not None


# ── completing waves ─────────────────────────────────────────────────────────


async def test_completing_a_wave_records_who_when_and_the_evidence() -> None:
    async with session_scope() as session:
        sys_ = await _system(session)
        await _flaws(session, sys_, 3)
        campaign = await create_campaign(
            session, system_id=sys_.id, name="c", window_start=TODAY,
            window_end=TODAY, actor="isso@acme.gov", wave_size=5,
        )
        waves = await waves_for(session, campaign.id)
        await complete_wave(
            session, waves[0], actor="ao@acme.gov", evidence_ref="CHG-4471"
        )
        assert waves[0].status == "completed"
        assert waves[0].completed_by == "ao@acme.gov"
        assert waves[0].completed_at is not None
        assert waves[0].evidence_ref == "CHG-4471"
        assert campaign.status == "in_progress"


async def test_completing_the_last_wave_completes_the_campaign() -> None:
    async with session_scope() as session:
        sys_ = await _system(session)
        await _flaws(session, sys_, 3)
        campaign = await create_campaign(
            session, system_id=sys_.id, name="c", window_start=TODAY,
            window_end=TODAY, actor="isso@acme.gov", wave_size=5,
        )
        for w in await waves_for(session, campaign.id):
            await complete_wave(session, w, actor="ao@acme.gov", evidence_ref="CHG-9")
        assert campaign.status == "completed"
        assert campaign.completed_at is not None


async def test_completing_a_wave_twice_is_refused() -> None:
    async with session_scope() as session:
        sys_ = await _system(session)
        await _flaws(session, sys_, 3)
        campaign = await create_campaign(
            session, system_id=sys_.id, name="c", window_start=TODAY,
            window_end=TODAY, actor="isso@acme.gov", wave_size=5,
        )
        wave = (await waves_for(session, campaign.id))[0]
        await complete_wave(session, wave, actor="ao@acme.gov", evidence_ref="CHG-1")
        with pytest.raises(PatchingError, match="already completed"):
            await complete_wave(session, wave, actor="ao@acme.gov", evidence_ref="CHG-1")


async def test_completing_out_of_order_is_refused() -> None:
    """Sequencing is the control; completing wave 2 before the canary would
    claim a protection that never applied."""
    async with session_scope() as session:
        sys_ = await _system(session)
        await _flaws(session, sys_, 5)
        campaign = await create_campaign(
            session, system_id=sys_.id, name="c", window_start=TODAY,
            window_end=TODAY, actor="isso@acme.gov", wave_size=2,
        )
        waves = await waves_for(session, campaign.id)
        with pytest.raises(PatchingError, match="still pending"):
            await complete_wave(session, waves[1], actor="ao@acme.gov")
        assert waves[1].status == "pending"


async def test_a_wave_may_reference_an_enforcement_plan() -> None:
    """The seam: recorded here, executed by enforcement when a provider exists."""
    async with session_scope() as session:
        sys_ = await _system(session)
        await _flaws(session, sys_, 2)
        plan = RemediationPlan(
            organization_id=sys_.organization_id,
            system_id=sys_.id,
            check_key="demo.check",
            provider_key="demo",
            status="applied",
        )
        session.add(plan)
        await session.flush()
        campaign = await create_campaign(
            session, system_id=sys_.id, name="c", window_start=TODAY,
            window_end=TODAY, actor="isso@acme.gov", wave_size=5,
        )
        wave = (await waves_for(session, campaign.id))[0]
        await complete_wave(
            session, wave, actor="ao@acme.gov", remediation_plan_id=plan.id
        )
        assert wave.remediation_plan_id == plan.id


# ── CRITICAL 2: a wave may only cite an applied plan for its own tenant/system ─


async def test_a_wave_citing_an_unapplied_plan_is_refused() -> None:
    """A ``refused``/``draft``/``failed``/``reversed``/``rejected`` plan never
    applied; citing it would read to an assessor as "applied by enforcement
    plan N" when it never ran."""
    async with session_scope() as session:
        sys_ = await _system(session)
        await _flaws(session, sys_, 2)
        plan = RemediationPlan(
            organization_id=sys_.organization_id,
            system_id=sys_.id,
            check_key="demo.check",
            provider_key="demo",
            status="refused",
        )
        session.add(plan)
        await session.flush()
        campaign = await create_campaign(
            session, system_id=sys_.id, name="c", window_start=TODAY,
            window_end=TODAY, actor="isso@acme.gov", wave_size=5,
        )
        wave = (await waves_for(session, campaign.id))[0]
        with pytest.raises(PatchingError, match="not an applied plan"):
            await complete_wave(
                session, wave, actor="ao@acme.gov", remediation_plan_id=plan.id
            )
        assert wave.status == "pending"


async def test_a_wave_citing_another_organizations_plan_is_refused() -> None:
    """FK enforcement alone would let this through -- it bypasses RLS and does
    not know about tenancy."""
    async with session_scope() as session:
        sys_ = await _system(session)
        other = await _system(session)
        await _flaws(session, sys_, 2)
        plan = RemediationPlan(
            organization_id=other.organization_id,
            system_id=other.id,
            check_key="demo.check",
            provider_key="demo",
            status="applied",
        )
        session.add(plan)
        await session.flush()
        campaign = await create_campaign(
            session, system_id=sys_.id, name="c", window_start=TODAY,
            window_end=TODAY, actor="isso@acme.gov", wave_size=5,
        )
        wave = (await waves_for(session, campaign.id))[0]
        with pytest.raises(PatchingError, match="not an applied plan"):
            await complete_wave(
                session, wave, actor="ao@acme.gov", remediation_plan_id=plan.id
            )


async def test_a_wave_citing_a_plan_for_a_different_system_is_refused() -> None:
    """Same organization, wrong system: the plan applied somewhere, just not
    to what this campaign is patching."""
    async with session_scope() as session:
        org_sys = await _system(session)
        sibling = System(
            organization_id=org_sys.organization_id, name=f"PatchSvcSibling-{next(_SEQ)}"
        )
        session.add(sibling)
        await session.flush()
        await _flaws(session, org_sys, 2)
        plan = RemediationPlan(
            organization_id=org_sys.organization_id,
            system_id=sibling.id,
            check_key="demo.check",
            provider_key="demo",
            status="applied",
        )
        session.add(plan)
        await session.flush()
        campaign = await create_campaign(
            session, system_id=org_sys.id, name="c", window_start=TODAY,
            window_end=TODAY, actor="isso@acme.gov", wave_size=5,
        )
        wave = (await waves_for(session, campaign.id))[0]
        with pytest.raises(PatchingError, match="not an applied plan"):
            await complete_wave(
                session, wave, actor="ao@acme.gov", remediation_plan_id=plan.id
            )


# ── CRITICAL 3: no evidence, no completion ──────────────────────────────────


async def test_completing_a_wave_with_no_evidence_at_all_is_refused() -> None:
    """The PR's own summary says a wave records completion "with evidence" --
    an empty body must not be able to complete one."""
    async with session_scope() as session:
        sys_ = await _system(session)
        await _flaws(session, sys_, 2)
        campaign = await create_campaign(
            session, system_id=sys_.id, name="c", window_start=TODAY,
            window_end=TODAY, actor="isso@acme.gov", wave_size=5,
        )
        wave = (await waves_for(session, campaign.id))[0]
        with pytest.raises(PatchingError, match="requires evidence_ref"):
            await complete_wave(session, wave, actor="ao@acme.gov")
        assert wave.status == "pending"


async def test_a_blank_evidence_ref_is_the_same_as_none() -> None:
    """Whitespace is not evidence."""
    async with session_scope() as session:
        sys_ = await _system(session)
        await _flaws(session, sys_, 2)
        campaign = await create_campaign(
            session, system_id=sys_.id, name="c", window_start=TODAY,
            window_end=TODAY, actor="isso@acme.gov", wave_size=5,
        )
        wave = (await waves_for(session, campaign.id))[0]
        with pytest.raises(PatchingError, match="requires evidence_ref"):
            await complete_wave(session, wave, actor="ao@acme.gov", evidence_ref="   ")


# ── IMPORTANT 6: a decided campaign cannot be resurrected ──────────────────


async def test_completing_a_wave_on_a_cancelled_campaign_is_refused() -> None:
    async with session_scope() as session:
        sys_ = await _system(session)
        await _flaws(session, sys_, 2)
        campaign = await create_campaign(
            session, system_id=sys_.id, name="c", window_start=TODAY,
            window_end=TODAY, actor="isso@acme.gov", wave_size=5,
        )
        campaign.status = "cancelled"
        await session.flush()
        wave = (await waves_for(session, campaign.id))[0]
        with pytest.raises(PatchingError, match="cancelled"):
            await complete_wave(session, wave, actor="ao@acme.gov", evidence_ref="CHG-1")
        assert wave.status == "pending"
        assert campaign.status == "cancelled"


async def test_completing_a_leftover_wave_on_a_completed_campaign_is_refused() -> None:
    """A campaign already marked completed must not be flipped back to
    in_progress by a leftover pending wave."""
    async with session_scope() as session:
        sys_ = await _system(session)
        await _flaws(session, sys_, 2)
        campaign = await create_campaign(
            session, system_id=sys_.id, name="c", window_start=TODAY,
            window_end=TODAY, actor="isso@acme.gov", wave_size=5,
        )
        wave = (await waves_for(session, campaign.id))[0]
        campaign.status = "completed"
        await session.flush()
        with pytest.raises(PatchingError, match="completed"):
            await complete_wave(session, wave, actor="ao@acme.gov", evidence_ref="CHG-1")


# ── IMPORTANT 7: skipped waves are named, not implied ───────────────────────


async def test_a_skipped_wave_does_not_block_the_campaign_from_completing() -> None:
    """Nothing can set ``skipped`` yet -- the DB constraint merely permits it
    -- but the rollup must treat it as a named terminal state rather than
    relying on "anything but pending"."""
    async with session_scope() as session:
        sys_ = await _system(session)
        await _flaws(session, sys_, 5)
        campaign = await create_campaign(
            session, system_id=sys_.id, name="c", window_start=TODAY,
            window_end=TODAY, actor="isso@acme.gov", wave_size=2,
        )
        waves = await waves_for(session, campaign.id)
        waves[1].status = "skipped"
        await session.flush()
        await complete_wave(
            session, waves[0], actor="ao@acme.gov", evidence_ref="CHG-1"
        )
        await complete_wave(
            session, waves[2], actor="ao@acme.gov", evidence_ref="CHG-2"
        )
        assert campaign.status == "completed"
        assert campaign.completed_at is not None


# ── Minor: resolve_window degrades like get_policy/set_policy, not a 500 ────


async def test_two_unscoped_policy_rows_do_not_crash_resolve_window() -> None:
    """``organization_id`` is nullable and Postgres treats NULLs as distinct
    under the unique constraint, so two unscoped rows are possible.
    ``resolve_window`` must degrade the same way api/routes/patching.py's
    ``get_policy``/``set_policy`` do (``.first()``), not 500 on
    ``scalar_one_or_none()``'s "more than one row" error.

    ``organization_id=None`` is the same row shape the "default policy"
    tests in test_patching_api.py depend on being absent, and
    ``session_scope`` commits -- so this cleans up its own two rows rather
    than leaving them behind for the rest of the suite to trip over.
    """
    ids: list[int] = []
    try:
        async with session_scope() as session:
            a = RemediationPolicy(organization_id=None, critical_days=3)
            b = RemediationPolicy(organization_id=None, critical_days=5)
            session.add_all([a, b])
            await session.flush()
            ids = [a.id, b.id]
        async with session_scope() as session:
            window = await resolve_window(session, None)
            assert window.days_for("critical") in (3, 5)
    finally:
        async with session_scope() as session:
            for pid in ids:
                row = await session.get(RemediationPolicy, pid)
                if row is not None:
                    await session.delete(row)


async def test_every_transition_is_audited() -> None:
    async with session_scope() as session:
        sys_ = await _system(session)
        await _flaws(session, sys_, 2)
        campaign = await create_campaign(
            session, system_id=sys_.id, name="c", window_start=TODAY,
            window_end=TODAY, actor="isso@acme.gov", wave_size=5,
        )
        rows = (
            await session.execute(
                select(AuditLog).where(
                    AuditLog.entity_type == "patch_campaign",
                    AuditLog.entity_id == str(campaign.id),
                )
            )
        ).scalars().all()
        assert [r.diff.get("event") for r in rows] == ["planned"]
        assert all(r.row_hash for r in rows)

        wave = (await waves_for(session, campaign.id))[0]
        await complete_wave(session, wave, actor="ao@acme.gov", evidence_ref="CHG-1")
        wave_rows = (
            await session.execute(
                select(AuditLog).where(
                    AuditLog.entity_type == "patch_wave",
                    AuditLog.entity_id == str(wave.id),
                )
            )
        ).scalars().all()
        assert [r.diff.get("event") for r in wave_rows] == ["completed"]
