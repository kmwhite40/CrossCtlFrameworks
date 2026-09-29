"""Live-scan health is a share of what was actually judged.

``health_pct`` divided passing checks by *every* recorded result, including the
ones that judged nothing. ``not_applicable`` is what a check returns when nothing
was in scope -- an unlicensed tenant makes every staleness finding
``not_applicable``, and `roll_up_findings` returns it for a fleet of zero -- so a
system where nothing could be assessed reported **0% health**. That reads as
catastrophic on a page whose job is to tell an operator where to look, when the
truth is that the system was never measured.
"""

from __future__ import annotations

import itertools
from datetime import UTC, datetime

import pytest
from sqlalchemy import delete

from ccf.analytics.live_scan import (
    _UNASSESSABLE,
    live_scan_by_system,
    live_scan_for_org,
    live_scan_for_system,
)
from ccf.db import session_scope
from ccf.models import Organization, System
from ccf.models_grc import ControlTest, ControlTestResult
from ccf.posture.rollup import EXCLUDED_FROM_ROLLUP

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()


async def _scene(statuses: list[str], *, org_id: int | None = None) -> tuple[int, int]:
    """One system carrying one generated control test per status."""
    tag = f"{next(_SEQ)}"
    async with session_scope() as s:
        if org_id is None:
            org = Organization(name=f"LiveScan Org {tag}")
            s.add(org)
            await s.flush()
            org_id = org.id
        sys_ = System(organization_id=org_id, name=f"LiveScan Sys {tag}")
        s.add(sys_)
        await s.flush()
        for i, status in enumerate(statuses):
            test = ControlTest(
                organization_id=org_id,
                system_id=sys_.id,
                control_id=f"AC-{i + 1}",
                name=f"check {i}",
                method="connector",
                source="generated",
                check_key=f"k.{tag}.{i}",
                last_status=status,
            )
            s.add(test)
            await s.flush()
            s.add(
                ControlTestResult(
                    control_test_id=test.id,
                    status=status,
                    run_at=datetime(2026, 9, 29, tzinfo=UTC),
                    evaluated=1,
                    failing=1 if status == "fail" else 0,
                )
            )
        await s.flush()
        return org_id, sys_.id


async def _cleanup(org_id: int) -> None:
    async with session_scope() as s:
        await s.execute(delete(Organization).where(Organization.id == org_id))


def test_the_unassessable_set_is_the_rollups_own() -> None:
    """One definition. A second list of "verdicts that do not count" is how two
    views of the same scan come to disagree."""
    assert _UNASSESSABLE is EXCLUDED_FROM_ROLLUP


@pytest.mark.asyncio
async def test_a_system_nothing_could_assess_is_not_reported_as_zero_percent() -> None:
    org_id, sys_id = await _scene(["not_applicable"] * 4)
    try:
        async with session_scope() as s:
            row = await live_scan_for_system(s, system_id=sys_id, org_id=org_id)
        assert row["total"] == 4
        assert row["assessed"] == 0
        assert row["health_pct"] is None, (
            "a system nothing could assess reported a health percentage"
        )
        assert row["attention"] == 0
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_out_of_scope_checks_do_not_dilute_the_percentage() -> None:
    """8 passing of 8 assessable is 100%, not 80% because two found nothing."""
    org_id, sys_id = await _scene(["pass"] * 8 + ["not_applicable"] * 2)
    try:
        async with session_scope() as s:
            row = await live_scan_for_system(s, system_id=sys_id, org_id=org_id)
        assert row["total"] == 10
        assert row["assessed"] == 8
        assert row["health_pct"] == 100
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_an_unassessable_check_still_counts_against_health() -> None:
    """`manual_review_required` is not out of scope -- the check should have
    judged the control and could not, so the system is not demonstrably healthy
    on it. Counting it as out of scope would let a missing app permission read
    as a clean result."""
    org_id, sys_id = await _scene(["pass", "manual_review_required"])
    try:
        async with session_scope() as s:
            row = await live_scan_for_system(s, system_id=sys_id, org_id=org_id)
        assert row["assessed"] == 2
        assert row["health_pct"] == 50
        assert row["attention"] == 1
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_a_failing_check_lowers_health_and_raises_attention() -> None:
    org_id, sys_id = await _scene(["pass", "pass", "fail", "warn"])
    try:
        async with session_scope() as s:
            row = await live_scan_for_system(s, system_id=sys_id, org_id=org_id)
        assert row["assessed"] == 4
        assert row["health_pct"] == 50
        assert row["attention"] == 2
        assert row["failing_resources"] == 1
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_the_org_rollup_uses_the_same_denominator_as_one_system() -> None:
    """Two views of one scan disagreeing is the defect this guards."""
    org_id, _sys = await _scene(["pass"] * 3 + ["not_applicable"])
    await _scene(["pass", "fail"], org_id=org_id)
    try:
        async with session_scope() as s:
            org_row = await live_scan_for_org(s, org_id=org_id)
            by_system = await live_scan_by_system(s, org_id=org_id)
        assert org_row["total"] == 6
        assert org_row["assessed"] == 5
        assert org_row["assessed"] == sum(r["assessed"] for r in by_system.values())
        assert org_row["health_pct"] == round(4 / 5 * 100)
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_another_tenants_scan_is_not_counted() -> None:
    mine, mine_sys = await _scene(["pass"])
    theirs, _ = await _scene(["fail"] * 5)
    try:
        async with session_scope() as s:
            row = await live_scan_for_system(s, system_id=mine_sys, org_id=mine)
            org_row = await live_scan_for_org(s, org_id=mine)
            everyone = await live_scan_by_system(s, org_id=mine)
        assert row["total"] == 1
        assert org_row["fail"] == 0, "another tenant's failures reached this rollup"
        assert all(r["fail"] == 0 for r in everyone.values())
    finally:
        await _cleanup(mine)
        await _cleanup(theirs)


@pytest.mark.asyncio
async def test_a_deleted_system_is_not_counted() -> None:
    """Analytics that forgot this once put a deleted system in the headline."""
    org_id, sys_id = await _scene(["fail"] * 3)
    try:
        async with session_scope() as s:
            sys_ = await s.get(System, sys_id)
            sys_.deleted_at = datetime(2026, 9, 29, tzinfo=UTC)
        async with session_scope() as s:
            org_row = await live_scan_for_org(s, org_id=org_id)
            by_system = await live_scan_by_system(s, org_id=org_id)
        assert org_row["total"] == 0
        assert sys_id not in by_system
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_a_system_with_no_scan_gets_the_empty_shape_not_a_missing_key() -> None:
    org_id, _sys_id = await _scene([])
    try:
        async with session_scope() as s:
            row = await live_scan_for_system(s, system_id=999_999, org_id=org_id)
        for key in ("total", "assessed", "pass", "attention", "health_pct", "latest_run"):
            assert key in row, key
        assert row["health_pct"] is None
    finally:
        await _cleanup(org_id)
