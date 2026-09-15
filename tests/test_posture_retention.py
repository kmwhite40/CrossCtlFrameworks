"""Retention: window the per-resource detail, keep the series."""

from __future__ import annotations

import itertools
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select, update

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance.control_tests import record_result
from ccf.models import Organization, System
from ccf.models_grc import ControlTest, ControlTestResourceResult, ControlTestResult
from ccf.models_waivers import Waiver
from ccf.posture.retention import prune_resource_detail
from ccf.posture.types import ResourceFinding

_SEQ = itertools.count()


def _f(rid: str, verdict: str = "fail") -> ResourceFinding:
    return ResourceFinding(
        resource_id=rid, resource_type="entra_user", verdict=verdict, observed="observed"
    )


async def _test_on_new_system(session) -> ControlTest:
    org = Organization(name=f"RetOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"RetSys-{next(_SEQ)}")
    session.add(sys_)
    await session.flush()
    test = ControlTest(
        organization_id=org.id,
        system_id=sys_.id,
        control_id="IA-2",
        name="MFA",
        method="connector",
        check_key=f"ret.check.{next(_SEQ)}",
    )
    session.add(test)
    await session.flush()
    return test


async def _age(session, result_id: int, days: int) -> None:
    """Backdate a result, since run_at has a server default."""
    await session.execute(
        update(ControlTestResult)
        .where(ControlTestResult.id == result_id)
        .values(run_at=datetime.now(UTC) - timedelta(days=days))
    )
    await session.flush()


async def _resource_rows(session, test_id: int) -> list[ControlTestResourceResult]:
    return list(
        (
            await session.execute(
                select(ControlTestResourceResult)
                .join(
                    ControlTestResult,
                    ControlTestResult.id == ControlTestResourceResult.result_id,
                )
                .where(ControlTestResult.control_test_id == test_id)
            )
        )
        .scalars()
        .all()
    )


async def _result_count(session, test_id: int) -> int:
    return (
        await session.execute(
            select(func.count())
            .select_from(ControlTestResult)
            .where(ControlTestResult.control_test_id == test_id)
        )
    ).scalar_one()


@pytest.mark.asyncio
async def test_rows_inside_the_window_survive() -> None:
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        old = await record_result(
            session, test, status="fail", detail="1", evaluated=1, failing=1,
            resources=[_f("a@acme.gov")],
        )
        await _age(session, old.id, 10)
        await record_result(
            session, test, status="fail", detail="2", evaluated=1, failing=1,
            resources=[_f("a@acme.gov")],
        )
        await prune_resource_detail(session, retain_days=30)
        assert len(await _resource_rows(session, test.id)) == 2


@pytest.mark.asyncio
async def test_rows_outside_the_window_are_deleted() -> None:
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        old = await record_result(
            session, test, status="fail", detail="1", evaluated=1, failing=1,
            resources=[_f("a@acme.gov")],
        )
        await _age(session, old.id, 400)
        await record_result(
            session, test, status="fail", detail="2", evaluated=1, failing=1,
            resources=[_f("a@acme.gov")],
        )
        out = await prune_resource_detail(session, retain_days=30)
        rows = await _resource_rows(session, test.id)
        assert len(rows) == 1, "only the recent result's detail remains"
        assert out["deleted"] >= 1


@pytest.mark.asyncio
async def test_the_latest_results_rows_survive_at_any_age() -> None:
    """A check that last ran eighteen months ago must still say which resources
    failed, or "3 of 47" becomes an unexplainable number."""
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        only = await record_result(
            session, test, status="fail", detail="ancient", evaluated=2, failing=2,
            resources=[_f("a@acme.gov"), _f("b@acme.gov")],
        )
        await _age(session, only.id, 540)
        await prune_resource_detail(session, retain_days=30)
        assert len(await _resource_rows(session, test.id)) == 2


@pytest.mark.asyncio
async def test_a_waived_row_survives_at_any_age() -> None:
    """It records which resource an acceptance covered -- the audit question a
    waiver exists to answer."""
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        w = Waiver(
            organization_id=test.organization_id,
            system_id=test.system_id,
            check_key=test.check_key,
            rationale="accepted",
            status="approved",
        )
        session.add(w)
        await session.flush()
        old = await record_result(
            session, test, status="fail", detail="waived", evaluated=1, failing=1,
            resources=[_f("accepted@acme.gov")],
        )
        await _age(session, old.id, 500)
        # A newer result, so the waived one is not protected by being latest.
        await record_result(
            session, test, status="fail", detail="newer", evaluated=1, failing=1,
            resources=[_f("accepted@acme.gov")],
        )
        await prune_resource_detail(session, retain_days=30)
        rows = await _resource_rows(session, test.id)
        assert any(r.waiver_id == w.id for r in rows), "the accepted row was pruned"


@pytest.mark.asyncio
async def test_no_control_test_result_is_ever_deleted() -> None:
    """The aggregate series is what an authorization package draws on."""
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        for i in range(3):
            res = await record_result(
                session, test, status="fail", detail=f"{i}", evaluated=1, failing=1,
                resources=[_f("a@acme.gov")],
            )
            await _age(session, res.id, 500 - i)
        await record_result(
            session, test, status="fail", detail="recent", evaluated=1, failing=1,
            resources=[_f("a@acme.gov")],
        )
        before = await _result_count(session, test.id)
        await prune_resource_detail(session, retain_days=30)
        assert await _result_count(session, test.id) == before == 4


@pytest.mark.asyncio
async def test_the_aggregate_counts_survive_the_prune() -> None:
    """Pruning detail must not touch evaluated/failing/waived on the result."""
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        old = await record_result(
            session, test, status="fail", detail="1", evaluated=47, failing=3,
            resources=[_f("a@acme.gov")],
        )
        await _age(session, old.id, 500)
        await record_result(
            session, test, status="fail", detail="2", evaluated=1, failing=1,
            resources=[_f("b@acme.gov")],
        )
        # Captured before expiring: reading old.id afterwards triggers a lazy
        # refresh and raises MissingGreenlet inside the async session.
        old_id = old.id
        await prune_resource_detail(session, retain_days=30)
        session.expire(old)
        kept = (
            await session.execute(select(ControlTestResult).where(ControlTestResult.id == old_id))
        ).scalar_one()
        assert (kept.evaluated, kept.failing, kept.status) == (47, 3, "fail")


@pytest.mark.asyncio
async def test_dry_run_deletes_nothing_and_reports_the_same_count() -> None:
    """An operator must be able to see the blast radius before committing."""
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        old = await record_result(
            session, test, status="fail", detail="1", evaluated=1, failing=1,
            resources=[_f("a@acme.gov"), _f("b@acme.gov")],
        )
        await _age(session, old.id, 500)
        await record_result(
            session, test, status="fail", detail="2", evaluated=1, failing=1,
            resources=[_f("a@acme.gov")],
        )
        dry = await prune_resource_detail(session, retain_days=30, dry_run=True)
        assert dry["deleted"] == 2
        assert dry["dry_run"] is True
        assert len(await _resource_rows(session, test.id)) == 3, "nothing was deleted"
        wet = await prune_resource_detail(session, retain_days=30)
        assert wet["deleted"] == dry["deleted"]
        assert len(await _resource_rows(session, test.id)) == 1


@pytest.mark.asyncio
async def test_pruning_twice_is_idempotent() -> None:
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        old = await record_result(
            session, test, status="fail", detail="1", evaluated=1, failing=1,
            resources=[_f("a@acme.gov")],
        )
        await _age(session, old.id, 500)
        await record_result(
            session, test, status="fail", detail="2", evaluated=1, failing=1,
            resources=[_f("a@acme.gov")],
        )
        first = await prune_resource_detail(session, retain_days=30)
        second = await prune_resource_detail(session, retain_days=30)
        assert first["deleted"] >= 1
        assert second["deleted"] == 0


@pytest.mark.asyncio
async def test_the_retain_days_default_comes_from_settings() -> None:
    """Calling with no window must not mean "delete everything"."""
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        old = await record_result(
            session, test, status="fail", detail="1", evaluated=1, failing=1,
            resources=[_f("a@acme.gov")],
        )
        # Just inside the configured default window.
        await _age(session, old.id, get_settings().posture_resource_retention_days - 5)
        await record_result(
            session, test, status="fail", detail="2", evaluated=1, failing=1,
            resources=[_f("a@acme.gov")],
        )
        out = await prune_resource_detail(session)
        assert out["retain_days"] == get_settings().posture_resource_retention_days
        assert len(await _resource_rows(session, test.id)) == 2


@pytest.mark.asyncio
async def test_a_zero_or_negative_window_is_refused() -> None:
    """retain_days=0 would delete every non-exempt row; that must be an
    explicit act, not a fat-fingered flag."""
    async with session_scope() as session:
        with pytest.raises(ValueError):
            await prune_resource_detail(session, retain_days=0)
        with pytest.raises(ValueError):
            await prune_resource_detail(session, retain_days=-1)
