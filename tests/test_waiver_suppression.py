"""Suppression: an accepted finding stops the consequence, not the evidence."""

from __future__ import annotations

import itertools
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

import ccf.governance.control_tests as ct
from ccf.db import session_scope
from ccf.governance.control_tests import record_result
from ccf.governance.waivers import Coverage
from ccf.models import POAM, Notification, Organization, System, Task
from ccf.models_grc import ControlTest, ControlTestResourceResult, ControlTestResult
from ccf.models_waivers import Waiver
from ccf.posture.scan import effective_verdict
from ccf.posture.types import ResourceFinding

_SEQ = itertools.count()
TODAY = datetime.now(UTC).date()


def _findings(*ids: str, verdict: str = "fail") -> list[ResourceFinding]:
    return [
        ResourceFinding(resource_id=i, resource_type="entra_user", verdict=verdict, observed="o")
        for i in ids
    ]


async def _fixture(session, *, check_key: str = "m365.identity.mfa_registered"):
    org = Organization(name=f"SuppOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"SuppSys-{next(_SEQ)}")
    session.add(sys_)
    await session.flush()
    test = ControlTest(
        organization_id=org.id,
        system_id=sys_.id,
        control_id="IA-2",
        name="MFA registered",
        method="connector",
        check_key=check_key,
    )
    session.add(test)
    await session.flush()
    return org, sys_, test


async def _waive(session, org, sys_, **kw) -> Waiver:
    base = dict(
        organization_id=org.id,
        system_id=sys_.id,
        check_key="m365.identity.mfa_registered",
        rationale="Accepted by the AO; compensating control documented.",
        status="approved",
    )
    base.update(kw)
    w = Waiver(**base)
    session.add(w)
    await session.flush()
    return w


async def _counts(session, org, sys_) -> tuple[int, int, int]:
    notifications = (
        await session.execute(
            select(func.count()).select_from(Notification).where(
                Notification.organization_id == org.id
            )
        )
    ).scalar_one()
    tasks = (
        await session.execute(
            select(func.count()).select_from(Task).where(Task.organization_id == org.id)
        )
    ).scalar_one()
    poams = (
        await session.execute(
            select(func.count()).select_from(POAM).where(POAM.system_id == sys_.id)
        )
    ).scalar_one()
    return notifications, tasks, poams


# ── the positive control, without which every absence below is vacuous ───────


async def test_an_unwaived_failure_alerts_and_opens_a_poam() -> None:
    """Without this, "no notification" is satisfied by a fixture that never
    alerts at all."""
    async with session_scope() as session:
        org, sys_, test = await _fixture(session)
        await record_result(
            session, test, status="fail", detail="2 failing",
            evaluated=2, failing=2, resources=_findings("res-0", "res-1"),
        )
        assert await _counts(session, org, sys_) == (1, 1, 1)


# ── suppression ──────────────────────────────────────────────────────────────


async def test_a_waived_failure_alerts_nothing_and_opens_no_poam() -> None:
    async with session_scope() as session:
        org, sys_, test = await _fixture(session)
        await _waive(session, org, sys_)
        await record_result(
            session, test, status="fail", detail="2 failing",
            evaluated=2, failing=2, resources=_findings("res-0", "res-1"),
        )
        assert await _counts(session, org, sys_) == (0, 0, 0)


async def test_a_waived_failure_still_records_the_finding_unchanged() -> None:
    """The invariant, asserted field by field."""
    async with session_scope() as session:
        org, sys_, test = await _fixture(session)
        w = await _waive(session, org, sys_)
        res = await record_result(
            session, test, status="fail", detail="2 failing",
            evaluated=2, failing=2, resources=_findings("res-0", "res-1"),
        )
        assert res.status == "fail", "a waiver must not rewrite the verdict"
        assert res.failing == 2
        assert res.waived == 2

        rows = (
            await session.execute(
                select(ControlTestResourceResult).where(
                    ControlTestResourceResult.result_id == res.id
                )
            )
        ).scalars().all()
        assert {r.resource_id for r in rows} == {"res-0", "res-1"}
        assert {r.verdict for r in rows} == {"fail"}
        assert {r.waiver_id for r in rows} == {w.id}

        assert test.last_status == "fail"
        assert test.last_tested_at is not None

        verdict = await effective_verdict(session, system_id=sys_.id, control_id="IA-2")
        assert verdict["verdict"] == "fail", "a waiver must not make a failure read as pass"


async def test_a_partially_waived_failure_still_alerts() -> None:
    async with session_scope() as session:
        org, sys_, test = await _fixture(session)
        await _waive(session, org, sys_, resource_id="res-0")
        res = await record_result(
            session, test, status="fail", detail="2 failing",
            evaluated=2, failing=2, resources=_findings("res-0", "res-1"),
        )
        notifications, tasks, poams = await _counts(session, org, sys_)
        assert notifications == 1
        assert tasks == 1
        assert poams == 1
        assert res.waived == 1, "the accepted resource is still recorded as accepted"


async def test_a_requested_waiver_does_not_suppress() -> None:
    async with session_scope() as session:
        org, sys_, test = await _fixture(session)
        await _waive(session, org, sys_, status="requested")
        await record_result(
            session, test, status="fail", detail="1 failing",
            evaluated=1, failing=1, resources=_findings("res-0"),
        )
        assert await _counts(session, org, sys_) == (1, 1, 1)


async def test_an_expired_waiver_lets_the_alert_fire_again() -> None:
    """No action taken -- only the clock moved."""
    async with session_scope() as session:
        org, sys_, test = await _fixture(session)
        await _waive(session, org, sys_, expires_on=TODAY - timedelta(days=1))
        await record_result(
            session, test, status="fail", detail="1 failing",
            evaluated=1, failing=1, resources=_findings("res-0"),
        )
        notifications, _tasks, poams = await _counts(session, org, sys_)
        assert notifications == 1
        assert poams == 1


async def test_a_waiver_expiring_today_still_suppresses() -> None:
    async with session_scope() as session:
        org, sys_, test = await _fixture(session)
        await _waive(session, org, sys_, expires_on=TODAY)
        await record_result(
            session, test, status="fail", detail="1 failing",
            evaluated=1, failing=1, resources=_findings("res-0"),
        )
        assert await _counts(session, org, sys_) == (0, 0, 0)


async def test_a_warn_is_suppressed_too() -> None:
    async with session_scope() as session:
        org, sys_, test = await _fixture(session)
        await _waive(session, org, sys_)
        await record_result(
            session, test, status="warn", detail="1 warning",
            evaluated=1, failing=0, resources=_findings("res-0", verdict="warn"),
        )
        assert await _counts(session, org, sys_) == (0, 0, 0)


async def test_a_resourceless_failure_is_suppressed_by_a_whole_check_waiver() -> None:
    """A manual test records no resources; the whole-check shape still covers it."""
    async with session_scope() as session:
        org, sys_, test = await _fixture(session)
        await _waive(session, org, sys_)
        await record_result(session, test, status="fail", detail="manual failure")
        assert await _counts(session, org, sys_) == (0, 0, 0)


async def test_a_resourceless_failure_is_not_suppressed_by_a_resource_waiver() -> None:
    """Nothing proves the waived resource was the failing one."""
    async with session_scope() as session:
        org, sys_, test = await _fixture(session)
        await _waive(session, org, sys_, resource_id="res-0")
        await record_result(session, test, status="fail", detail="manual failure")
        assert await _counts(session, org, sys_) == (1, 1, 1)


# ── what a waiver must not do ────────────────────────────────────────────────


async def test_a_waiver_does_not_close_an_existing_poam() -> None:
    """Fail, then waive, then fail again: the POA&M stays open, undoubled."""
    async with session_scope() as session:
        org, sys_, test = await _fixture(session)
        await record_result(
            session, test, status="fail", detail="first failure",
            evaluated=1, failing=1, resources=_findings("res-0"),
        )
        _n, _t, poams_before = await _counts(session, org, sys_)
        assert poams_before == 1

        await _waive(session, org, sys_)
        await record_result(
            session, test, status="fail", detail="second failure",
            evaluated=1, failing=1, resources=_findings("res-0"),
        )
        poam = (
            await session.execute(select(POAM).where(POAM.system_id == sys_.id))
        ).scalar_one()
        assert poam.status == "open", "an acceptance must not erase an outstanding weakness"
        assert "first failure" in poam.weakness, "nor silently refresh it"


async def test_a_waived_failure_is_not_treated_as_a_recovery() -> None:
    """A waived fail must take neither the alert branch nor the recovery one."""
    async with session_scope() as session:
        org, sys_, test = await _fixture(session)
        await record_result(
            session, test, status="fail", detail="first",
            evaluated=1, failing=1, resources=_findings("res-0"),
        )
        await _waive(session, org, sys_)
        await record_result(
            session, test, status="fail", detail="second",
            evaluated=1, failing=1, resources=_findings("res-0"),
        )
        poam = (
            await session.execute(select(POAM).where(POAM.system_id == sys_.id))
        ).scalar_one()
        assert poam.status == "open"
        assert test.last_status == "fail"
        # The property actually at risk: recovery resolves the remediation
        # task, and a waived failure is not a recovery. Nothing was fixed --
        # the finding was accepted -- so the task a human still owns must stay
        # open. (The elif-vs-if mutation was equivalent; this is not.)
        task = (
            await session.execute(select(Task).where(Task.organization_id == org.id))
        ).scalar_one()
        assert task.status == "open"


async def test_the_recovery_path_still_works_unchanged() -> None:
    """A genuine fix must still resolve the remediation task.

    It does NOT close the POA&M, and asserting that it did was wrong:
    _resolve_on_recovery deliberately leaves the POA&M open, because closing
    one asserts in an authorization package that a weakness is remediated and
    a single passing test is one observation, not that assertion. What recovery
    owns is the Task.
    """
    async with session_scope() as session:
        org, _sys, test = await _fixture(session)
        await record_result(
            session, test, status="fail", detail="failing",
            evaluated=1, failing=1, resources=_findings("res-0"),
        )
        await record_result(
            session, test, status="pass", detail="fixed",
            evaluated=1, failing=0, resources=_findings("res-0", verdict="pass"),
        )
        task = (
            await session.execute(select(Task).where(Task.organization_id == org.id))
        ).scalar_one()
        assert task.status == "done"
        assert test.last_status == "pass"


async def test_a_waiver_for_another_check_does_not_suppress() -> None:
    async with session_scope() as session:
        org, sys_, test = await _fixture(session)
        await _waive(session, org, sys_, check_key="some.other.check")
        await record_result(
            session, test, status="fail", detail="failing",
            evaluated=1, failing=1, resources=_findings("res-0"),
        )
        assert await _counts(session, org, sys_) == (1, 1, 1)


async def test_an_unwaived_result_records_waived_zero() -> None:
    async with session_scope() as session:
        _org, _sys, test = await _fixture(session)
        res = await record_result(
            session, test, status="fail", detail="failing",
            evaluated=1, failing=1, resources=_findings("res-0"),
        )
        assert res.waived == 0
        rows = (
            await session.execute(
                select(ControlTestResourceResult).where(
                    ControlTestResourceResult.result_id == res.id
                )
            )
        ).scalars().all()
        assert [r.waiver_id for r in rows] == [None]


# ── IMPORTANT 2: a bug in waiver logic must not cost the recorded finding ────


async def test_a_bug_in_waiver_lookup_does_not_cost_the_recorded_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """record_result never commits -- the caller owns the transaction -- so an
    unguarded exception from the waiver block would propagate out and the
    caller would roll back everything, including the already-flushed result
    and resource rows. Simulate a bug in waivers_for_test and confirm three
    things: (1) record_result does not raise, (2) it fails closed -- nothing
    is suppressed, the alert fires as if no waiver existed, and (3) the
    result actually survives the caller's eventual commit (session_scope's
    own commit on exit) rather than the transaction being left aborted by a
    flush-time failure the try/except alone wouldn't have caught."""
    monkeypatch.setattr(ct, "waivers_for_test", _boom)

    async with session_scope() as session:
        org, sys_, test = await _fixture(session)
        await _waive(session, org, sys_)  # would have suppressed, had it been reached
        res = await record_result(
            session, test, status="fail", detail="2 failing",
            evaluated=2, failing=2, resources=_findings("res-0", "res-1"),
        )
        assert res.waived == 0, "failed closed: nothing was suppressed"
        notifications, tasks, poams = await _counts(session, org, sys_)
        assert (notifications, tasks, poams) == (1, 1, 1), "the alert fired normally"
        result_id = res.id

    # session_scope committed without raising on the way out of the block
    # above -- if the waiver block's failure had left the transaction
    # aborted, that commit (or a query afterward) would have raised instead.
    async with session_scope() as session:
        reloaded = (
            await session.execute(
                select(ControlTestResult).where(ControlTestResult.id == result_id)
            )
        ).scalar_one()
        assert reloaded.status == "fail"
        assert reloaded.failing == 2
        rows = (
            await session.execute(
                select(ControlTestResourceResult).where(
                    ControlTestResourceResult.result_id == result_id
                )
            )
        ).scalars().all()
        assert {r.resource_id for r in rows} == {"res-0", "res-1"}


async def _boom(*_args: object, **_kwargs: object) -> list[Waiver]:
    raise RuntimeError("simulated bug in waiver logic")


async def test_a_flush_time_bug_in_waiver_logic_does_not_poison_the_transaction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unlike the lookup-time bug above, this fails INSIDE the flush itself:
    ``cover()`` is made to attribute a finding to a waiver id that does not
    exist, which raises an IntegrityError (FK violation) when
    ``row.waiver_id`` is flushed. A bare try/except around a bare flush would
    not be enough to satisfy the "no bug costs the recorded finding"
    guarantee here: ``AsyncSession.rollback()`` is not savepoint-scoped, so
    an aborted flush would leave the *outer* Postgres transaction aborted and
    the caller's eventual commit would fail anyway -- still costing the
    finding despite record_result itself not raising. The SAVEPOINT
    (``session.begin_nested()``) is what actually prevents that."""

    def _bad_cover(*_a: object, **_kw: object) -> Coverage:
        return Coverage(suppress=True, waived=1, by_resource={"res-0": 999_999_999})

    monkeypatch.setattr(ct, "cover", _bad_cover)

    async with session_scope() as session:
        org, sys_, test = await _fixture(session)
        await _waive(session, org, sys_)
        res = await record_result(
            session, test, status="fail", detail="1 failing",
            evaluated=1, failing=1, resources=_findings("res-0"),
        )
        # The SAVEPOINT rollback expires res's attributes touched inside it
        # (waived was set there before the flush failed) -- refresh to read
        # them back rather than asserting on stale in-Python state.
        await session.refresh(res)
        assert res.waived == 0, "failed closed despite the bad waiver id"
        notifications, tasks, poams = await _counts(session, org, sys_)
        assert (notifications, tasks, poams) == (1, 1, 1)
        result_id = res.id

    # As above: this commit (session_scope's, on exit of the block above)
    # having already succeeded is half the proof; re-reading confirms the
    # result really is there, not just that no exception happened to surface.
    async with session_scope() as session:
        reloaded = (
            await session.execute(
                select(ControlTestResult).where(ControlTestResult.id == result_id)
            )
        ).scalar_one()
        assert reloaded.status == "fail"
        assert reloaded.failing == 1
        assert reloaded.waived == 0


async def test_a_passing_result_is_unaffected_by_a_waiver() -> None:
    async with session_scope() as session:
        org, sys_, test = await _fixture(session)
        await _waive(session, org, sys_)
        res = await record_result(
            session, test, status="pass", detail="all good",
            evaluated=1, failing=0, resources=_findings("res-0", verdict="pass"),
        )
        assert res.waived == 0
        assert await _counts(session, org, sys_) == (0, 0, 0)
