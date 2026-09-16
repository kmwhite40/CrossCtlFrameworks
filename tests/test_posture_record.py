"""record_result stays the only writer -- widened, not duplicated."""

from __future__ import annotations

import itertools

import pytest
from sqlalchemy import select

from ccf.db import session_scope
from ccf.governance.control_tests import record_result
from ccf.models import POAM, Organization, System, Task
from ccf.models_grc import ControlTest, ControlTestResourceResult
from ccf.posture.checks import ResourceFinding

_SEQ = itertools.count()


async def _test_row(session) -> ControlTest:
    org = Organization(name=f"RecOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"RecSys-{next(_SEQ)}")
    session.add(sys_)
    await session.flush()
    t = ControlTest(
        organization_id=org.id,
        system_id=sys_.id,
        control_id="AC-3",
        name="demo",
        method="connector",
    )
    session.add(t)
    await session.flush()
    return t


async def test_records_resource_findings() -> None:
    async with session_scope() as session:
        t = await _test_row(session)
        res = await record_result(
            session,
            t,
            status="fail",
            evaluated=3,
            failing=1,
            expected="public access blocked",
            resources=(
                ResourceFinding("b1", "s3_bucket", "pass", "blocked"),
                ResourceFinding("b2", "s3_bucket", "fail", "open"),
                ResourceFinding("b3", "s3_bucket", "pass", "blocked"),
            ),
        )
        assert res.evaluated == 3
        assert res.failing == 1
        assert res.expected == "public access blocked"
        rows = (
            await session.execute(
                select(ControlTestResourceResult).where(
                    ControlTestResourceResult.result_id == res.id
                )
            )
        ).scalars().all()
        assert len(rows) == 3
        assert {r.verdict for r in rows} == {"pass", "fail"}


async def test_accepts_the_widened_vocabulary() -> None:
    async with session_scope() as session:
        t = await _test_row(session)
        res = await record_result(
            session, t, status="not_applicable", detail="nothing in scope"
        )
        assert res.status == "not_applicable"
        assert t.last_status == "not_applicable"


async def test_rejects_a_verdict_outside_the_vocabulary() -> None:
    async with session_scope() as session:
        t = await _test_row(session)
        with pytest.raises(ValueError, match="status must be one of"):
            await record_result(session, t, status="nonsense")


async def test_legacy_call_without_resources_is_unchanged() -> None:
    """Existing callers pass no resource data and must behave exactly as before."""
    async with session_scope() as session:
        t = await _test_row(session)
        res = await record_result(session, t, status="pass", detail="all good")
        assert res.status == "pass"
        assert res.evaluated == 0
        assert res.failing == 0
        assert res.expected is None
        rows = (
            await session.execute(
                select(ControlTestResourceResult).where(
                    ControlTestResourceResult.result_id == res.id
                )
            )
        ).scalars().all()
        assert rows == []


async def test_recovery_still_fires_on_fail_then_pass() -> None:
    """The existing recovery loop must keep working through the widened
    writer -- proven by the actual POA&M/Task transition record_result's
    recovery branch makes, not merely by ``last_status`` (which record_result
    sets unconditionally, before the recovery branch even runs, so it can
    never distinguish "recovery fired" from "recovery was skipped/deleted").
    """
    async with session_scope() as session:
        t = await _test_row(session)
        await record_result(session, t, status="fail", detail="broken")
        assert t.last_status == "fail"

        dedupe = f"ctltest-fix:{t.id}"
        source_ref = f"control_test:{t.id}"
        task = (
            await session.execute(select(Task).where(Task.dedupe_key == dedupe))
        ).scalar_one()
        assert task.status == "open"
        poam = (
            await session.execute(
                select(POAM).where(POAM.system_id == t.system_id, POAM.source_ref == source_ref)
            )
        ).scalar_one()
        assert poam.status == "open"

        await record_result(session, t, status="pass", detail="fixed")
        assert t.last_status == "pass"

        await session.refresh(task)
        assert task.status == "done", "recovery must resolve the remediation Task"
        await session.refresh(poam)
        assert poam.status == "open", "recovery surfaces, never auto-closes, the POA&M"
        assert poam.remediation_plan is not None and "now passes" in poam.remediation_plan


async def test_not_applicable_is_not_treated_as_a_recovery() -> None:
    """Only `pass` clears a failure. not_applicable asserts nothing was in
    scope, which is not evidence the weakness cleared -- proven by asserting
    recovery did NOT run (the Task/POA&M opened by the fail stay open),
    not merely by ``last_status``."""
    async with session_scope() as session:
        t = await _test_row(session)
        await record_result(session, t, status="fail", detail="broken")
        res = await record_result(session, t, status="not_applicable", detail="none in scope")
        assert res.status == "not_applicable"
        assert t.last_status == "not_applicable"

        dedupe = f"ctltest-fix:{t.id}"
        source_ref = f"control_test:{t.id}"
        task = (
            await session.execute(select(Task).where(Task.dedupe_key == dedupe))
        ).scalar_one()
        assert task.status == "open", "not_applicable must not resolve the remediation Task"
        poam = (
            await session.execute(
                select(POAM).where(POAM.system_id == t.system_id, POAM.source_ref == source_ref)
            )
        ).scalar_one()
        assert poam.remediation_plan is None, "not_applicable must not annotate the POA&M"


async def test_long_resource_ids_are_truncated_not_rejected() -> None:
    """An over-long ARN must not fail the whole run."""
    async with session_scope() as session:
        t = await _test_row(session)
        res = await record_result(
            session,
            t,
            status="fail",
            resources=(ResourceFinding("x" * 900, "s3_bucket", "fail", "open"),),
        )
        row = (
            await session.execute(
                select(ControlTestResourceResult).where(
                    ControlTestResourceResult.result_id == res.id
                )
            )
        ).scalars().one()
        assert len(row.resource_id) == 512
