"""ConMon overdue controls and failed automated control tests must open
POA&Ms (not just Tasks/Notifications), idempotently.

Complements the pure-logic ``assess_health`` tests in ``test_governance.py``
and the Task/Notification integration tests in ``test_grc_integration.py``
with the POA&M side of both paths.
"""

from __future__ import annotations

from datetime import date, timedelta

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance import conmon, control_tests
from ccf.models import POAM, Control, ControlImplementation, Organization, System
from ccf.models_grc import ControlTest

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _make_org_system(session, name: str) -> tuple[int, int]:
    org = Organization(name=name)
    session.add(org)
    await session.flush()
    sysm = System(organization_id=org.id, name=f"{name} system")
    session.add(sysm)
    await session.flush()
    return org.id, sysm.id


async def _overdue_impl(session, sys_id: int, identifier: str) -> ControlImplementation:
    ctrl = Control(identifier=identifier, control_name="Test control")
    session.add(ctrl)
    await session.flush()
    impl = ControlImplementation(
        system_id=sys_id,
        control_id=ctrl.id,
        status="implemented",
        next_assessment_due=date.today() - timedelta(days=5),
    )
    session.add(impl)
    await session.flush()
    return impl


async def _open_poams(session, *, system_id: int, source: str) -> list[POAM]:
    rows = (
        await session.execute(
            select(POAM).where(POAM.system_id == system_id, POAM.source == source)
        )
    ).scalars().all()
    return list(rows)


# --- ConMon overdue control -> POA&M -----------------------------------------


@pytest.mark.asyncio
async def test_overdue_control_opens_conmon_poam() -> None:
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "ConmonPoam Org")
        impl = await _overdue_impl(s, sys_id, "AC-CONMON-1")
        control_id = impl.control_id

    async with session_scope() as s:
        result = await conmon.scan(s, today=date.today(), org_id=org_id)
        assert result["findings"] >= 1

    async with session_scope() as s:
        poams = await _open_poams(s, system_id=sys_id, source="conmon")
        assert len(poams) == 1
        p = poams[0]
        assert p.control_id == control_id
        assert p.status == "open"
        assert p.severity == "high"  # overdue -> high
        assert p.weakness and "assessment overdue" in p.weakness

    # Existing Task/Notification behaviour is preserved alongside the POA&M.
    from ccf.models import Notification, Task  # noqa: PLC0415

    async with session_scope() as s:
        tasks = (
            await s.execute(select(Task).where(Task.dedupe_key == f"conmon:impl:{impl.id}"))
        ).scalars().all()
        assert len(tasks) == 1
        notes = (
            await s.execute(
                select(Notification).where(Notification.dedupe_key == f"conmon:{impl.id}")
            )
        ).scalars().all()
        assert len(notes) == 1


@pytest.mark.asyncio
async def test_conmon_scan_does_not_duplicate_poam_across_runs() -> None:
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "ConmonDedupe Org")
        await _overdue_impl(s, sys_id, "AC-CONMON-2")

    async with session_scope() as s:
        await conmon.scan(s, today=date.today(), org_id=org_id)
    async with session_scope() as s:
        await conmon.scan(s, today=date.today() + timedelta(days=1), org_id=org_id)

    async with session_scope() as s:
        poams = await _open_poams(s, system_id=sys_id, source="conmon")
        assert len(poams) == 1  # still overdue on the second scan; no duplicate


@pytest.mark.asyncio
async def test_conmon_poam_reopens_if_prior_one_was_closed() -> None:
    """Closing the POA&M a human resolved must not block a fresh open on the
    next scan if the control is (still/again) overdue — dedupe is scoped to
    OPEN POA&Ms only."""
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "ConmonReopen Org")
        impl = await _overdue_impl(s, sys_id, "AC-CONMON-3")
        control_id = impl.control_id

    async with session_scope() as s:
        await conmon.scan(s, today=date.today(), org_id=org_id)

    async with session_scope() as s:
        poams = await _open_poams(s, system_id=sys_id, source="conmon")
        assert len(poams) == 1
        poams[0].status = "closed"
        poams[0].closed_on = date.today()

    async with session_scope() as s:
        await conmon.scan(s, today=date.today() + timedelta(days=1), org_id=org_id)

    async with session_scope() as s:
        rows = (
            await s.execute(
                select(POAM).where(POAM.system_id == sys_id, POAM.source == "conmon")
            )
        ).scalars().all()
        assert len(rows) == 2  # the closed one, plus a fresh open one
        open_rows = [p for p in rows if p.status == "open"]
        assert len(open_rows) == 1
        assert open_rows[0].control_id == control_id


# --- Failed automated control test -> POA&M ----------------------------------


async def _make_test(
    session, org_id: int, sys_id: int, control_id: str = "AC.L2-3.1.1"
) -> ControlTest:
    test = ControlTest(
        organization_id=org_id,
        system_id=sys_id,
        control_id=control_id,
        name="Least privilege review",
        method="manual",
    )
    session.add(test)
    await session.flush()
    return test


@pytest.mark.asyncio
async def test_failed_control_test_opens_poam() -> None:
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "CtlTestPoam Org")
        test = await _make_test(s, org_id, sys_id)
        test_id = test.id

    async with session_scope() as s:
        test = (await s.execute(select(ControlTest).where(ControlTest.id == test_id))).scalar_one()
        await control_tests.record_result(s, test, status="fail", detail="no evidence on file")

    async with session_scope() as s:
        poams = await _open_poams(s, system_id=sys_id, source="control_test")
        assert len(poams) == 1
        p = poams[0]
        assert p.status == "open"
        assert p.severity == "high"
        assert p.source_ref == f"control_test:{test_id}"
        assert "no evidence on file" in (p.weakness or "")

    # Existing remediation Task is preserved alongside the POA&M.
    from ccf.models import Task  # noqa: PLC0415

    async with session_scope() as s:
        tasks = (
            await s.execute(select(Task).where(Task.dedupe_key == f"ctltest-fix:{test_id}"))
        ).scalars().all()
        assert len(tasks) == 1


@pytest.mark.asyncio
async def test_failing_control_test_does_not_duplicate_poam_across_runs() -> None:
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "CtlTestDedupe Org")
        test = await _make_test(s, org_id, sys_id, control_id="AC.L2-3.1.2")
        test_id = test.id

    async with session_scope() as s:
        test = (await s.execute(select(ControlTest).where(ControlTest.id == test_id))).scalar_one()
        await control_tests.record_result(s, test, status="fail", detail="first failure")

    async with session_scope() as s:
        test = (await s.execute(select(ControlTest).where(ControlTest.id == test_id))).scalar_one()
        await control_tests.record_result(s, test, status="fail", detail="still failing")

    async with session_scope() as s:
        poams = await _open_poams(s, system_id=sys_id, source="control_test")
        assert len(poams) == 1
        assert "still failing" in (poams[0].weakness or "")  # refreshed, not duplicated


@pytest.mark.asyncio
async def test_control_test_warn_does_not_open_poam() -> None:
    """Only fail (not warn) opens a POA&M — matches the existing remediation
    Task guard, which only fires on fail."""
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "CtlTestWarn Org")
        test = await _make_test(s, org_id, sys_id, control_id="AC.L2-3.1.3")
        test_id = test.id

    async with session_scope() as s:
        test = (await s.execute(select(ControlTest).where(ControlTest.id == test_id))).scalar_one()
        await control_tests.record_result(s, test, status="warn", detail="stale evidence")

    async with session_scope() as s:
        poams = await _open_poams(s, system_id=sys_id, source="control_test")
        assert poams == []


@pytest.mark.asyncio
async def test_failed_control_test_poam_dedupe_scoped_to_system() -> None:
    """The dedupe lookup must also match on system_id — defense-in-depth
    consistency with ``conmon._upsert_poam`` — so a POA&M that happens to share
    this test's ``source_ref`` but belongs to a DIFFERENT system is never
    silently reused/mutated by this test's run."""
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "CtlTestSysScope Org")
        _, other_sys_id = await _make_org_system(s, "CtlTestSysScope Other Org")
        test = await _make_test(s, org_id, sys_id, control_id="AC.L2-3.1.9")
        test_id = test.id
        # A POA&M under the SAME source_ref but a DIFFERENT system_id — e.g. a
        # data anomaly, or the test having been re-pointed to a new system
        # since that POA&M was opened. It must never be matched by this run.
        stray = POAM(
            system_id=other_sys_id,
            title="stray",
            weakness="stray weakness",
            severity="high",
            status="open",
            source="control_test",
            source_ref=f"control_test:{test_id}",
        )
        s.add(stray)
        await s.flush()
        stray_id = stray.id

    async with session_scope() as s:
        test = (await s.execute(select(ControlTest).where(ControlTest.id == test_id))).scalar_one()
        await control_tests.record_result(s, test, status="fail", detail="scoped failure")

    async with session_scope() as s:
        # The stray POA&M (wrong system) must be untouched.
        stray = (await s.execute(select(POAM).where(POAM.id == stray_id))).scalar_one()
        assert stray.weakness == "stray weakness"
        # A new POA&M must exist for the test's actual system instead.
        poams = await _open_poams(s, system_id=sys_id, source="control_test")
        assert len(poams) == 1
        assert "scoped failure" in (poams[0].weakness or "")


@pytest.mark.asyncio
async def test_control_test_poam_best_effort_links_catalog_control() -> None:
    """When the test's control id matches a row in the org's Control catalog,
    the POA&M links to it (nullable FK) instead of leaving it unset."""
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "CtlTestCatalog Org")
        ctrl = Control(identifier="AC-CATALOG-1", control_name="Catalog control")
        s.add(ctrl)
        await s.flush()
        catalog_control_id = ctrl.id
        test = await _make_test(s, org_id, sys_id, control_id="AC-CATALOG-1")
        test_id = test.id

    async with session_scope() as s:
        test = (await s.execute(select(ControlTest).where(ControlTest.id == test_id))).scalar_one()
        await control_tests.record_result(s, test, status="fail", detail="drifted")

    async with session_scope() as s:
        poams = await _open_poams(s, system_id=sys_id, source="control_test")
        assert len(poams) == 1
        assert poams[0].control_id == catalog_control_id
