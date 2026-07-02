"""DB-level integration tests for the GRC modules — register import round-trip,
insights rollups, and control-test result recording.

Complements the parse-layer tests in ``test_exporter.py`` and the page-render
tests in ``test_ui_grc_pages.py``. Each test scopes to a freshly created org so
it is independent of pre-existing data in the shared test DB.
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance import control_tests, exporter, insights
from ccf.models import POAM, Organization, Risk, System, Task
from ccf.models_grc import ControlTest, ControlTestResult

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
    sys = System(organization_id=org.id, name=f"{name} system")
    session.add(sys)
    await session.flush()
    return org.id, sys.id


@pytest.mark.asyncio
async def test_import_rows_round_trip_updates_and_creates() -> None:
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "ImportRT Org")
        existing = Risk(
            system_id=sys_id,
            title="Legacy risk",
            category="operational",
            likelihood="low",
            impact="low",
            treatment="mitigate",
            status="open",
        )
        s.add(existing)
        await s.flush()
        existing_id = existing.id

        # CSV updates the existing risk by id (raise the rating) and adds a new one.
        csv = (
            "id,title,category,likelihood,impact,treatment,status\n"
            f"{existing_id},Legacy risk,operational,high,high,mitigate,open\n"
            ",Fresh imported risk,technical,moderate,high,transfer,open\n"
        )
        summary = await exporter.import_rows(
            s, dataset="risks", content=csv.encode(), fmt="csv", org_id=org_id
        )
        assert summary["updated"] == 1
        assert summary["created"] == 1
        assert summary["skipped"] == 0

        rows = (
            await s.execute(select(Risk).where(Risk.system_id == sys_id).order_by(Risk.id))
        ).scalars().all()
        assert len(rows) == 2
        updated = next(r for r in rows if r.id == existing_id)
        # high x high must have recomputed to a higher inherent score than low x low.
        assert updated.likelihood == "high"
        assert updated.inherent_score is not None and updated.inherent_score >= 16
        created = next(r for r in rows if r.id != existing_id)
        assert created.title == "Fresh imported risk"
        assert created.system_id == sys_id  # linked to the org's system


@pytest.mark.asyncio
async def test_import_rows_skips_rows_missing_required_field() -> None:
    async with session_scope() as s:
        org_id, _ = await _make_org_system(s, "ImportSkip Org")
        csv = "title,name\n,Nameless policy\nValid Policy,\n"
        summary = await exporter.import_rows(
            s, dataset="policies", content=csv.encode(), fmt="csv", org_id=org_id
        )
        # policies require 'name'; row 1 has no name → skipped, row 2 has name → created.
        assert summary["created"] == 1
        assert summary["skipped"] == 1
        assert any("missing required" in e for e in summary["errors"])


@pytest.mark.asyncio
async def test_import_rejects_unknown_dataset() -> None:
    async with session_scope() as s:
        with pytest.raises(ValueError):
            await exporter.import_rows(
                s, dataset="widgets", content=b"[]", fmt="json", org_id=None
            )


@pytest.mark.asyncio
async def test_executive_and_data_quality_reflect_seeded_data() -> None:
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "Exec Org")
        # A system with no profile is a data-quality finding; an open POA&M with no
        # due date is another.
        s.add(POAM(system_id=sys_id, title="Ungoverned weakness", status="open", due_on=None))
        await s.flush()

        dq = await insights.data_quality(s, org_id=org_id)
        assert dq["total_issues"] >= 1
        assert "systems_without_profile" in {c["check"] for c in dq["checks"]}

        rollup = await insights.executive(s, org_id=org_id)
        for key in ("avg_sprs_score", "systems_total", "open_poams", "risk_by_residual_band"):
            assert key in rollup
        assert rollup["systems_total"] >= 1
        assert rollup["data_quality_issues"] == dq["total_issues"]


@pytest.mark.asyncio
async def test_record_result_fail_opens_alert_and_dedup_task() -> None:
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "CtlTest Org")
        test = ControlTest(
            organization_id=org_id,
            system_id=sys_id,
            control_id="AC.L2-3.1.1",
            name="Least privilege review",
            method="manual",
        )
        s.add(test)
        await s.flush()

        await control_tests.record_result(s, test, status="fail", detail="no evidence")
        await s.flush()

        assert test.last_status == "fail"
        assert test.last_tested_at is not None
        results = (
            await s.execute(
                select(ControlTestResult).where(ControlTestResult.control_test_id == test.id)
            )
        ).scalars().all()
        assert len(results) == 1 and results[0].status == "fail"

        dedupe = f"ctltest-fix:{test.id}"
        tasks = (
            await s.execute(select(Task).where(Task.dedupe_key == dedupe))
        ).scalars().all()
        assert len(tasks) == 1
        assert tasks[0].kind == "remediation" and tasks[0].priority == "high"

        # A second failure must not open a duplicate remediation task.
        await control_tests.record_result(s, test, status="fail", detail="still failing")
        await s.flush()
        tasks2 = (
            await s.execute(select(Task).where(Task.dedupe_key == dedupe))
        ).scalars().all()
        assert len(tasks2) == 1


@pytest.mark.asyncio
async def test_record_result_rejects_bad_status() -> None:
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "BadStatus Org")
        test = ControlTest(
            organization_id=org_id, system_id=sys_id, control_id="AC-1", name="x", method="manual"
        )
        s.add(test)
        await s.flush()
        with pytest.raises(ValueError):
            await control_tests.record_result(s, test, status="green")
