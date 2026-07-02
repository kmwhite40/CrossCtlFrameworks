"""DB-level integration tests for the GRC modules — register import round-trip,
insights rollups, and control-test result recording.

Complements the parse-layer tests in ``test_exporter.py`` and the page-render
tests in ``test_ui_grc_pages.py``. Each test scopes to a freshly created org so
it is independent of pre-existing data in the shared test DB.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance import control_tests, digest, exporter, insights
from ccf.models import POAM, Notification, Organization, Risk, System, Task
from ccf.models_grc import (
    AuditEngagement,
    AuditRequest,
    ConnectorConfig,
    ControlTest,
    ControlTestResult,
    RegulatoryUpdate,
    TrustAccessRequest,
)

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
async def test_run_due_auto_evaluates_connector_backed_test() -> None:
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "AutoRun Org")
        s.add(
            ConnectorConfig(
                organization_id=org_id,
                name="Prod AWS GovCloud",
                connector_type="aws_govcloud",
                status="configured",
                last_sync=datetime.now(UTC),
                objects_discovered=290,
            )
        )
        test = ControlTest(
            organization_id=org_id,
            system_id=sys_id,
            control_id="AC.L2-3.1.5",
            name="IAM least-privilege sync",
            method="connector",
            connector_type="aws_govcloud",
            frequency="daily",
            active=True,
            last_tested_at=datetime.now(UTC) - timedelta(days=3),  # overdue
        )
        s.add(test)
        await s.flush()

        counts = await control_tests.run_due(s, today=datetime.now(UTC).date())
        assert counts["evaluated"] >= 1
        await s.refresh(test)
        assert test.last_status == "pass"  # configured + fresh + objects>0
        results = (
            await s.execute(
                select(ControlTestResult).where(ControlTestResult.control_test_id == test.id)
            )
        ).scalars().all()
        assert len(results) == 1 and results[0].status == "pass"


@pytest.mark.asyncio
async def test_digest_flags_overdue_regulatory_and_audit() -> None:
    async with session_scope() as s:
        org_id, _ = await _make_org_system(s, "Digest Org")
        today = datetime.now(UTC).date()
        s.add(
            RegulatoryUpdate(
                organization_id=org_id,
                title="Overdue reg change",
                framework_impacted="NIST 800-171",
                status="assessing",
                due_on=today - timedelta(days=5),
            )
        )
        eng = AuditEngagement(organization_id=org_id, name="C3PAO CMMC L2")
        s.add(eng)
        await s.flush()
        s.add(
            AuditRequest(
                engagement_id=eng.id,
                title="Provide access-control policy",
                status="open",
                due_on=today - timedelta(days=3),
            )
        )
        await s.flush()

        counts = await digest.run(s, today=today, org_id=org_id)
        assert counts["regulatory"] >= 1
        assert counts["audit"] >= 1

        cats = {
            n.category
            for n in (
                await s.execute(
                    select(Notification).where(Notification.organization_id == org_id)
                )
            ).scalars().all()
        }
        assert "regulatory" in cats
        assert "audit" in cats


@pytest.mark.asyncio
async def test_connector_and_control_test_detail_pages_render() -> None:
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "Detail Pages Org")
        conn = ConnectorConfig(
            organization_id=org_id,
            name="Prod AWS GovCloud",
            connector_type="aws_govcloud",
            status="configured",
            objects_discovered=290,
            evidence_produced=29,
        )
        s.add(conn)
        test = ControlTest(
            organization_id=org_id,
            system_id=sys_id,
            control_id="AC.L2-3.1.7",
            name="Detail render test",
            method="manual",
        )
        s.add(test)
        await s.flush()
        conn_id, test_id = conn.id, test.id
        await control_tests.record_result(s, test, status="fail", detail="drift detected")

    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        r_conn = await client.get(f"/connectors/{conn_id}")
        assert r_conn.status_code == 200
        assert "Prod AWS GovCloud" in r_conn.text and "Objects discovered" in r_conn.text

        r_test = await client.get(f"/control-tests/{test_id}")
        assert r_test.status_code == 200
        assert "Detail render test" in r_test.text and "drift detected" in r_test.text

        assert (await client.get("/connectors/999999")).status_code == 404
        assert (await client.get("/control-tests/999999")).status_code == 404


@pytest.mark.asyncio
async def test_trust_and_regulatory_form_workflows() -> None:
    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://t", follow_redirects=False) as c:
        # Trust access request: create → approve.
        r = await c.post(
            "/trust/access-requests",
            data={"requester_name": "Jane Auditor", "company": "C3PAO LLC"},
        )
        assert r.status_code == 303

        # Regulatory: create → advance disposition.
        r = await c.post(
            "/regulatory", data={"title": "NIST 800-171 Rev 3", "status": "new"}
        )
        assert r.status_code == 303

    async with session_scope() as s:
        ar = (
            await s.execute(
                select(TrustAccessRequest).where(
                    TrustAccessRequest.requester_name == "Jane Auditor"
                )
            )
        ).scalars().first()
        assert ar is not None and ar.status == "pending"
        upd = (
            await s.execute(
                select(RegulatoryUpdate).where(RegulatoryUpdate.title == "NIST 800-171 Rev 3")
            )
        ).scalars().first()
        assert upd is not None
        ar_id, upd_id = ar.id, upd.id

    async with AsyncClient(transport=transport, base_url="http://t", follow_redirects=False) as c:
        assert (
            await c.post(f"/trust/access-requests/{ar_id}/decide", data={"approve": "1"})
        ).status_code == 303
        assert (
            await c.post(
                f"/regulatory/{upd_id}/update",
                data={"applicability": "applicable", "status": "in_progress", "owner": "Kevin"},
            )
        ).status_code == 303

    async with session_scope() as s:
        ar = await s.get(TrustAccessRequest, ar_id)
        upd = await s.get(RegulatoryUpdate, upd_id)
        assert ar.status == "approved" and ar.decided_at is not None
        assert upd.applicability == "applicable"
        assert upd.status == "in_progress"
        assert upd.owner == "Kevin"


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
