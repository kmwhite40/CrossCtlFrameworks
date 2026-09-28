"""SSP scan synchronization read model."""

from __future__ import annotations

import itertools
from datetime import UTC, datetime

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import POAM, Organization, SSPControlEntry, SSPProject, System
from ccf.models_grc import ControlTest, ControlTestResult

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _seed() -> int:
    async with session_scope() as s:
        org = Organization(name=f"SSP Scan Sync Org {next(_SEQ)}")
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name=f"SSP Scan Sync Sys {next(_SEQ)}")
        s.add(system)
        await s.flush()
        project = SSPProject(
            organization_id=org.id,
            system_id=system.id,
            customer_name="SSP Scan Sync",
            platform="m365",
        )
        s.add(project)
        await s.flush()
        for order, control_id in enumerate(("AC-2", "AC-3", "IA-2", "AU-6"), start=1):
            s.add(
                SSPControlEntry(
                    project_id=project.id,
                    control_id=control_id,
                    nist_id=control_id,
                    domain=control_id.split("-", 1)[0],
                    requirement=f"{control_id} requirement",
                    sort_order=order,
                    implementation_status=["Implemented"],
                )
            )
        await s.flush()

        tests: dict[str, ControlTest] = {}
        for control_id, status, detail in (
            ("AC-2", "pass", "all users passed"),
            ("AC-3", "fail", "1 of 3 resources failing"),
            ("IA-2", "manual_review_required", "provider readiness blocked scan"),
        ):
            test = ControlTest(
                organization_id=org.id,
                system_id=system.id,
                control_id=control_id,
                name=f"{control_id} automated check",
                source="generated",
                check_key=f"check.{control_id}",
                connector_type="msgraph",
                expected=f"{control_id} expected state",
                last_status=status,
                last_tested_at=datetime(2026, 9, 27, tzinfo=UTC),
            )
            s.add(test)
            await s.flush()
            tests[control_id] = test
            s.add(
                ControlTestResult(
                    control_test_id=test.id,
                    status=status,
                    detail=detail,
                    expected=test.expected,
                    evidence_ref=f"scan://{control_id}" if status == "pass" else None,
                    evaluated=3 if status != "manual_review_required" else 0,
                    failing=1 if status == "fail" else 0,
                )
            )
        await s.flush()
        s.add(
            POAM(
                system_id=system.id,
                title="AC-3 automated finding",
                weakness="AC-3 failed automated scan",
                severity="high",
                status="open",
                source="control_test",
                source_ref=f"control_test:{tests['AC-3'].id}",
            )
        )
        await s.flush()
        return project.id


@pytest.mark.asyncio
async def test_ssp_scan_sync_summarizes_evidence_findings_and_manual_review() -> None:
    project_id = await _seed()

    async with _client() as c:
        r = await c.get(f"/api/ssp/projects/{project_id}/scan-sync")
    assert r.status_code == 200, r.text
    body = r.json()

    assert body["summary"] == {
        "controls": 4,
        "with_passing_evidence": 1,
        "with_open_findings": 1,
        "manual_review_required": 1,
        "ssp_blockers": 2,
    }
    rows = {row["control_id"]: row for row in body["controls"]}
    assert rows["AC-2"]["ssp_impact"] == "automated_evidence_available"
    assert rows["AC-2"]["passing_evidence"][0]["evidence_ref"] == "scan://AC-2"
    assert rows["AC-3"]["ssp_impact"] == "open_poam_or_finding"
    assert rows["AC-3"]["open_findings"][0]["poam"]["severity"] == "high"
    assert rows["IA-2"]["ssp_impact"] == "manual_evidence_required"
    assert rows["IA-2"]["manual_review_required"][0]["detail"] == (
        "provider readiness blocked scan"
    )
    assert rows["AU-6"]["ssp_impact"] == "no_scan_evidence"


@pytest.mark.asyncio
async def test_openapi_lists_ssp_scan_sync_route() -> None:
    async with _client() as c:
        paths = (await c.get("/openapi.json")).json()["paths"]
    assert "/api/ssp/projects/{project_id}/scan-sync" in paths
