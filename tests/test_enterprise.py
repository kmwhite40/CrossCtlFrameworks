"""Integration tests for the enterprise layer: posture, audit trail, OSCAL SSP."""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, ScoringStatus, System

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _fresh_system(name: str = "PostureSys") -> int:
    async with session_scope() as s:
        org = (
            await s.execute(select(Organization).where(Organization.name == "PostureOrg"))
        ).scalar_one_or_none()
        if org is None:
            org = Organization(name="PostureOrg")
            s.add(org)
            await s.flush()
        sys = (
            await s.execute(
                select(System).where(System.organization_id == org.id, System.name == name)
            )
        ).scalar_one_or_none()
        if sys is None:
            sys = System(organization_id=org.id, name=name, baseline="moderate")
            s.add(sys)
            await s.flush()
        await s.execute(delete(ScoringStatus).where(ScoringStatus.system_id == sys.id))
        return sys.id


@pytest.mark.asyncio
async def test_posture_summary_reflects_live_sprs() -> None:
    async with _client() as c:
        await c.post("/api/scoring/seed")
        sid = await _fresh_system()
        matrix = (await c.get(f"/api/scoring/systems/{sid}/matrix")).json()
        for row in matrix["controls"]:
            await c.put(
                f"/api/scoring/systems/{sid}/controls/{row['control_id']}",
                json={"state": "implemented"},
            )

        summary = (await c.get("/api/posture/summary")).json()
        assert summary["systems_total"] >= 1
        assert summary["avg_sprs_score"] is not None
        # The fully-implemented system should score 110 and surface in the scorecard.
        card = next(c for c in summary["systems"] if c["system_id"] == sid)
        assert card["sprs_score"] == 110
        assert card["controls_assessed"] == 110
        assert set(summary["evidence"]) >= {"fresh", "expiring_soon", "expired"}
        assert set(summary["poam_aging"]["buckets"]) == {
            "0-30",
            "31-60",
            "61-90",
            "90+",
            "unknown",
        }


@pytest.mark.asyncio
async def test_audit_trail_records_mutations() -> None:
    async with _client() as c:
        r = await c.post(
            "/api/ssp/projects",
            json={"customer_name": "AuditCo"},
            headers={"X-Actor": "tester@example.com"},
        )
        assert r.status_code == 201
        # The mutation is the most recent audit entry, attributed to the actor.
        latest = (await c.get("/api/audit")).json()[0]
        assert latest["actor"] == "tester@example.com"
        assert latest["action"] == "create"
        assert latest["entity_type"] == "ssp"
        assert latest["diff"]["method"] == "POST"
        assert latest["diff"]["path"] == "/api/ssp/projects"

        # Read requests are never audited — the latest entry is unchanged after a GET.
        await c.get("/api/posture/summary")
        assert (await c.get("/api/audit")).json()[0]["diff"]["path"] == "/api/ssp/projects"


@pytest.mark.asyncio
async def test_oscal_ssp_export_shape() -> None:
    async with _client() as c:
        await c.post("/api/scoring/seed")
        pid = (
            await c.post(
                "/api/ssp/projects",
                json={"customer_name": "OscalCo", "platform": "aws_govcloud"},
            )
        ).json()["id"]
        doc = (await c.get(f"/api/oscal/ssp/{pid}")).json()
        ssp = doc["system-security-plan"]
        assert ssp["metadata"]["oscal-version"].startswith("1.1")
        assert ssp["system-characteristics"]["security-sensitivity-level"] == "cui"
        reqs = ssp["control-implementation"]["implemented-requirements"]
        assert len(reqs) == 110
        assert reqs[0]["control-id"] == "3.1.1"
        assert reqs[0]["statements"]
        assert (await c.get("/api/oscal/ssp/999999")).status_code == 404
