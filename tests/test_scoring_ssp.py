"""Integration tests for the live-scoring + SSP API (against Postgres)."""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from ccf import db as ccf_db
from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, ScoringStatus, System


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
async def _fresh_engine() -> object:
    """pytest-asyncio uses a per-test event loop; the global asyncpg engine is
    bound to whichever loop created it. Dispose + reset it after each test so the
    next test gets a fresh engine on its own loop."""
    yield
    if ccf_db._engine is not None:
        await ccf_db._engine.dispose()
    ccf_db._engine = None
    ccf_db._session_factory = None


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _fresh_system(name: str = "ScoreSysX") -> int:
    """Get-or-create a system (the test DB persists across runs) and clear any
    prior scoring statuses so the baseline is deterministic."""
    async with session_scope() as s:
        org = (
            await s.execute(select(Organization).where(Organization.name == "ScoreOrgX"))
        ).scalar_one_or_none()
        if org is None:
            org = Organization(name="ScoreOrgX")
            s.add(org)
            await s.flush()
        sys = (
            await s.execute(
                select(System).where(System.organization_id == org.id, System.name == name)
            )
        ).scalar_one_or_none()
        if sys is None:
            sys = System(organization_id=org.id, name=name)
            s.add(sys)
            await s.flush()
        await s.execute(delete(ScoringStatus).where(ScoringStatus.system_id == sys.id))
        return sys.id


@pytest.mark.asyncio
async def test_seed_and_list_scoring_controls() -> None:
    async with _client() as c:
        r = await c.post("/api/scoring/seed")
        assert r.status_code == 200
        assert r.json()["total"] == 110

        r = await c.get("/api/scoring/controls", params={"domain": "AC"})
        assert r.status_code == 200
        ac = r.json()
        assert ac and all(x["domain"] == "AC" for x in ac)
        assert {"point_value", "objective_parts"} <= ac[0].keys()


@pytest.mark.asyncio
async def test_live_score_recompute() -> None:
    async with _client() as c:
        await c.post("/api/scoring/seed")
        sid = await _fresh_system()

        # Baseline: nothing assessed → score floored well below 110.
        base = (await c.get(f"/api/scoring/systems/{sid}/score")).json()
        assert base["score"] < base["max_score"]

        # Mark every control implemented → perfect score, computed live.
        matrix = (await c.get(f"/api/scoring/systems/{sid}/matrix")).json()
        for row in matrix["controls"]:
            await c.put(
                f"/api/scoring/systems/{sid}/controls/{row['control_id']}",
                json={"state": "implemented"},
            )
        final = (await c.get(f"/api/scoring/systems/{sid}/score")).json()
        assert final["score"] == 110
        assert final["met_controls"] == 110

        # A single 5-point miss recomputes immediately.
        five = next(r for r in matrix["controls"] if r["point_value"] == "5")
        out = await c.put(
            f"/api/scoring/systems/{sid}/controls/{five['control_id']}",
            json={"state": "not_implemented"},
        )
        assert out.json()["summary"]["score"] == 105


@pytest.mark.asyncio
async def test_ssp_project_lifecycle_and_document() -> None:
    async with _client() as c:
        await c.post("/api/scoring/seed")
        r = await c.post(
            "/api/ssp/projects",
            json={"customer_name": "Lifecycle Co", "system_name": "Enclave", "version": "0.3"},
        )
        assert r.status_code == 201
        pid = r.json()["id"]

        detail = (await c.get(f"/api/ssp/projects/{pid}")).json()
        assert len(detail["entries"]) == 110
        first = detail["entries"][0]

        upd = await c.put(
            f"/api/ssp/projects/{pid}/entries/{first['control_id']}",
            json={
                "responsible_role": "Custom Role",
                "implementation_status": ["Implemented"],
                "control_origination": ["Shared"],
            },
        )
        assert upd.status_code == 200
        assert upd.json()["responsible_role"] == "Custom Role"

        doc = await c.get(f"/api/ssp/projects/{pid}/document")
        assert doc.status_code == 200
        assert doc.headers["content-type"].startswith(
            "application/vnd.openxmlformats-officedocument"
        )
        assert doc.content[:2] == b"PK"  # a real .docx (zip) payload
        assert "lifecycle-co" in doc.headers["content-disposition"]
