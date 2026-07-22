"""Integration tests for the live-scoring + SSP API (against Postgres)."""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import POAM, Organization, ScoringStatus, System

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


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
async def test_delete_system_soft_deletes_and_preserves_dependent_data() -> None:
    """DATA-04: deleting a system must not CASCADE-wipe its authorization
    record. It should soft-delete (hide from inventory, refuse a second
    delete) while every dependent row — scoring statuses, POA&Ms — survives
    and remains directly queryable."""
    async with _client() as c:
        await c.post("/api/scoring/seed")
        sid = await _fresh_system("DeleteMeSys")
        # leave dependent records to prove they are NOT cascade-wiped
        await c.put(
            f"/api/scoring/systems/{sid}/controls/AC.L2-3.1.1", json={"state": "implemented"}
        )
        assert (await c.get(f"/api/scoring/systems/{sid}/score")).status_code == 200
        poam = await c.post(
            "/api/poams",
            json={
                "system_id": sid,
                "title": "Soft-delete survives",
                "severity": "high",
                "status": "open",
            },
        )
        assert poam.status_code == 201
        poam_id = poam.json()["id"]

        assert (await c.delete(f"/api/systems/{sid}")).status_code == 204
        # hidden from inventory ...
        listed = (await c.get("/api/systems")).json()
        assert all(s["id"] != sid for s in listed)
        # ... and a second delete 404s (soft-deleted systems are out of scope)
        assert (await c.delete(f"/api/systems/{sid}")).status_code == 404

    # ... but the underlying rows are preserved — query the tables directly.
    async with session_scope() as s:
        sys_row = (await s.execute(select(System).where(System.id == sid))).scalar_one()
        assert sys_row.deleted_at is not None

        statuses = (
            (await s.execute(select(ScoringStatus).where(ScoringStatus.system_id == sid)))
            .scalars()
            .all()
        )
        assert statuses, "scoring statuses must survive a system soft-delete"

        poam_row = (await s.execute(select(POAM).where(POAM.id == poam_id))).scalar_one_or_none()
        assert poam_row is not None, "POA&M must survive a system soft-delete"


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


@pytest.mark.asyncio
async def test_assessment_lifecycle_sar_and_poams() -> None:
    async with _client() as c:
        await c.post("/api/scoring/seed")
        sid = await _fresh_system("AssessSys")
        r = await c.post(
            "/api/assessments",
            json={"system_id": sid, "name": "Q3 SA", "kind": "self", "assessor": "3PAO"},
        )
        assert r.status_code == 201
        aid = r.json()["id"]

        detail = (await c.get(f"/api/assessments/{aid}")).json()
        assert len(detail["results"]) == 110
        assert detail["results"][0]["objective_findings"]  # seeded from objectives

        await c.put(f"/api/assessments/{aid}/controls/AC.L2-3.1.1", json={"finding": "satisfied"})
        await c.put(
            f"/api/assessments/{aid}/controls/AC.L2-3.1.12",
            json={"finding": "other_than_satisfied", "assessor_note": "no session monitoring"},
        )
        summ = (await c.get(f"/api/assessments/{aid}/summary")).json()
        assert summ["assessed"] == 2
        assert summ["by_finding"]["satisfied"] == 1
        assert summ["by_finding"]["other_than_satisfied"] == 1

        # POA&Ms auto-created from other-than-satisfied findings (idempotent).
        assert (await c.post(f"/api/assessments/{aid}/poams-from-findings")).json()["created"] == 1
        assert (await c.post(f"/api/assessments/{aid}/poams-from-findings")).json()["created"] == 0

        sar = await c.get(f"/api/assessments/{aid}/sar")
        assert sar.status_code == 200 and sar.content[:2] == b"PK"

        # invalid finding is rejected.
        bad = await c.put(
            f"/api/assessments/{aid}/controls/AC.L2-3.1.1", json={"finding": "bogus"}
        )
        assert bad.status_code == 422
