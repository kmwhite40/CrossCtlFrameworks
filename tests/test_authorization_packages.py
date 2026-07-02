"""Authorization packages — provenance capture, diff, replay drift, no mutation."""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import POAM, Control, ControlImplementation, Organization, System
from ccf.models_packages import AuthorizationPackage, AuthorizationPackageFact
from ccf.packages import service

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _seed(name: str = "PkgOrg") -> tuple[int, int, int]:
    """org, system, poam_id — a small authorization posture."""
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name="PkgSys", baseline="moderate")
        s.add(sysm)
        await s.flush()
        control = (await s.execute(select(Control).limit(1))).scalar_one_or_none()
        if control is None:
            control = Control(identifier="AC-2", control_name="Account Management")
            s.add(control)
            await s.flush()
        s.add(ControlImplementation(
            system_id=sysm.id, control_id=control.id, status="implemented"))
        poam = POAM(system_id=sysm.id, title="Fix X", severity="high", status="open")
        s.add(poam)
        await s.flush()
        return org.id, sysm.id, poam.id


@pytest.mark.asyncio
async def test_create_package_stores_provenance() -> None:
    _org_id, sys_id, _poam = await _seed("PkgOrgA")
    async with _client() as c:
        r = await c.post(
            "/api/authorization-packages", json={"system_id": sys_id, "kind": "fedramp20x"}
        )
        assert r.status_code == 201, r.text
        pid = r.json()["id"]
        assert r.json()["fact_count"] > 0

        prov = (await c.get(f"/api/authorization-packages/{pid}/provenance")).json()
        types = {f["fact_type"] for f in prov["facts"]}
        assert "control" in types
        assert "poam" in types


@pytest.mark.asyncio
async def test_diff_detects_changed_poam() -> None:
    _org_id, sys_id, poam_id = await _seed("PkgOrgB")
    async with _client() as c:
        p1 = (await c.post("/api/authorization-packages", json={"system_id": sys_id})).json()["id"]
        # Change the authorization posture.
        async with session_scope() as s:
            poam = await s.get(POAM, poam_id)
            poam.status = "completed"
        p2 = (await c.post("/api/authorization-packages", json={"system_id": sys_id})).json()["id"]

        diff = (await c.get(f"/api/authorization-packages/{p1}/diff/{p2}")).json()
        assert diff["summary"]["changed"] >= 1
        poam_changes = diff["changes"].get("poam", {}).get("changed", [])
        assert any(ch["from"]["value"] == "open" and ch["to"]["value"] == "completed"
                   for ch in poam_changes)


@pytest.mark.asyncio
async def test_replay_detects_drift_without_mutating() -> None:
    _org_id, sys_id, poam_id = await _seed("PkgOrgC")
    async with _client() as c:
        pid = (await c.post("/api/authorization-packages", json={"system_id": sys_id})).json()["id"]

        # Fresh replay against unchanged DB → reproducible.
        assert (await c.post(f"/api/authorization-packages/{pid}/replay")).json()["status"] \
            == "reproducible"

        # Drift the DB, then replay detects it.
        async with session_scope() as s:
            poam = await s.get(POAM, poam_id)
            poam.status = "risk_accepted"
        drifted = await c.post(f"/api/authorization-packages/{pid}/replay")
        assert drifted.json()["status"] == "drifted"

    # Replay must not have mutated the persisted package facts.
    async with session_scope() as s:
        original = (
            await s.execute(
                select(AuthorizationPackageFact.value).where(
                    AuthorizationPackageFact.package_id == pid,
                    AuthorizationPackageFact.fact_type == "poam",
                )
            )
        ).scalars().all()
        assert "open" in original  # captured value unchanged despite DB drift


@pytest.mark.asyncio
async def test_authorization_delta_memo() -> None:
    _org_id, sys_id, poam_id = await _seed("PkgOrgD")
    async with _client() as c:
        await c.post("/api/authorization-packages", json={"system_id": sys_id})
        async with session_scope() as s:
            poam = await s.get(POAM, poam_id)
            poam.status = "completed"
        await c.post("/api/authorization-packages", json={"system_id": sys_id})

        memo = await c.get(f"/api/fedramp/20x/systems/{sys_id}/authorization-delta")
        assert memo.status_code == 200
        assert "Authorization Delta Memo" in memo.json()["body"]


@pytest.mark.asyncio
async def test_replay_is_read_only_on_facts_count() -> None:
    org_id, sys_id, _poam = await _seed("PkgOrgE")
    async with session_scope() as s:
        pkg = await service.create_package(s, org_id=org_id, system_id=sys_id)
        pid = pkg.id
        before = (
            await s.execute(
                select(func.count()).select_from(AuthorizationPackageFact).where(
                    AuthorizationPackageFact.package_id == pid
                )
            )
        ).scalar_one()
    async with session_scope() as s:
        pkg = await s.get(AuthorizationPackage, pid)
        await service.replay_package(s, org_id=org_id, package=pkg)
    async with session_scope() as s:
        after = (
            await s.execute(
                select(func.count()).select_from(AuthorizationPackageFact).where(
                    AuthorizationPackageFact.package_id == pid
                )
            )
        ).scalar_one()
    assert before == after
