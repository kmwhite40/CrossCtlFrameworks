"""Compliance pack runtime — validate, install idempotency, coverage, tests, RLS."""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope, set_session_tenant
from ccf.models import Control, ControlImplementation, Organization, System
from ccf.models_packs import CompliancePack, PackControl
from ccf.packs import catalog, service

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


# --- catalog + validation ----------------------------------------------------


def test_bundled_packs_are_valid() -> None:
    available = catalog.list_available()
    assert any(p["id"] == "ai-agent-governance" for p in available)
    for p in available:
        manifest = catalog.load_pack(p["id"])
        assert catalog.validate_manifest(manifest) == []


def test_invalid_manifest_fails_clearly() -> None:
    errors = catalog.validate_manifest({"name": "x"})  # missing id/version/controls
    assert errors
    assert any("id" in e for e in errors)
    assert any("controls" in e for e in errors)


# --- install idempotency + content ------------------------------------------


@pytest.mark.asyncio
async def test_install_is_idempotent_and_materializes_controls() -> None:
    async with session_scope() as s:
        org = Organization(name="PackInstallOrg")
        s.add(org)
        await s.flush()
        org_id = org.id
    manifest = catalog.load_pack("ai-agent-governance")
    async with session_scope() as s:
        await service.install_pack(s, org_id=org_id, manifest=manifest, actor="t")
    async with session_scope() as s:
        await service.install_pack(s, org_id=org_id, manifest=manifest, actor="t")  # again
    async with session_scope() as s:
        packs = (
            await s.execute(select(CompliancePack).where(CompliancePack.organization_id == org_id))
        ).scalars().all()
        assert len(packs) == 1  # idempotent — one pack, not two
        n_controls = (
            await s.execute(
                select(func.count()).select_from(PackControl).where(
                    PackControl.pack_id == packs[0].id
                )
            )
        ).scalar_one()
        assert n_controls == len(manifest["controls"])  # no duplication on re-install


# --- routes: install, coverage, test ----------------------------------------


@pytest.mark.asyncio
async def test_install_coverage_and_test_via_api() -> None:
    async with session_scope() as s:
        org = Organization(name="PackApiOrg")
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name="PackSys", baseline="moderate")
        s.add(sysm)
        await s.flush()
        control = Control(identifier="AIG-1", control_name="AI agent inventory")
        s.add(control)
        await s.flush()
        s.add(ControlImplementation(
            system_id=sysm.id, control_id=control.id, status="implemented"))
        sys_id = sysm.id
    async with _client() as c:
        inst = await c.post("/api/packs/install", json={"pack_id": "ai-agent-governance"})
        assert inst.status_code == 201, inst.text

        cov = await c.get(f"/api/packs/ai-agent-governance/coverage?system_id={sys_id}")
        assert cov.status_code == 200
        assert cov.json()["total_controls"] == 5
        assert cov.json()["covered"] == 1  # only AIG-1 implemented

        tst = await c.post("/api/packs/ai-agent-governance/test")
        assert tst.json()["failed"] == 0
        assert tst.json()["passed"] >= 1


@pytest.mark.asyncio
async def test_validate_route() -> None:
    async with _client() as c:
        ok = await c.post("/api/packs/validate", json=catalog.load_pack("nist-ssdf-genai"))
        assert ok.json()["valid"] is True
        bad = await c.post("/api/packs/validate", json={"name": "nope"})
        assert bad.json()["valid"] is False


# --- RLS ---------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pack_install_is_tenant_scoped() -> None:
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")
    manifest = catalog.load_pack("nist-ssdf-genai")
    async with session_scope() as s:
        a = Organization(name="PackRlsA")
        b = Organization(name="PackRlsB")
        s.add_all([a, b])
        await s.flush()
        await service.install_pack(s, org_id=a.id, manifest=manifest, actor="t")
        await service.install_pack(s, org_id=b.id, manifest=manifest, actor="t")
        org_a = a.id
    async with session_scope() as s:
        await set_session_tenant(s, org_a)
        orgs = {
            p.organization_id
            for p in (await s.execute(select(CompliancePack))).scalars().all()
        }
        assert orgs == {org_a}  # tenant A cannot see B's installed packs


# --- cross-pack posture rule key collisions -----------------------------------
# catalog.validate_manifest's `seen_keys` only catches a duplicate *within* one
# manifest. Two separately installed packs declaring the same key would
# otherwise collapse to one ControlTest (unique on system_id, check_key),
# silently discarding whichever pack's verdict did not run last.


def _posture_manifest(pack_id: str, rule_key: str) -> dict:
    return {
        "id": pack_id,
        "name": pack_id,
        "version": "1.0.0",
        "schema_version": "1",
        "controls": [{"control_id": "AC-2", "title": "Account Management"}],
        "rules": [
            {
                "key": rule_key,
                "kind": "posture",
                "definition": {
                    "provider": "msgraph",
                    "resource_type": "entra_user",
                    "endpoint": "/v1.0/users?$select=id,userPrincipalName,userType",
                    "expected": "no guest account exists",
                    "control_ids": ["AC-2"],
                    "predicate": {"op": "not_equals", "path": "userType", "value": "Guest"},
                },
            }
        ],
    }


@pytest.mark.asyncio
async def test_a_second_pack_cannot_claim_another_installed_packs_rule_key() -> None:
    async with session_scope() as s:
        org = Organization(name="PackKeyCollisionOrg")
        s.add(org)
        await s.flush()
        org_id = org.id
    async with session_scope() as s:
        await service.install_pack(
            s, org_id=org_id, manifest=_posture_manifest("pack-one", "org.shared_key"), actor="t"
        )
    async with session_scope() as s:
        with pytest.raises(service.PackError, match=r"org\.shared_key"):
            await service.install_pack(
                s,
                org_id=org_id,
                manifest=_posture_manifest("pack-two", "org.shared_key"),
                actor="t",
            )


@pytest.mark.asyncio
async def test_reinstalling_the_same_pack_does_not_collide_with_its_own_key() -> None:
    async with session_scope() as s:
        org = Organization(name="PackKeySelfOrg")
        s.add(org)
        await s.flush()
        org_id = org.id
    manifest = _posture_manifest("pack-self", "org.self_key")
    async with session_scope() as s:
        await service.install_pack(s, org_id=org_id, manifest=manifest, actor="t")
    async with session_scope() as s:
        # A reinstall/upgrade of the SAME pack must not conflict with its own
        # previously-installed rule key.
        await service.install_pack(s, org_id=org_id, manifest=manifest, actor="t")


@pytest.mark.asyncio
async def test_the_same_rule_key_is_fine_across_different_organizations() -> None:
    async with session_scope() as s:
        a = Organization(name="PackKeyOrgA")
        b = Organization(name="PackKeyOrgB")
        s.add_all([a, b])
        await s.flush()
        org_a, org_b = a.id, b.id
    async with session_scope() as s:
        await service.install_pack(
            s, org_id=org_a, manifest=_posture_manifest("pack-a", "org.same_key"), actor="t"
        )
    async with session_scope() as s:
        await service.install_pack(
            s, org_id=org_b, manifest=_posture_manifest("pack-b", "org.same_key"), actor="t"
        )
