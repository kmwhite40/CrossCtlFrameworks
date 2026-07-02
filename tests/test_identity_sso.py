"""Enterprise identity — OIDC fallback, JIT, group→role, SCIM, audit, deactivation."""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.identity import provisioning
from ccf.models import AuditLog, Organization, User
from ccf.models_identity import GroupRoleMapping, ScimProvisioningEvent

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return org.id


# --- OIDC fallback -----------------------------------------------------------


@pytest.mark.asyncio
async def test_sso_login_falls_back_to_local_when_oidc_disabled() -> None:
    async with _client() as c:
        r = await c.get("/auth/login", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/login"


# --- JIT + group→role + audit ------------------------------------------------


@pytest.mark.asyncio
async def test_jit_provision_creates_user_and_writes_audit() -> None:
    org_id = await _org("JitOrg")
    async with session_scope() as s:
        user, created = await provisioning.provision_from_oidc(
            s, claims={"sub": "abc", "email": "Neo@Jit.gov", "name": "Neo"}, org_id=org_id,
        )
        assert created is True
        assert user.email == "neo@jit.gov"  # normalized
        assert user.role == "viewer"  # default
    async with session_scope() as s:
        events = (
            await s.execute(
                select(AuditLog).where(
                    AuditLog.entity_type == "identity", AuditLog.action == "create"
                )
            )
        ).scalars().all()
        assert any("jit_provision" in str(e.diff) for e in events)


@pytest.mark.asyncio
async def test_group_maps_to_role_and_role_change_audited() -> None:
    org_id = await _org("GroupOrg")
    async with session_scope() as s:
        s.add(
            GroupRoleMapping(organization_id=org_id, group="gcp-admins", role="admin", priority=10)
        )
    claims = {"sub": "u1", "email": "adm@group.gov", "groups": ["gcp-admins"]}
    async with session_scope() as s:
        user, _ = await provisioning.provision_from_oidc(s, claims=claims, org_id=org_id)
        assert user.role == "admin"
    # Next login with a lower-privilege group flips the role and audits the change.
    async with session_scope() as s:
        s.add(GroupRoleMapping(organization_id=org_id, group="viewers", role="viewer", priority=20))
    async with session_scope() as s:
        user, _ = await provisioning.provision_from_oidc(
            s, claims={"sub": "u1", "email": "adm@group.gov", "groups": ["viewers"]}, org_id=org_id
        )
        assert user.role == "viewer"
    async with session_scope() as s:
        assert (
            await s.execute(
                select(AuditLog).where(AuditLog.action == "update").where(
                    AuditLog.entity_type == "identity"
                )
            )
        ).scalars().first() is not None


@pytest.mark.asyncio
async def test_disallowed_domain_and_jit_off() -> None:
    org_id = await _org("DomainOrg")
    async with session_scope() as s:
        with pytest.raises(provisioning.ProvisioningError):
            await provisioning.provision_from_oidc(
                s, claims={"sub": "x", "email": "a@evil.com"}, org_id=org_id,
                allowed_domains=["gov.example"],
            )
        with pytest.raises(provisioning.ProvisioningError):
            await provisioning.provision_from_oidc(
                s, claims={"sub": "y", "email": "b@x.gov"}, org_id=org_id, jit=False,
            )


# --- SCIM deactivate prevents login ------------------------------------------


@pytest.mark.asyncio
async def test_scim_deactivate_blocks_reprovisioning() -> None:
    org_id = await _org("ScimOrg")
    async with session_scope() as s:
        user, _ = await provisioning.scim_create_or_update_user(
            s, org_id=org_id, payload={"userName": "sc@scim.gov", "active": True},
        )
        uid = user.id
    async with session_scope() as s:
        user = await s.get(User, uid)
        await provisioning.scim_deactivate_user(s, org_id=org_id, user=user)
    # A deactivated account cannot be re-provisioned via OIDC (login is blocked).
    async with session_scope() as s:
        with pytest.raises(provisioning.ProvisioningError, match="deactivated"):
            await provisioning.provision_from_oidc(
                s, claims={"sub": "sc", "email": "sc@scim.gov"}, org_id=org_id,
            )
        events = (
            await s.execute(
                select(ScimProvisioningEvent).where(ScimProvisioningEvent.email == "sc@scim.gov")
            )
        ).scalars().all()
        assert {e.operation for e in events} >= {"create", "deactivate"}


# --- SCIM API routes ---------------------------------------------------------


@pytest.mark.asyncio
async def test_scim_api_requires_token_and_provisions(monkeypatch) -> None:
    await _org("ScimApiOrg")
    monkeypatch.setenv("CCF_SCIM_ENABLED", "true")
    monkeypatch.setenv("CCF_SCIM_BEARER_TOKEN", "s3cr3t")
    get_settings.cache_clear()
    try:
        async with _client() as c:
            # Wrong token → 401.
            bad = await c.post(
                "/api/scim/v2/Users",
                headers={"Authorization": "Bearer nope"},
                json={"userName": "api@scim.gov"},
            )
            assert bad.status_code == 401

            hdr = {"Authorization": "Bearer s3cr3t"}
            created = await c.post(
                "/api/scim/v2/Users", headers=hdr, json={"userName": "api@scim.gov", "active": True}
            )
            assert created.status_code == 201, created.text
            uid = int(created.json()["id"])

            # Deactivate via PATCH.
            patched = await c.patch(
                f"/api/scim/v2/Users/{uid}",
                headers=hdr,
                json={"Operations": [{"op": "replace", "path": "active", "value": False}]},
            )
            assert patched.json()["active"] is False
    finally:
        get_settings.cache_clear()
