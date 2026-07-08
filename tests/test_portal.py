"""External collaboration portal — grants, token resolution, scope, audit, RLS.

The portal gives customers/assessors/vendors scoped, expiring, token-based access
to shared packages/evidence — with no internal account and every access audited.
The security-critical invariants live here: expired/revoked tokens don't resolve,
a grant only exposes what was explicitly shared, and nothing crosses tenants.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope, set_session_tenant
from ccf.evidence import service as ev_service
from ccf.models import Organization, System
from ccf.models_portal import (
    ExternalAccessGrant,
    ExternalComment,
    ExternalPackageShare,
    ExternalPortalAuditEvent,
)
from ccf.packages import service as pkg_service
from ccf.portal import service as portal
from ccf.reliability.checks import (
    _check_external_access_scope_integrity,
    _check_external_grant_expiration,
    _check_external_portal_audit_completeness,
)

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name, description="portal test")
        s.add(org)
        await s.flush()
        return org.id


async def _system(org_id: int, name: str) -> int:
    async with session_scope() as s:
        sysm = System(organization_id=org_id, name=name, baseline="moderate")
        s.add(sysm)
        await s.flush()
        return sysm.id


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


@pytest.mark.asyncio
async def test_create_and_resolve_grant() -> None:
    org = await _org("PortalCreate")
    async with session_scope() as s:
        grant = await portal.create_grant(
            s, org_id=org, principal_name="Auditor A", kind="assessor", ttl_days=14
        )
        token = grant.token
        assert token and len(token) <= 64
    async with session_scope() as s:
        resolved = await portal.resolve_grant(s, token)
        assert resolved is not None
        assert resolved.organization_id == org
        assert resolved.kind == "assessor"


@pytest.mark.asyncio
async def test_resolve_rejects_expired_grant() -> None:
    org = await _org("PortalExpired")
    async with session_scope() as s:
        grant = await portal.create_grant(s, org_id=org, principal_name="Late", ttl_days=1)
        grant.expires_at = datetime.now(UTC) - timedelta(days=1)  # force expiry
        token = grant.token
    async with session_scope() as s:
        assert await portal.resolve_grant(s, token) is None


@pytest.mark.asyncio
async def test_resolve_rejects_revoked_grant() -> None:
    org = await _org("PortalRevoked")
    async with session_scope() as s:
        grant = await portal.create_grant(s, org_id=org, principal_name="Gone", ttl_days=30)
        gid, token = grant.id, grant.token
    async with session_scope() as s:
        assert await portal.revoke_grant(s, gid, actor="admin@x") is True
    async with session_scope() as s:
        assert await portal.resolve_grant(s, token) is None


@pytest.mark.asyncio
async def test_grant_contents_only_returns_shared_artifacts() -> None:
    org = await _org("PortalScope")
    system = await _system(org, "ScopeSys")
    async with session_scope() as s:
        shared = await pkg_service.create_package(
            s, org_id=org, system_id=system, kind="json", label="Shared pkg"
        )
        private = await pkg_service.create_package(
            s, org_id=org, system_id=system, kind="json", label="Private pkg"
        )
        ev = await ev_service.create_object(
            s, org_id=org, title="Shared evidence", system_id=system
        )
        shared_id, private_id, ev_id = shared.id, private.id, ev.id
    async with session_scope() as s:
        grant = await portal.create_grant(
            s, org_id=org, principal_name="Cust", package_ids=[shared_id], evidence_ids=[ev_id]
        )
        token = grant.token
    async with session_scope() as s:
        grant = await portal.resolve_grant(s, token)
        contents = await portal.grant_contents(s, grant)
        pkg_ids = {p["id"] for p in contents["packages"]}
        ev_ids = {e["id"] for e in contents["evidence"]}
        assert pkg_ids == {shared_id}
        assert private_id not in pkg_ids  # not shared → never exposed
        assert ev_ids == {ev_id}


@pytest.mark.asyncio
async def test_access_and_comment_write_audit_events() -> None:
    org = await _org("PortalAudit")
    async with session_scope() as s:
        grant = await portal.create_grant(s, org_id=org, principal_name="Talker")
        gid, token = grant.id, grant.token
    async with session_scope() as s:
        grant = await portal.resolve_grant(s, token)
        await portal.record_access(s, grant, action="view", target_type="package", target_id="1")
        await portal.add_comment(
            s, grant, target_type="evidence", target_id="9", author="Talker", body="Looks good"
        )
    async with session_scope() as s:
        comments = (
            await s.execute(select(func.count()).select_from(ExternalComment).where(
                ExternalComment.grant_id == gid))
        ).scalar_one()
        events = (
            await s.execute(select(ExternalPortalAuditEvent).where(
                ExternalPortalAuditEvent.grant_id == gid))
        ).scalars().all()
        actions = {e.action for e in events}
        assert comments == 1
        assert "view" in actions and "comment" in actions  # both access and comment audited


@pytest.mark.asyncio
async def test_rls_blocks_cross_tenant_grants() -> None:
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")
    org_a = await _org("PortalRlsA")
    org_b = await _org("PortalRlsB")
    async with session_scope() as s:
        await portal.create_grant(s, org_id=org_a, principal_name="A")
        await portal.create_grant(s, org_id=org_b, principal_name="B")
    async with session_scope() as s:
        await set_session_tenant(s, org_a)
        orgs = {
            g.organization_id
            for g in (await s.execute(select(ExternalAccessGrant))).scalars().all()
        }
        assert orgs == {org_a}  # tenant A cannot see tenant B's grants


@pytest.mark.asyncio
async def test_admin_and_portal_api_end_to_end() -> None:
    org = await _org("PortalApi")
    system = await _system(org, "ApiSys")
    async with session_scope() as s:
        pkg = await pkg_service.create_package(
            s, org_id=org, system_id=system, kind="json", label="API pkg"
        )
        pkg_id = pkg.id
    async with _client() as c:
        created = await c.post(
            "/api/admin/portal/grants",
            json={"organization_id": org, "principal_name": "Ext Auditor",
                  "kind": "assessor", "package_ids": [pkg_id], "ttl_days": 30},
        )
        assert created.status_code == 200
        token = created.json()["token"]
        assert token

        listed = await c.get("/api/admin/portal/grants", params={"organization_id": org})
        assert listed.status_code == 200
        assert any(g["token"] == token for g in listed.json())

        # Portal session resolves with the bearer token and returns the shared package.
        sess = await c.get("/api/portal/session", headers={"Authorization": f"Bearer {token}"})
        assert sess.status_code == 200
        assert any(p["id"] == pkg_id for p in sess.json()["packages"])

        # A bogus token is denied.
        bad = await c.get("/api/portal/session", headers={"Authorization": "Bearer nope"})
        assert bad.status_code == 401


# --- reliability checks -----------------------------------------------------


@pytest.mark.asyncio
async def test_scope_integrity_check_flags_cross_tenant_share() -> None:
    org_a = await _org("ScopeChkA")
    org_b = await _org("ScopeChkB")
    system_b = await _system(org_b, "BSys")
    async with session_scope() as s:
        pkg_b = await pkg_service.create_package(
            s, org_id=org_b, system_id=system_b, kind="json", label="B pkg"
        )
        grant_a = await portal.create_grant(s, org_id=org_a, principal_name="A")
        grant_a_id, pkg_b_id = grant_a.id, pkg_b.id
    # Clean state → PASS.
    async with session_scope() as s:
        await set_session_tenant(s, None)
        assert (await _check_external_access_scope_integrity(s)).status == "pass"
    # Craft a cross-tenant leak: A's grant referencing B's package.
    async with session_scope() as s:
        bad = ExternalPackageShare(grant_id=grant_a_id, package_id=pkg_b_id)
        s.add(bad)
        await s.flush()
        bad_id = bad.id
    try:
        async with session_scope() as s:
            await set_session_tenant(s, None)
            assert (await _check_external_access_scope_integrity(s)).status == "fail"
    finally:
        async with session_scope() as s:  # clean up so global reliability stays green
            leak = await s.get(ExternalPackageShare, bad_id)
            if leak is not None:
                await s.delete(leak)


@pytest.mark.asyncio
async def test_grant_expiration_check_warns_on_stale_live_grant() -> None:
    org = await _org("ExpChk")
    async with session_scope() as s:
        grant = await portal.create_grant(s, org_id=org, principal_name="Stale", ttl_days=1)
        grant.expires_at = datetime.now(UTC) - timedelta(days=2)  # expired, not revoked
    async with session_scope() as s:
        await set_session_tenant(s, None)
        chk = await _check_external_grant_expiration(s)
        assert chk.status == "warn"
        assert "expired" in chk.message.lower()


@pytest.mark.asyncio
async def test_audit_completeness_check_warns_on_grant_without_audit() -> None:
    org = await _org("AuditChk")
    # A grant inserted directly (bypassing the service) has no audit trail.
    async with session_scope() as s:
        bare = ExternalAccessGrant(organization_id=org, kind="customer", token="bare-" + "x" * 20)
        s.add(bare)
        await s.flush()
        bare_id = bare.id
    try:
        async with session_scope() as s:
            await set_session_tenant(s, None)
            assert (await _check_external_portal_audit_completeness(s)).status == "warn"
    finally:
        async with session_scope() as s:
            g = await s.get(ExternalAccessGrant, bare_id)
            if g is not None:
                await s.delete(g)
