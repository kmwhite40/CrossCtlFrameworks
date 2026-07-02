"""Tests for authentication, RBAC, and multi-tenant scoping."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from ccf.api.main import create_app
from ccf.auth import (
    hash_password,
    new_api_token,
    sign_session,
    verify_password,
    verify_session,
)
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, System, User

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


# ── pure primitives (no DB) ────────────────────────────────


def test_password_hash_roundtrip() -> None:
    h = hash_password("s3cret-passphrase")
    assert verify_password("s3cret-passphrase", h)
    assert not verify_password("wrong", h)
    assert not verify_password("x", None)
    # Two hashes of the same password differ (random salt) but both verify.
    assert hash_password("p") != hash_password("p")


def test_session_sign_and_verify() -> None:
    tok = sign_session(7, "secret", ttl_hours=1)
    assert verify_session(tok, "secret") == 7
    assert verify_session(tok, "other-secret") is None  # bad signature
    assert verify_session("garbage", "secret") is None
    assert verify_session(sign_session(7, "secret", ttl_hours=-1), "secret") is None  # expired


# ── enforcement + tenancy (DB + app, auth enabled) ─────────


@pytest.fixture
async def auth_on() -> AsyncIterator[None]:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


async def _mk_user(email: str, org_name: str, role: str, password: str = "pw") -> tuple[int, str]:
    async with session_scope() as s:
        org = (
            await s.execute(select(Organization).where(Organization.name == org_name))
        ).scalar_one_or_none()
        if org is None:
            org = Organization(name=org_name)
            s.add(org)
            await s.flush()
        user = (await s.execute(select(User).where(User.email == email))).scalar_one_or_none()
        if user is None:
            user = User(email=email, organization_id=org.id)
            s.add(user)
        user.role = role
        user.active = True
        user.password_hash = hash_password(password)
        token = new_api_token()
        user.api_token = token
        await s.flush()
        return org.id, token


async def _mk_system(org_id: int, name: str) -> int:
    async with session_scope() as s:
        sys = (
            await s.execute(
                select(System).where(System.organization_id == org_id, System.name == name)
            )
        ).scalar_one_or_none()
        if sys is None:
            sys = System(organization_id=org_id, name=name)
            s.add(sys)
            await s.flush()
        return sys.id


@pytest.mark.asyncio
async def test_auth_enforcement_rbac_and_tenant_isolation(auth_on: None) -> None:
    org_a, token_a = await _mk_user("admin@a.test", "OrgA-Auth", "admin")
    org_b, token_b = await _mk_user("viewer@b.test", "OrgB-Auth", "viewer")
    sys_a = await _mk_system(org_a, "A-Enclave")
    sys_b = await _mk_system(org_b, "B-Enclave")
    # The test DB persists between runs — clear the system the POST below creates.
    async with session_scope() as s:
        await s.execute(delete(System).where(System.name == "Forced"))
    ha = {"Authorization": f"Bearer {token_a}"}
    hb = {"Authorization": f"Bearer {token_b}"}

    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        # Unauthenticated: API → 401, browser path → redirect to /login.
        assert (await c.get("/api/posture/summary")).status_code == 401
        assert (await c.get("/posture")).status_code == 303

        # Tenant isolation: admin A sees only org A's systems.
        names = {s["name"] for s in (await c.get("/api/systems", headers=ha)).json()}
        assert "A-Enclave" in names and "B-Enclave" not in names
        assert (await c.get(f"/api/systems/{sys_a}/summary", headers=ha)).status_code == 200
        assert (await c.get(f"/api/systems/{sys_b}/summary", headers=ha)).status_code == 404

        # RBAC: viewer cannot seed the matrix; admin can.
        assert (await c.post("/api/scoring/seed", headers=hb)).status_code == 403
        assert (await c.post("/api/scoring/seed", headers=ha)).status_code == 200

        # Create-system is forced into the principal's org (ignores spoofed org id).
        created = (
            await c.post(
                "/api/systems", json={"organization_id": org_b, "name": "Forced"}, headers=ha
            )
        ).json()
        assert created["organization_id"] == org_a

        # SSP project tenant isolation: B cannot see A's project.
        proj = (
            await c.post("/api/ssp/projects", json={"customer_name": "A SSP"}, headers=ha)
        ).json()
        assert (await c.get(f"/api/ssp/projects/{proj['id']}", headers=ha)).status_code == 200
        assert (await c.get(f"/api/ssp/projects/{proj['id']}", headers=hb)).status_code == 404
        b_projects = (await c.get("/api/ssp/projects", headers=hb)).json()
        assert all(p["id"] != proj["id"] for p in b_projects)

        # Server-rendered UI pages honor the same org boundary.
        assert (await c.get(f"/ssp/{proj['id']}", headers=hb)).status_code == 404
        assert (await c.get(f"/systems/{sys_a}", headers=hb)).status_code == 404
        # B cannot delete A's system (out of scope → 404, system survives).
        assert (await c.delete(f"/api/systems/{sys_a}", headers=hb)).status_code == 404
        assert (await c.get(f"/api/systems/{sys_a}/summary", headers=ha)).status_code == 200

        # Login issues a session; /me reflects the principal.
        login = await c.post(
            "/api/auth/login", json={"email": "admin@a.test", "password": "pw"}
        )
        assert login.status_code == 200 and login.json()["role"] == "admin"
        me = (await c.get("/api/auth/me", headers=ha)).json()
        assert me["email"] == "admin@a.test" and me["organization_id"] == org_a

        # Audit attributes the mutation to the authenticated principal.
        entries = (await c.get("/api/audit", headers=ha)).json()
        assert any(e["actor"] == "admin@a.test" for e in entries)


@pytest.mark.asyncio
async def test_oscal_and_reports_are_org_scoped(auth_on: None) -> None:
    """Export endpoints must not leak another tenant's data (IDOR regression)."""
    org_a, token_a = await _mk_user("admin@oscal-a.test", "OscalOrgA", "admin")
    _org_b, token_b = await _mk_user("admin@oscal-b.test", "OscalOrgB", "admin")
    sys_a = await _mk_system(org_a, "OscalA-Enclave")
    ha = {"Authorization": f"Bearer {token_a}"}
    hb = {"Authorization": f"Bearer {token_b}"}

    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        # OSCAL component-definition: owner 200, cross-tenant 404, anonymous 401.
        url = f"/api/oscal/component-definition/{sys_a}"
        assert (await c.get(url, headers=ha)).status_code == 200
        assert (await c.get(url, headers=hb)).status_code == 404
        assert (await c.get(url)).status_code == 401

        # OSCAL SSP export honors the SSP project's org boundary.
        proj = (
            await c.post("/api/ssp/projects", json={"customer_name": "OscalA SSP"}, headers=ha)
        ).json()
        assert (await c.get(f"/api/oscal/ssp/{proj['id']}", headers=ha)).status_code == 200
        assert (await c.get(f"/api/oscal/ssp/{proj['id']}", headers=hb)).status_code == 404

        # Report builder: cross-tenant system id → 404; anonymous → 401.
        assert (
            await c.get(f"/api/reports/build?system_id={sys_a}", headers=hb)
        ).status_code == 404
        assert (await c.get("/api/reports/build")).status_code == 401
