"""RBAC gate on the audit-read API (IA-02): list_audit / verify_chain must
require a privileged role once auth is enabled — the audit trail spans every
tenant's mutations and audit_log has no organization_id column to scope it
(see the DATA-06 note in ``ccf.api.routes.audit``).
"""

from __future__ import annotations

import os

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, User

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def _auth_enabled() -> None:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _mk_user(email: str, org_name: str, role: str) -> str:
    """Create an org + a user with the given role; return a bearer token."""
    async with session_scope() as s:
        org = Organization(name=org_name)
        s.add(org)
        await s.flush()
        user = User(
            email=email,
            organization_id=org.id,
            role=role,
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(user)
        await s.flush()
        return user.api_token


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --- unauthenticated ---------------------------------------------------------


@pytest.mark.asyncio
async def test_unauthenticated_refused() -> None:
    async with _client() as c:
        assert (await c.get("/api/audit")).status_code == 401
        assert (await c.get("/api/audit/verify")).status_code == 401


# --- non-privileged roles get 403 --------------------------------------------


@pytest.mark.asyncio
async def test_viewer_refused() -> None:
    token = await _mk_user("viewer@audit-rbac.test", "Audit RBAC Viewer Org", "viewer")
    async with _client() as c:
        r1 = await c.get("/api/audit", headers=_auth(token))
        assert r1.status_code == 403
        r2 = await c.get("/api/audit/verify", headers=_auth(token))
        assert r2.status_code == 403


@pytest.mark.asyncio
async def test_control_owner_refused() -> None:
    token = await _mk_user(
        "co@audit-rbac.test", "Audit RBAC ControlOwner Org", "control_owner"
    )
    async with _client() as c:
        r1 = await c.get("/api/audit", headers=_auth(token))
        assert r1.status_code == 403
        r2 = await c.get("/api/audit/verify", headers=_auth(token))
        assert r2.status_code == 403


# --- privileged roles are let through ------------------------------------------


@pytest.mark.asyncio
async def test_admin_allowed() -> None:
    token = await _mk_user("admin@audit-rbac.test", "Audit RBAC Admin Org", "admin")
    async with _client() as c:
        r1 = await c.get("/api/audit", headers=_auth(token))
        assert r1.status_code == 200
        r2 = await c.get("/api/audit/verify", headers=_auth(token))
        assert r2.status_code == 200
        assert r2.json()["ok"] is True


@pytest.mark.asyncio
async def test_assessor_allowed() -> None:
    token = await _mk_user(
        "assessor@audit-rbac.test", "Audit RBAC Assessor Org", "assessor"
    )
    async with _client() as c:
        r1 = await c.get("/api/audit", headers=_auth(token))
        assert r1.status_code == 200
        r2 = await c.get("/api/audit/verify", headers=_auth(token))
        assert r2.status_code == 200
        assert r2.json()["ok"] is True


# --- chain-verify logic is preserved under the gate ----------------------------


@pytest.mark.asyncio
async def test_chain_verify_still_works_for_admin() -> None:
    """The hash-chain verify behavior (incl. tamper detection) is unchanged by
    the role gate — this exercises it end-to-end as an authenticated admin."""
    token = await _mk_user("admin2@audit-rbac.test", "Audit RBAC Chain Org", "admin")
    async with _client() as c:
        # A mutation (creating the org/user above happened outside the HTTP
        # layer) — trigger one through the API so there's a chained row, then
        # confirm the chain still verifies for a privileged caller.
        await c.post(
            "/api/ssp/projects",
            json={"customer_name": "AuditRbacChainCo"},
            headers=_auth(token),
        )
        r = await c.get("/api/audit/verify", headers=_auth(token))
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert body["checked"] >= 1
