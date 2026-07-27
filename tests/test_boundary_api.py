"""JSON CRUD API for boundary entities (Task 6): RBAC gate, tenant scoping,
cross-system guard, and controlled-vocabulary validation.

Mirrors ``tests/test_audit_rbac.py``'s auth-enabled harness exactly (module
autouse ``_auth_enabled`` fixture, ``_client()``, ``_mk_user``, ``_auth``) —
this repo's tests use unique org/email names per test since the DB isn't
truncated between tests.
"""

from __future__ import annotations

import os

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, System, User

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


async def _mk_user_and_system(
    email: str, org_name: str, role: str, sys_name: str
) -> tuple[str, int]:
    """Like ``_mk_user``, but also creates a System in the new org and returns
    its id."""
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
        sysrow = System(organization_id=org.id, name=sys_name)
        s.add(sysrow)
        await s.flush()
        return user.api_token, sysrow.id


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --- RBAC: viewer refused, admin allowed ------------------------------------


@pytest.mark.asyncio
async def test_viewer_post_refused() -> None:
    token, sys_id = await _mk_user_and_system(
        "viewer@boundary-api.test", "Boundary API Viewer Org", "viewer", "Viewer Sys"
    )
    async with _client() as c:
        r = await c.post(
            f"/api/systems/{sys_id}/boundary/components",
            json={"type": "software", "title": "Widget"},
            headers=_auth(token),
        )
        assert r.status_code == 403


@pytest.mark.asyncio
async def test_admin_create_then_list() -> None:
    token, sys_id = await _mk_user_and_system(
        "admin@boundary-api.test", "Boundary API Admin Org", "admin", "Admin Sys"
    )
    async with _client() as c:
        r = await c.post(
            f"/api/systems/{sys_id}/boundary/components",
            json={"type": "software", "title": "API Gateway", "status": "operational"},
            headers=_auth(token),
        )
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["title"] == "API Gateway"
        assert body["system_id"] == sys_id

        r2 = await c.get(
            f"/api/systems/{sys_id}/boundary/components", headers=_auth(token)
        )
        assert r2.status_code == 200
        titles = [row["title"] for row in r2.json()]
        assert "API Gateway" in titles


@pytest.mark.asyncio
async def test_assessor_can_create() -> None:
    token, sys_id = await _mk_user_and_system(
        "assessor@boundary-api.test", "Boundary API Assessor Org", "assessor", "Assessor Sys"
    )
    async with _client() as c:
        r = await c.post(
            f"/api/systems/{sys_id}/boundary/inventory",
            json={"asset_id": "srv-01", "asset_type": "hardware"},
            headers=_auth(token),
        )
        assert r.status_code == 201, r.text


# --- controlled-vocabulary validation ---------------------------------------


@pytest.mark.asyncio
async def test_invalid_component_type_422() -> None:
    token, sys_id = await _mk_user_and_system(
        "badtype@boundary-api.test", "Boundary API BadType Org", "admin", "BadType Sys"
    )
    async with _client() as c:
        r = await c.post(
            f"/api/systems/{sys_id}/boundary/components",
            json={"type": "not-a-real-type", "title": "Bad"},
            headers=_auth(token),
        )
        assert r.status_code == 422


@pytest.mark.asyncio
async def test_invalid_interconnection_direction_422() -> None:
    token, sys_id = await _mk_user_and_system(
        "baddir@boundary-api.test", "Boundary API BadDir Org", "admin", "BadDir Sys"
    )
    async with _client() as c:
        r = await c.post(
            f"/api/systems/{sys_id}/boundary/interconnections",
            json={
                "remote_system_name": "External",
                "direction": "sideways",
                "agreement_type": "ISA",
            },
            headers=_auth(token),
        )
        assert r.status_code == 422


@pytest.mark.asyncio
async def test_invalid_inventory_asset_type_422() -> None:
    token, sys_id = await _mk_user_and_system(
        "badasset@boundary-api.test", "Boundary API BadAsset Org", "admin", "BadAsset Sys"
    )
    async with _client() as c:
        r = await c.post(
            f"/api/systems/{sys_id}/boundary/inventory",
            json={"asset_id": "srv-02", "asset_type": "spaceship"},
            headers=_auth(token),
        )
        assert r.status_code == 422


# --- cross-system guard on PATCH/DELETE -------------------------------------


@pytest.mark.asyncio
async def test_patch_cross_system_404() -> None:
    token, sys_id = await _mk_user_and_system(
        "cross1@boundary-api.test", "Boundary API Cross Org", "admin", "Cross Sys 1"
    )
    async with session_scope() as s:
        # A second system in the SAME org as the token's user.
        org_id = (
            await s.execute(select(System.organization_id).where(System.id == sys_id))
        ).scalar_one()
        other_sys = System(organization_id=org_id, name="Cross Sys 2")
        s.add(other_sys)
        await s.flush()
        other_sys_id = other_sys.id

    async with _client() as c:
        create = await c.post(
            f"/api/systems/{sys_id}/boundary/components",
            json={"type": "software", "title": "Belongs to sys 1"},
            headers=_auth(token),
        )
        assert create.status_code == 201
        component_id = create.json()["id"]

        # Attempt to PATCH it via the OTHER system's path.
        patch = await c.patch(
            f"/api/systems/{other_sys_id}/boundary/components/{component_id}",
            json={"title": "Hijacked"},
            headers=_auth(token),
        )
        assert patch.status_code == 404

        delete = await c.delete(
            f"/api/systems/{other_sys_id}/boundary/components/{component_id}",
            headers=_auth(token),
        )
        assert delete.status_code == 404

        # Confirm it's untouched via the correct system path.
        get_correct = await c.get(
            f"/api/systems/{sys_id}/boundary/components", headers=_auth(token)
        )
        titles = [row["title"] for row in get_correct.json()]
        assert "Belongs to sys 1" in titles
        assert "Hijacked" not in titles


# --- cross-tenant isolation ---------------------------------------------------


@pytest.mark.asyncio
async def test_cross_tenant_not_visible_or_mutable() -> None:
    token_a, sys_a = await _mk_user_and_system(
        "tenanta@boundary-api.test", "Boundary API Tenant A", "admin", "Tenant A Sys"
    )
    token_b, sys_b = await _mk_user_and_system(
        "tenantb@boundary-api.test", "Boundary API Tenant B", "admin", "Tenant B Sys"
    )

    async with _client() as c:
        create = await c.post(
            f"/api/systems/{sys_a}/boundary/components",
            json={"type": "software", "title": "Org A Secret Component"},
            headers=_auth(token_a),
        )
        assert create.status_code == 201
        component_id = create.json()["id"]

        # Org B's admin can't reach org A's system at all (404 from scoping).
        get_wrong_system = await c.get(
            f"/api/systems/{sys_a}/boundary/components", headers=_auth(token_b)
        )
        assert get_wrong_system.status_code == 404

        # Org B's admin can't PATCH/DELETE org A's component even via org B's
        # own (unrelated) system path.
        patch = await c.patch(
            f"/api/systems/{sys_b}/boundary/components/{component_id}",
            json={"title": "Stolen"},
            headers=_auth(token_b),
        )
        assert patch.status_code == 404

        delete = await c.delete(
            f"/api/systems/{sys_b}/boundary/components/{component_id}",
            headers=_auth(token_b),
        )
        assert delete.status_code == 404

        # Org B's own list is empty of org A's data.
        list_b = await c.get(
            f"/api/systems/{sys_b}/boundary/components", headers=_auth(token_b)
        )
        assert list_b.status_code == 200
        assert list_b.json() == []
