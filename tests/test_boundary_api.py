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


@pytest.mark.asyncio
async def test_inventory_component_id_cross_system_422() -> None:
    # An inventory item's component_id must belong to the SAME system; linking to
    # another system's component is rejected (422) before it can be stored.
    token, sys_id = await _mk_user_and_system(
        "invcomp@boundary-api.test", "Boundary API InvComp Org", "admin", "InvComp Sys 1"
    )
    async with session_scope() as s:
        org_id = (
            await s.execute(select(System.organization_id).where(System.id == sys_id))
        ).scalar_one()
        other_sys = System(organization_id=org_id, name="InvComp Sys 2")
        s.add(other_sys)
        await s.flush()
        other_sys_id = other_sys.id

    async with _client() as c:
        create = await c.post(
            f"/api/systems/{sys_id}/boundary/components",
            json={"type": "software", "title": "Comp in sys 1"},
            headers=_auth(token),
        )
        assert create.status_code == 201
        comp_id = create.json()["id"]

        # Try to create an inventory item under system 2 linked to system 1's component.
        bad = await c.post(
            f"/api/systems/{other_sys_id}/boundary/inventory",
            json={"asset_id": "A-1", "asset_type": "software", "component_id": comp_id},
            headers=_auth(token),
        )
        assert bad.status_code == 422

        # Same component under its OWN system is accepted.
        ok = await c.post(
            f"/api/systems/{sys_id}/boundary/inventory",
            json={"asset_id": "A-2", "asset_type": "software", "component_id": comp_id},
            headers=_auth(token),
        )
        assert ok.status_code == 201


@pytest.mark.asyncio
async def test_require_system_in_scope_rejects_a_foreign_principal_without_rls() -> None:
    """``systems.require_system_in_scope``'s OWN org predicate, at its own layer.

    ``test_cross_tenant_not_visible_or_mutable`` above asserts the right
    end-to-end result, but it cannot fail when only the explicit predicate is
    removed: ``ccf.systems`` carries a ``tenant_isolation`` RLS policy and
    ``ccf.api.deps.get_session`` binds the RLS tenant from the principal, so
    the outsider's request 404s at the query before the helper's own check is
    reached. Confirmed by mutation -- deleting the predicate left that test,
    ``test_boundary_ui.py::test_cross_tenant_system_404`` and
    ``test_guided_onboarding.py::test_page_404s_for_a_system_outside_the_principals_org``
    all passing, i.e. the single most widely shared system-scoping guard in
    the API had no test that could fail.

    RLS is documented in ``ccf.api.deps.get_session`` as a backstop *beneath*
    the app-layer scoping, and the unscoped ``session_scope()`` the CLI and
    scheduler use bypasses it by design, so the predicate is pinned here where
    it is the only defense. The owning org is asserted first, so the 404 is
    provably the org check and not the row being unreachable.
    """
    from fastapi import HTTPException  # noqa: PLC0415

    from ccf.api.routes.systems import require_system_in_scope  # noqa: PLC0415
    from ccf.auth import Principal  # noqa: PLC0415

    _token_a, sys_a = await _mk_user_and_system(
        "layera@boundary-api.test", "Boundary API Layer A", "admin", "Layer A Sys"
    )
    _token_b, sys_b = await _mk_user_and_system(
        "layerb@boundary-api.test", "Boundary API Layer B", "admin", "Layer B Sys"
    )
    async with session_scope() as s:  # unscoped: RLS is not filtering here
        row_a = await s.get(System, sys_a)
        row_b = await s.get(System, sys_b)
        assert row_a is not None and row_b is not None
        org_a, org_b = row_a.organization_id, row_b.organization_id

        owner = Principal(
            user_id=None, email="layera@boundary-api.test", org_id=org_a, role="admin"
        )
        found = await require_system_in_scope(s, sys_a, owner)
        assert found.id == sys_a  # the owning org is not locked out

        outsider = Principal(
            user_id=None, email="layerb@boundary-api.test", org_id=org_b, role="admin"
        )
        with pytest.raises(HTTPException) as exc:
            await require_system_in_scope(s, sys_a, outsider)
        assert exc.value.status_code == 404  # 404, not 403 -- no id disclosure
