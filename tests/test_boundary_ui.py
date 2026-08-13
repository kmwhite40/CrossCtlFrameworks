"""Role-gated boundary UI page (Task 7): a viewer is refused, an admin gets
the four boundary sections and both auto-rendered Mermaid diagrams.

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


async def _mk_user_and_system(
    email: str, org_name: str, role: str, sys_name: str
) -> tuple[str, int]:
    """Create an org + a user with the given role + a System in that org;
    return (bearer token, system id)."""
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


@pytest.mark.asyncio
async def test_viewer_refused() -> None:
    token, sys_id = await _mk_user_and_system(
        "viewer@boundary-ui.test", "Boundary UI Viewer Org", "viewer", "Viewer Sys"
    )
    async with _client() as c:
        r = await c.get(f"/systems/{sys_id}/boundary", headers=_auth(token))
        assert r.status_code == 403


@pytest.mark.asyncio
async def test_admin_sees_sections_and_diagrams() -> None:
    token, sys_id = await _mk_user_and_system(
        "admin@boundary-ui.test", "Boundary UI Admin Org", "admin", "Admin Sys"
    )
    async with _client() as c:
        r = await c.get(f"/systems/{sys_id}/boundary", headers=_auth(token))
        assert r.status_code == 200
        body = r.text
        for heading in (
            "Components",
            "Inventory items",
            "Information types",
            "Interconnections",
        ):
            assert heading in body
        assert 'class="mermaid"' in body
        # Both diagrams render (boundary flowchart + data-flow flowchart).
        assert "flowchart TD" in body
        assert "flowchart LR" in body
        # The vendored Mermaid script is loaded and initialized once.
        assert "/static/vendor/mermaid.min.js" in body
        assert "mermaid.initialize" in body


@pytest.mark.asyncio
async def test_assessor_also_allowed() -> None:
    token, sys_id = await _mk_user_and_system(
        "assessor@boundary-ui.test", "Boundary UI Assessor Org", "assessor", "Assessor Sys"
    )
    async with _client() as c:
        r = await c.get(f"/systems/{sys_id}/boundary", headers=_auth(token))
        assert r.status_code == 200


@pytest.mark.asyncio
async def test_cross_tenant_system_404() -> None:
    token_a, _sys_a = await _mk_user_and_system(
        "tenanta@boundary-ui.test", "Boundary UI Tenant A", "admin", "Tenant A Sys"
    )
    _token_b, sys_b = await _mk_user_and_system(
        "tenantb@boundary-ui.test", "Boundary UI Tenant B", "admin", "Tenant B Sys"
    )
    async with _client() as c:
        r = await c.get(f"/systems/{sys_b}/boundary", headers=_auth(token_a))
        assert r.status_code == 404


@pytest.mark.asyncio
async def test_system_detail_page_embeds_boundary_summary() -> None:
    """The read-only boundary summary card on the system-view page (no role
    gate on system_detail itself, but it links into the gated boundary page)."""
    token, sys_id = await _mk_user_and_system(
        "detail@boundary-ui.test", "Boundary UI Detail Org", "admin", "Detail Sys"
    )
    async with _client() as c:
        r = await c.get(f"/systems/{sys_id}", headers=_auth(token))
        assert r.status_code == 200
        assert f"/systems/{sys_id}/boundary" in r.text
        assert "0 component(s)" in r.text
