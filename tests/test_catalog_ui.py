"""RBAC gate on the server-rendered ``/catalog/integrity`` page (IA-02):
mirrors the ``/audit`` page gate in ``tests/test_audit_rbac.py`` — a
non-admin, authenticated caller must be refused outright, and an admin must
reach the rendered report (or its empty state when no reconciliation has run
yet).
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


@pytest.mark.asyncio
async def test_catalog_integrity_requires_admin() -> None:
    token = await _mk_user("viewer@catalog-ui.test", "Catalog UI Viewer Org", "viewer")
    async with _client() as c:
        r = await c.get("/catalog/integrity", headers=_auth(token))
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_catalog_integrity_renders_for_admin() -> None:
    token = await _mk_user("admin@catalog-ui.test", "Catalog UI Admin Org", "admin")
    async with _client() as c:
        r = await c.get("/catalog/integrity", headers=_auth(token))
    assert r.status_code == 200
    assert "atalog" in r.text  # page renders (empty-state or report)
