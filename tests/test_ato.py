"""Authorization (ATO) write path — ``POST /api/systems/{id}/authorize``.

Covers the two acceptance criteria from ISSM-01: an open critical/high POA&M
blocks authorization (409), and a clean system is authorized and stamped with
an expiration. Also checks the mutation flows through the normal HTTP path so
``audit_middleware`` records it, and that the endpoint is role-gated.
"""

from __future__ import annotations

import os
from datetime import date, timedelta

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import POAM, Organization, System, User

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _make_org_system(name: str) -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        sys = System(organization_id=org.id, name=f"{name} system")
        s.add(sys)
        await s.flush()
        return org.id, sys.id


@pytest.mark.asyncio
async def test_authorize_blocked_by_open_critical_poam() -> None:
    _org_id, sys_id = await _make_org_system("ATO Blocked Org")
    async with session_scope() as s:
        s.add(
            POAM(
                system_id=sys_id,
                title="Unpatched critical CVE",
                severity="critical",
                status="open",
            )
        )
        await s.flush()

    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post(f"/api/systems/{sys_id}/authorize")
        assert r.status_code == 409

    async with session_scope() as s:
        sys = await s.get(System, sys_id)
        assert sys.ato_status in (None, "none")


@pytest.mark.asyncio
async def test_authorize_blocked_by_open_high_in_progress_poam() -> None:
    """"in_progress" counts as open, and "high" severity also blocks (not just
    "critical")."""
    _org_id, sys_id = await _make_org_system("ATO Blocked High Org")
    async with session_scope() as s:
        s.add(
            POAM(
                system_id=sys_id,
                title="High severity misconfiguration",
                severity="high",
                status="in_progress",
            )
        )
        await s.flush()

    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post(f"/api/systems/{sys_id}/authorize")
        assert r.status_code == 409


@pytest.mark.asyncio
async def test_authorize_ignores_closed_or_low_severity_poams() -> None:
    _org_id, sys_id = await _make_org_system("ATO Clean Org")
    async with session_scope() as s:
        # A closed critical POA&M and an open low-severity one must not block.
        s.add(
            POAM(
                system_id=sys_id,
                title="Old critical, already fixed",
                severity="critical",
                status="closed",
            )
        )
        s.add(
            POAM(
                system_id=sys_id,
                title="Minor open issue",
                severity="low",
                status="open",
            )
        )
        await s.flush()

    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post(f"/api/systems/{sys_id}/authorize")
        assert r.status_code == 200
        body = r.json()
        assert body["ato_status"] == "authorized"
        assert body["ato_expires_on"] is not None


@pytest.mark.asyncio
async def test_authorize_success_sets_status_and_expiration() -> None:
    _org_id, sys_id = await _make_org_system("ATO Success Org")
    expires = (date.today() + timedelta(days=180)).isoformat()

    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post(
            f"/api/systems/{sys_id}/authorize", json={"expires_on": expires}
        )
        assert r.status_code == 200
        body = r.json()
        assert body["ato_status"] == "authorized"
        assert body["ato_expires_on"] == expires

    async with session_scope() as s:
        sys = await s.get(System, sys_id)
        assert sys.ato_status == "authorized"
        assert sys.ato_expires_on.isoformat() == expires

    # The mutation went through the normal HTTP path, so audit_middleware
    # recorded it.
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.get("/api/audit", params={"entity_type": "systems"})
        assert r.status_code == 200
        entries = r.json()
        assert any(
            e["entity_id"] == str(sys_id) and e["action"] == "create" for e in entries
        )


@pytest.mark.asyncio
async def test_authorize_requires_admin_role() -> None:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    try:
        org_id, sys_id = await _make_org_system("ATO RBAC Org")
        async with session_scope() as s:
            org = await s.get(Organization, org_id)
            viewer = User(
                email="viewer@ato-rbac.test",
                organization_id=org.id,
                role="viewer",
                active=True,
                password_hash=hash_password("pw"),
                api_token=new_api_token(),
            )
            s.add(viewer)
            await s.flush()
            token = viewer.api_token

        transport = ASGITransport(app=create_app())
        async with AsyncClient(transport=transport, base_url="http://t") as c:
            r = await c.post(
                f"/api/systems/{sys_id}/authorize",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert r.status_code == 403
    finally:
        os.environ.pop("CCF_AUTH_ENABLED", None)
        os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
        get_settings.cache_clear()
