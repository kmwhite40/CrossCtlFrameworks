"""Tests for account lockout after failed logins (AC-7).

Auth is enabled for this module (mirrors ``tests/test_audit_rbac.py``'s
module-level harness). The DB is not truncated between tests, so every test
uses unique org/email names.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.auth import hash_password
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, User

_PASSWORD = "Correct-horse-battery-staple"

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


async def _mk_user(email: str, org_name: str) -> int:
    """Create an org + a user with a known password; return the user id."""
    async with session_scope() as s:
        org = Organization(name=org_name)
        s.add(org)
        await s.flush()
        user = User(
            email=email,
            organization_id=org.id,
            role="viewer",
            active=True,
            password_hash=hash_password(_PASSWORD),
        )
        s.add(user)
        await s.flush()
        return user.id


async def _get_user(user_id: int) -> User:
    async with session_scope() as s:
        return (await s.execute(select(User).where(User.id == user_id))).scalar_one()


@pytest.mark.asyncio
async def test_locked_account_rejects_even_correct_password() -> None:
    user_id = await _mk_user("locked-a@lockout.test", "LockoutOrgA")
    async with session_scope() as s:
        user = (await s.execute(select(User).where(User.id == user_id))).scalar_one()
        user.locked_until = datetime.now(UTC) + timedelta(minutes=15)
        await s.flush()

    async with _client() as c:
        resp = await c.post(
            "/api/auth/login",
            json={"email": "locked-a@lockout.test", "password": _PASSWORD},
        )
    assert resp.status_code == 429


@pytest.mark.asyncio
async def test_threshold_failed_logins_locks_account() -> None:
    settings = get_settings()
    threshold = settings.auth_lockout_threshold
    await _mk_user("locked-b@lockout.test", "LockoutOrgB")

    async with _client() as c:
        for _ in range(threshold):
            resp = await c.post(
                "/api/auth/login",
                json={"email": "locked-b@lockout.test", "password": "wrong-password"},
            )
            assert resp.status_code == 401

        # The account is now locked — even a further attempt (right or wrong
        # password) is refused with 429.
        locked_resp = await c.post(
            "/api/auth/login",
            json={"email": "locked-b@lockout.test", "password": _PASSWORD},
        )
        assert locked_resp.status_code == 429

    async with session_scope() as s:
        user = (
            await s.execute(select(User).where(User.email == "locked-b@lockout.test"))
        ).scalar_one()
        assert user.locked_until is not None
        assert user.locked_until > datetime.now(UTC)
        assert user.failed_login_attempts == 0


@pytest.mark.asyncio
async def test_successful_login_resets_failed_attempts() -> None:
    user_id = await _mk_user("locked-c@lockout.test", "LockoutOrgC")

    async with _client() as c:
        # A couple of failed attempts, but under the lockout threshold.
        for _ in range(2):
            resp = await c.post(
                "/api/auth/login",
                json={"email": "locked-c@lockout.test", "password": "wrong-password"},
            )
            assert resp.status_code == 401

        ok_resp = await c.post(
            "/api/auth/login",
            json={"email": "locked-c@lockout.test", "password": _PASSWORD},
        )
        assert ok_resp.status_code == 200

    user = await _get_user(user_id)
    assert user.failed_login_attempts == 0
    assert user.locked_until is None


@pytest.mark.asyncio
async def test_expired_lock_allows_correct_login() -> None:
    user_id = await _mk_user("locked-d@lockout.test", "LockoutOrgD")
    async with session_scope() as s:
        user = (await s.execute(select(User).where(User.id == user_id))).scalar_one()
        user.locked_until = datetime.now(UTC) - timedelta(minutes=5)
        await s.flush()

    async with _client() as c:
        resp = await c.post(
            "/api/auth/login",
            json={"email": "locked-d@lockout.test", "password": _PASSWORD},
        )
    assert resp.status_code == 200

    user = await _get_user(user_id)
    assert user.failed_login_attempts == 0
    assert user.locked_until is None
