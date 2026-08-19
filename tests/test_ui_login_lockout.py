"""The HTML form login must enforce the same AC-7 brute-force controls as the API.

``POST /login`` (the browser form in ``api/routes/ui.py``) previously performed a
bare ``verify_password`` check: it neither incremented ``failed_login_attempts``
nor honoured ``locked_until``. An attacker could therefore bypass the lockout
enforced on ``POST /api/auth/login`` entirely by pointing the same password
spray at the form endpoint.

Both routes now share ``api.login_service.authenticate``.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.limiter import limiter
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
    limiter.reset()
    yield
    limiter.reset()
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _mk_user(email: str, org_name: str) -> int:
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


async def _get_user(email: str) -> User:
    async with session_scope() as s:
        return (await s.execute(select(User).where(User.email == email))).scalar_one()


@pytest.mark.asyncio
async def test_form_login_increments_failed_attempts_and_locks() -> None:
    """Failed form logins must count toward the lockout threshold."""
    email = "ui-lock-a@lockout.test"
    await _mk_user(email, "UiLockoutOrgA")
    threshold = get_settings().auth_lockout_threshold

    async with _client() as c:
        for _ in range(threshold):
            resp = await c.post("/login", data={"email": email, "password": "wrong-password"})
            assert resp.status_code == 303

    user = await _get_user(email)
    assert user.locked_until is not None, "form login did not lock the account"
    assert user.locked_until > datetime.now(UTC)


@pytest.mark.asyncio
async def test_form_login_refuses_locked_account_with_correct_password() -> None:
    """A locked account must not be able to sign in through the form either."""
    email = "ui-lock-b@lockout.test"
    user_id = await _mk_user(email, "UiLockoutOrgB")
    async with session_scope() as s:
        user = (await s.execute(select(User).where(User.id == user_id))).scalar_one()
        user.locked_until = datetime.now(UTC) + timedelta(minutes=15)
        await s.flush()

    async with _client() as c:
        resp = await c.post("/login", data={"email": email, "password": _PASSWORD})

    assert resp.status_code == 303
    # Refused: redirected back to the login form, and no session cookie issued.
    assert "/login" in resp.headers.get("location", "")
    assert "concord_session" not in resp.cookies


@pytest.mark.asyncio
async def test_form_login_success_resets_counters() -> None:
    email = "ui-lock-c@lockout.test"
    await _mk_user(email, "UiLockoutOrgC")

    async with _client() as c:
        for _ in range(2):
            await c.post("/login", data={"email": email, "password": "wrong-password"})
        resp = await c.post("/login", data={"email": email, "password": _PASSWORD})

    assert resp.status_code == 303
    assert resp.headers.get("location") == "/"
    user = await _get_user(email)
    assert user.failed_login_attempts == 0
    assert user.locked_until is None


@pytest.mark.asyncio
async def test_form_login_is_rate_limited() -> None:
    """SC-5: the form login must carry a per-IP rate limit like the API login."""
    email = "ui-lock-d@lockout.test"
    await _mk_user(email, "UiLockoutOrgD")

    saw_429 = False
    async with _client() as c:
        for _ in range(15):
            resp = await c.post("/login", data={"email": email, "password": "wrong-password"})
            if resp.status_code == 429:
                saw_429 = True
                break
    assert saw_429, "form login accepted >10 attempts/minute from one IP"
