"""Sessions must be revocable (AC-12 / ASVS 3.3.1).

The signed session cookie carried only ``{uid, exp}``, so it stayed valid for
its full TTL no matter what happened server-side. Logging out only cleared the
cookie in the caller's own browser, and changing a password did not invalidate
sessions already issued — a stolen cookie kept working for up to
``auth_session_ttl_hours``.

The token now also carries ``sv`` (session version). ``users.session_version`` is
bumped on logout and on password change, which invalidates every outstanding
cookie for that user.

Note: deactivation was already effective, because principal lookup filters on
``User.active``. That is asserted here so the property does not regress.
"""

from __future__ import annotations

import os

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.limiter import limiter
from ccf.api.main import create_app
from ccf.auth import hash_password, read_session, sign_session, verify_session
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
            role="admin",
            active=True,
            password_hash=hash_password(_PASSWORD),
        )
        s.add(user)
        await s.flush()
        return user.id


# --- token plumbing (no DB) --------------------------------------------------


def test_token_round_trips_session_version() -> None:
    tok = sign_session(7, "secret", ttl_hours=1, session_version=4)
    assert read_session(tok, "secret") == (7, 4)


def test_legacy_token_without_sv_reads_as_version_zero() -> None:
    """Tokens minted before this change must not force a fleet-wide logout."""
    legacy = sign_session(7, "secret", ttl_hours=1)
    assert read_session(legacy, "secret") == (7, 0)
    assert verify_session(legacy, "secret") == 7


def test_tampered_or_expired_tokens_are_rejected() -> None:
    assert read_session(sign_session(7, "secret", ttl_hours=1), "other") is None
    assert read_session(sign_session(7, "secret", ttl_hours=-1), "secret") is None
    assert read_session("garbage", "secret") is None


# --- end-to-end revocation ---------------------------------------------------


@pytest.mark.asyncio
async def test_logout_invalidates_the_issued_cookie() -> None:
    """The cookie must stop working server-side, not just be dropped locally."""
    email = "revoke-a@session.test"
    await _mk_user(email, "RevokeOrgA")

    async with _client() as c:
        login = await c.post("/api/auth/login", json={"email": email, "password": _PASSWORD})
        assert login.status_code == 200
        cookie = login.cookies["concord_session"]

        assert (await c.get("/api/auth/me")).status_code == 200
        assert (await c.post("/api/auth/logout")).status_code == 200

    # Replay the captured cookie on a brand-new client, as a thief would.
    async with _client() as thief:
        thief.cookies.set("concord_session", cookie)
        resp = await thief.get("/api/auth/me")
    assert resp.status_code == 401, "logged-out cookie still authenticates"


@pytest.mark.asyncio
async def test_password_change_invalidates_existing_sessions() -> None:
    email = "revoke-b@session.test"
    user_id = await _mk_user(email, "RevokeOrgB")

    async with _client() as c:
        login = await c.post("/api/auth/login", json={"email": email, "password": _PASSWORD})
        cookie = login.cookies["concord_session"]

    async with session_scope() as s:
        user = (await s.execute(select(User).where(User.id == user_id))).scalar_one()
        user.password_hash = hash_password("a-brand-new-password")
        user.session_version = (user.session_version or 0) + 1
        await s.flush()

    async with _client() as thief:
        thief.cookies.set("concord_session", cookie)
        resp = await thief.get("/api/auth/me")
    assert resp.status_code == 401, "session survived a password change"


@pytest.mark.asyncio
async def test_deactivation_invalidates_existing_sessions() -> None:
    """Pre-existing property — asserted so it cannot silently regress."""
    email = "revoke-c@session.test"
    user_id = await _mk_user(email, "RevokeOrgC")

    async with _client() as c:
        login = await c.post("/api/auth/login", json={"email": email, "password": _PASSWORD})
        cookie = login.cookies["concord_session"]

    async with session_scope() as s:
        user = (await s.execute(select(User).where(User.id == user_id))).scalar_one()
        user.active = False
        await s.flush()

    async with _client() as thief:
        thief.cookies.set("concord_session", cookie)
        resp = await thief.get("/api/auth/me")
    assert resp.status_code == 401
