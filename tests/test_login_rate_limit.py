"""Tests for the per-IP login rate limit (slowapi, ``@limiter.limit("10/minute")``
on ``POST /api/auth/login`` — see ``ccf.api.routes.auth.login``).

Auth is enabled for this module (mirrors ``tests/test_audit_rbac.py`` and
``tests/test_login_lockout.py``'s module-level harness). The DB is not
truncated between tests, so every test uses unique org/email names.

The shared ``limiter`` (``ccf.api.limiter.limiter``) uses slowapi's default
in-memory storage, which is a process-wide singleton independent of the
per-test ``create_app()`` instance — so counts persist across tests/modules
that share a key. To keep this module's tests isolated from each other (and
from other test modules that may also hit ``/api/auth/login`` from the
default test-client address), each test resets the limiter's storage first
and uses a distinct client IP.
"""

from __future__ import annotations

import os

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient

from ccf.api.limiter import limiter
from ccf.api.main import create_app
from ccf.config import get_settings

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


def _client(ip: str) -> AsyncClient:
    # A fixed, distinctive client address (TEST-NET-3, RFC 5737) so
    # ``get_remote_address`` sees a stable, real-looking ``request.client.host``
    # and so this module's rate-limit bucket is isolated per test/IP rather
    # than colliding with the shared "127.0.0.1" default other tests use.
    return AsyncClient(
        transport=ASGITransport(app=create_app(), client=(ip, 12345)),
        base_url="http://t",
    )


@pytest.mark.asyncio
async def test_rapid_login_attempts_trip_429() -> None:
    """More than 10 rapid POSTs to /api/auth/login from one IP must yield a 429.

    The credentials are wrong (no user exists for this email), so absent the
    rate limit every response would be 401 — a 429 appearing proves the
    limiter actually fires, not just that the decorator is present.
    """
    async with _client("203.0.113.10") as c:
        statuses = []
        for _ in range(15):
            resp = await c.post(
                "/api/auth/login",
                json={"email": "nobody@ratelimit.test", "password": "wrong"},
            )
            statuses.append(resp.status_code)

    assert 429 in statuses, f"expected a 429 among {statuses}"
    # Everything before the limit trips is a normal auth failure (401), and
    # nothing outside {401, 429} should appear.
    assert set(statuses) <= {401, 429}
    # The limit is 10/minute, so at least the first 10 succeed as normal
    # (non-rate-limited) auth failures before any 429 shows up.
    assert statuses[:10] == [401] * 10


@pytest.mark.asyncio
async def test_login_attempts_under_the_limit_are_not_rate_limited() -> None:
    """A handful of attempts (well under 10/minute) never see a 429."""
    async with _client("203.0.113.20") as c:
        for _ in range(5):
            resp = await c.post(
                "/api/auth/login",
                json={"email": "nobody-else@ratelimit.test", "password": "wrong"},
            )
            assert resp.status_code == 401
