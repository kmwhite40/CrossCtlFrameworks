"""IMPORTANT 5 (PR #16 review): /metrics must not expose every tenant's
per-system posture (``ccf_posture_failing_resources``, the pre-existing
``ccf_fedramp20x_readiness_pct``) to any authenticated caller.
``auth_gate_middleware`` alone only requires *a* valid principal, any role,
any tenant -- this pins the operator-level gate added in ``metrics_endpoint``,
and that the pre-existing ``CCF_METRICS_REQUIRE_AUTH=false`` escape hatch for
an anonymous-scrape deployment still works unauthenticated.
"""

from __future__ import annotations

import os

import pytest
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, User


@pytest.fixture(autouse=True)
def _auth_enabled():
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
async def test_unauthenticated_refused() -> None:
    """/metrics is not under /api, so the pre-existing auth_gate_middleware
    treats it as a browser path and redirects to /login rather than 401 --
    this pins that it is refused at all, not the exact status of that refusal
    (the role gate inside metrics_endpoint is never reached)."""
    async with _client() as c:
        r = await c.get("/metrics", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/login"


@pytest.mark.asyncio
async def test_a_viewer_in_one_tenant_is_refused() -> None:
    """The defect: a low-privilege, authenticated caller in ANY tenant could
    read every other tenant's posture gauges. Must now be a 403."""
    token = await _mk_user("viewer@metrics-rbac.test", "Metrics RBAC Viewer Org", "viewer")
    async with _client() as c:
        r = await c.get("/metrics", headers=_auth(token))
        assert r.status_code == 403


@pytest.mark.asyncio
async def test_an_admin_is_allowed() -> None:
    token = await _mk_user("admin@metrics-rbac.test", "Metrics RBAC Admin Org", "admin")
    async with _client() as c:
        r = await c.get("/metrics", headers=_auth(token))
        assert r.status_code == 200
        assert b"ccf_http_requests_total" in r.content


@pytest.mark.asyncio
async def test_the_anonymous_scrape_escape_hatch_still_works() -> None:
    """CCF_METRICS_REQUIRE_AUTH=false is the pre-existing opt-out for a
    deployment that scrapes anonymously and restricts /metrics at the network
    layer instead -- the new role gate must not re-require auth it turned off."""
    os.environ["CCF_METRICS_REQUIRE_AUTH"] = "false"
    get_settings.cache_clear()
    try:
        async with _client() as c:
            r = await c.get("/metrics")
            assert r.status_code == 200
    finally:
        os.environ.pop("CCF_METRICS_REQUIRE_AUTH", None)
        get_settings.cache_clear()
