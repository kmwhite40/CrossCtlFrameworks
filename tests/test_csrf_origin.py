"""Origin/Referer enforcement on state-changing requests (CSRF compensating control).

Concord authenticates browsers with a cookie and has no synchronizer tokens, so
``SameSite=Lax`` was the only thing standing between a malicious page and a
state-changing request. Lax does block cross-site POST, but it is a single
control with known gaps (a same-site subdomain, a browser that does not honour
it, any state-changing GET).

This middleware adds a second, independent check: a request that carries a
browser-supplied ``Origin`` (or ``Referer``) must have it match the host being
served, or an explicitly configured trusted origin.

Requests with *neither* header are allowed through: browsers always attach
``Origin`` to cross-origin state-changing requests, so their absence indicates a
non-browser client (CLI, SCIM provisioner, CI integration) that is not reachable
by CSRF. Blocking those would break every API consumer for no security gain.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from ccf.api.csrf import is_allowed_origin
from ccf.api.main import create_app


def _check(method: str, headers: dict[str, str], trusted: list[str] | None = None) -> bool:
    return is_allowed_origin(
        method=method,
        origin=headers.get("origin"),
        referer=headers.get("referer"),
        host=headers.get("host", "concord.example.gov"),
        trusted_origins=trusted or [],
    )


# --- safe methods are never blocked -----------------------------------------


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
def test_safe_methods_are_never_blocked(method: str) -> None:
    assert _check(method, {"origin": "https://evil.example.com"})


# --- non-browser clients ----------------------------------------------------


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_requests_without_origin_or_referer_are_allowed(method: str) -> None:
    """CLI / SCIM / CI clients send no Origin and cannot be CSRF-ed."""
    assert _check(method, {})


# --- same-origin browser traffic --------------------------------------------


@pytest.mark.parametrize(
    "origin",
    ["https://concord.example.gov", "http://concord.example.gov"],
)
def test_same_host_origin_is_allowed(origin: str) -> None:
    assert _check("POST", {"origin": origin, "host": "concord.example.gov"})


def test_same_host_with_port_is_allowed() -> None:
    assert _check("POST", {"origin": "http://localhost:8088", "host": "localhost:8088"})


# --- the attack this blocks -------------------------------------------------


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_foreign_origin_is_rejected(method: str) -> None:
    assert not _check(method, {"origin": "https://evil.example.com"})


def test_foreign_referer_is_rejected_when_origin_absent() -> None:
    assert not _check("POST", {"referer": "https://evil.example.com/attack.html"})


def test_same_origin_referer_is_allowed_when_origin_absent() -> None:
    assert _check(
        "POST",
        {"referer": "https://concord.example.gov/systems", "host": "concord.example.gov"},
    )


def test_subdomain_of_served_host_is_not_trusted() -> None:
    """A sibling/sub domain is a different origin and must not be implicitly trusted."""
    assert not _check(
        "POST",
        {"origin": "https://evil.concord.example.gov", "host": "concord.example.gov"},
    )


def test_prefix_lookalike_host_is_rejected() -> None:
    assert not _check(
        "POST",
        {"origin": "https://concord.example.gov.evil.com", "host": "concord.example.gov"},
    )


# --- explicit trust ---------------------------------------------------------


def test_configured_trusted_origin_is_allowed() -> None:
    assert _check(
        "POST",
        {"origin": "https://portal.partner.gov"},
        trusted=["https://portal.partner.gov"],
    )


def test_wildcard_cors_does_not_blanket_trust_every_origin() -> None:
    """A wildcard CORS setting must not disable CSRF checking."""
    assert not _check("POST", {"origin": "https://evil.example.com"}, trusted=["*"])


# --- wired into the app ------------------------------------------------------


@pytest.mark.asyncio
async def test_middleware_is_active_on_the_real_app() -> None:
    """End-to-end: a forged cross-origin POST is refused before reaching a route."""
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        forged = await c.post(
            "/api/auth/login",
            json={"email": "x@y.z", "password": "irrelevant"},
            headers={"origin": "https://evil.example.com"},
        )
        assert forged.status_code == 403

        # Same-origin and header-less callers are untouched.
        same_origin = await c.post(
            "/api/auth/login",
            json={"email": "x@y.z", "password": "irrelevant"},
            headers={"origin": "http://t"},
        )
        assert same_origin.status_code != 403
        no_origin = await c.post(
            "/api/auth/login", json={"email": "x@y.z", "password": "irrelevant"}
        )
        assert no_origin.status_code != 403


@pytest.mark.asyncio
async def test_rejection_response_still_carries_security_headers() -> None:
    """The guard sits inside the headers middleware, so its 403 is decorated too."""
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        resp = await c.post(
            "/api/systems",
            json={},
            headers={"origin": "https://evil.example.com"},
        )
    assert resp.status_code == 403
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("x-frame-options") == "DENY"
    assert "content-security-policy" in resp.headers
