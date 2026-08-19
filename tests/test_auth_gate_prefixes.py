"""The auth gate must match public paths on segment boundaries, not raw prefixes.

``_PUBLIC_PREFIXES`` was compared with a bare ``str.startswith``, so any route
whose path merely *began* with a public entry skipped the gate. In practice
``/api/authorization-packages`` matched the ``/api/auth`` entry and the whole
authorization-package router bypassed ``auth_gate_middleware``.

That was not exploitable — every one of those routes also carries an explicit
``Depends(get_principal)`` — but it is a latent bypass: the next route added
under a colliding prefix without its own dependency would be silently anonymous.
"""

from __future__ import annotations

import pytest

from ccf.api.auth_deps import is_public_path
from ccf.config import get_settings


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/login",
        "/logout",
        "/healthz",
        "/readyz",
        "/livez",
        "/docs",
        "/docs/oauth2-redirect",
        "/redoc",
        "/openapi.json",
        "/static/css/app.css",
        "/favicon.ico",
        "/api/auth/login",
        "/api/auth/logout",
        "/api/scim/v2/Users",
        "/api/portal/session",
        "/portal",
        "/auth/login",
        "/auth/callback",
    ],
)
def test_genuinely_public_paths_stay_public(path: str) -> None:
    assert is_public_path(path), f"{path} must remain reachable pre-auth"


@pytest.mark.parametrize(
    "path",
    [
        # The actual defect: these share the "/api/auth" text prefix but are a
        # different resource entirely.
        "/api/authorization-packages",
        "/api/authorization-packages/1",
        "/api/authorization-packages/1/provenance",
        "/api/authorization-packages/1/replay",
        # Generic siblings that must not inherit a public prefix's exemption.
        "/api/authz",
        "/api/portalx",
        "/loginsomething",
        "/metricsx",
        "/staticfiles",
        "/api/systems",
        "/api/users",
    ],
)
def test_prefix_lookalikes_are_not_public(path: str) -> None:
    assert not is_public_path(path), f"{path} must NOT bypass the auth gate"


def test_metrics_requires_auth_by_default() -> None:
    """AC-3: telemetry is not anonymous unless explicitly opened up."""
    assert not is_public_path("/metrics")


def test_metrics_can_be_reopened_for_unauthenticated_scrapers(monkeypatch) -> None:
    """The opt-out exists so an existing Prometheus scrape is not broken silently."""
    monkeypatch.setenv("CCF_METRICS_REQUIRE_AUTH", "false")
    get_settings.cache_clear()
    try:
        assert is_public_path("/metrics")
    finally:
        monkeypatch.delenv("CCF_METRICS_REQUIRE_AUTH", raising=False)
        get_settings.cache_clear()
