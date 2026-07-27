"""Security-headers middleware (SC-8/SI-10) — see ``ccf.api.security_headers``.

``SecurityHeadersMiddleware`` is pure-ASGI (not ``BaseHTTPMiddleware``) and appends
baseline headers to every HTTP response, without overwriting a header a route
already set. HSTS is gated by the ``hsts`` flag (wired to ``not is_dev_env`` in
``main.py``); tests run under ``env=test``, which counts as dev, so HSTS is off
in the default app and must be asserted separately with the flag forced on.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.api.security_headers import SecurityHeadersMiddleware

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.mark.asyncio
async def test_default_app_carries_baseline_security_headers() -> None:
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        r = await c.get("/healthz")
    assert r.status_code == 200
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"]
    assert r.headers["content-security-policy"]


@pytest.mark.asyncio
async def test_default_app_omits_hsts_in_dev_test_env() -> None:
    """env=test is treated as dev (no TLS assumed), so hsts=False is wired in
    main.py and the header must not be present."""
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        r = await c.get("/healthz")
    assert "strict-transport-security" not in r.headers


@pytest.mark.asyncio
async def test_hsts_header_added_when_enabled() -> None:
    app = create_app()
    app.add_middleware(SecurityHeadersMiddleware, hsts=True)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/healthz")
    assert r.status_code == 200
    assert r.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
