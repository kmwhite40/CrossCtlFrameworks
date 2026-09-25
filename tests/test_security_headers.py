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
from ccf.api.security_headers import _HEADERS, SecurityHeadersMiddleware

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


def test_csp_allows_unsafe_eval_for_alpine():
    # Alpine.js compiles directives via the Function constructor; without
    # 'unsafe-eval' a CSP-enforcing browser silently disables all reactivity.
    csp = _HEADERS[b"content-security-policy"].decode()
    assert "'unsafe-eval'" in csp
    assert "script-src" in csp


#: Referrer policies that make a browser send ``Origin: null`` on any request
#: whose method is neither GET nor HEAD.
#:
#: From the Fetch standard, "append a request `Origin` header": for a non-GET,
#: non-HEAD request, "if request's referrer policy is `no-referrer`, then set
#: serializedOrigin to `null`". The header is still sent -- it just carries an
#: opaque origin, which any correct CSRF origin check must refuse.
ORIGIN_NULLING_REFERRER_POLICIES = frozenset({"no-referrer"})


@pytest.mark.asyncio
async def test_the_referrer_policy_does_not_null_the_origin_we_then_check() -> None:
    """Two defensible headers combined to break every form in the product.

    ``Referrer-Policy: no-referrer`` and ``CsrfOriginMiddleware`` are each
    correct in isolation. Together they were not: the policy made browsers
    send ``Origin: null`` on every POST, the CSRF check refused it as an
    opaque origin, and the result was ``cross-origin request rejected`` on
    every connector, POA&M and settings form -- while every GET kept working,
    so the app looked fine.

    ``same-origin`` withholds the referrer cross-origin exactly as before and
    leaves the origin intact. This pins the interaction rather than the
    string, so any future policy change is checked against the rule that
    matters instead of against a value someone has to remember the reason for.
    """
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        r = await client.get("/healthz")

    policy = r.headers["referrer-policy"].strip().lower()
    assert policy not in ORIGIN_NULLING_REFERRER_POLICIES, (
        f"Referrer-Policy {policy!r} makes browsers send `Origin: null` on every "
        "non-GET request, which CsrfOriginMiddleware refuses -- every form in the "
        "application would return `cross-origin request rejected`"
    )
    # Still withholding the referrer cross-origin: the reason the header exists.
    assert policy in {"same-origin", "strict-origin", "strict-origin-when-cross-origin"}


@pytest.mark.asyncio
async def test_an_opaque_origin_is_still_refused_by_the_csrf_check() -> None:
    """The fix is the policy, not loosening the check.

    Pinned because the tempting shortcut -- allowing ``Origin: null`` through
    CSRF -- would have made the symptom disappear while admitting exactly the
    sandboxed-frame and redirected-form cases the check exists to stop.
    """
    from ccf.api.csrf import is_allowed_origin

    assert not is_allowed_origin(
        method="POST",
        origin="null",
        referer=None,
        host="localhost:8088",
        trusted_origins=(),
    )
