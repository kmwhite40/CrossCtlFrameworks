"""The middleware stack's order is load-bearing, so it is pinned here.

Starlette inserts each registration at position 0 and builds the app with
``reversed(user_middleware)``, so the LAST one added is OUTERMOST. That is easy
to get backwards, and getting it backwards is silent: the stack still works,
just with guards above the things that were meant to wrap them.

Two defects came from exactly that:

* ``CORSMiddleware`` was innermost. A browser preflight (``OPTIONS``) carries
  neither cookie nor ``Authorization`` by spec, so the auth gate answered it
  401 with no ``Access-Control-*`` headers — every preflighted cross-origin
  request failed whenever auth was enabled.
* ``SecurityHeadersMiddleware`` sat below the auth gate, so 401s and ``/login``
  redirects shipped with no CSP and no HSTS.

Neither was caught because ``auth_enabled`` defaults to false, so the suite only
ever assembled a stack without the auth gate.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from ccf.api.main import create_app
from ccf.config import get_settings

# Outermost -> innermost.
EXPECTED_FULL = [
    "CORSMiddleware",
    "SecurityHeadersMiddleware",
    "metrics_middleware",
    "CsrfOriginMiddleware",
    "auth_gate_middleware",
    "audit_middleware",
]


def _names(app) -> list[str]:
    """Middleware names, outermost first.

    ``app.middleware("http")(fn)`` registers ``BaseHTTPMiddleware`` with the
    function passed as ``dispatch``, so the class name alone cannot tell three
    of these apart — resolve through to the wrapped function.
    """
    out = []
    for m in app.user_middleware:
        dispatch = m.kwargs.get("dispatch") if getattr(m, "kwargs", None) else None
        out.append(getattr(dispatch, "__name__", None) or m.cls.__name__)
    return out


@pytest.fixture
def auth_on() -> Iterator[None]:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


def test_full_stack_order_with_auth_enabled(auth_on: None) -> None:
    """The production shape. No test exercised this before."""
    assert _names(create_app()) == EXPECTED_FULL


def test_default_stack_keeps_the_same_relative_order() -> None:
    """With auth off the gate is absent; everything else keeps its position."""
    names = _names(create_app())
    assert "auth_gate_middleware" not in names
    assert names == [n for n in EXPECTED_FULL if n != "auth_gate_middleware"]


def test_cors_is_outermost(auth_on: None) -> None:
    """So a preflight is answered before any guard can 401 it."""
    assert _names(create_app())[0] == "CORSMiddleware"


def test_security_headers_wrap_every_guard(auth_on: None) -> None:
    """Anything that can short-circuit must sit below the headers middleware."""
    names = _names(create_app())
    headers = names.index("SecurityHeadersMiddleware")
    for guard in ("CsrfOriginMiddleware", "auth_gate_middleware"):
        assert names.index(guard) > headers, f"{guard} can short-circuit above the headers"


def test_metrics_counts_rejections(auth_on: None) -> None:
    """Metrics above the auth gate, so a 401 spike is visible."""
    names = _names(create_app())
    assert names.index("metrics_middleware") < names.index("auth_gate_middleware")


def test_auth_gate_runs_before_audit(auth_on: None) -> None:
    """auth_gate sets request.state.principal; the audit middleware reads it."""
    names = _names(create_app())
    assert names.index("auth_gate_middleware") < names.index("audit_middleware")
