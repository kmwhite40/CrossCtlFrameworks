"""Origin/Referer enforcement for state-changing requests (CSRF defense in depth).

Concord authenticates browsers with a session cookie and issues no synchronizer
tokens, so ``SameSite=Lax`` was the only barrier against a malicious page
driving a state-changing request with the victim's credentials. Lax is a real
mitigation, but it is a *single* one, and it does not cover a hostile same-site
subdomain or a client that ignores the attribute.

This middleware adds an independent check. It is deliberately conservative
about what it rejects:

* Safe methods (GET/HEAD/OPTIONS) are never blocked — they are also how the
  CORS preflight and every page load arrive.
* A request carrying neither ``Origin`` nor ``Referer`` is allowed. Browsers
  always attach ``Origin`` to cross-origin state-changing requests, so the
  absence of both marks a non-browser caller (the ``ccf`` CLI, a SCIM
  provisioner, CI) that CSRF cannot reach. Rejecting those would break every
  API integration and buy nothing.
* Otherwise the origin's host must equal the host being served, or appear in
  ``CCF_CSRF_TRUSTED_ORIGINS``.

Written as pure ASGI for the same reason as ``security_headers`` — Starlette's
``BaseHTTPMiddleware`` can re-enter or hang around streaming responses.
"""

from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import urlsplit

from starlette.types import ASGIApp, Receive, Scope, Send

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})

_DENIED_BODY = b'{"detail":"cross-origin request rejected"}'


def _host_of(url: str) -> str | None:
    """Return the ``host[:port]`` of an absolute URL, or ``None`` if unusable."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if not parts.scheme or not parts.netloc:
        return None
    # netloc may carry userinfo (user:pass@host); the host is what matters.
    return parts.netloc.rsplit("@", 1)[-1].lower()


def is_allowed_origin(
    *,
    method: str,
    origin: str | None,
    referer: str | None,
    host: str | None,
    trusted_origins: Iterable[str],
) -> bool:
    """True when the request may proceed under the CSRF policy described above."""
    if method.upper() in _SAFE_METHODS:
        return True

    candidate = origin if origin else referer
    if not candidate:
        return True  # non-browser client — see module docstring

    # "null" is what a sandboxed iframe / redirected form sends; treat it as a
    # present-but-untrusted origin rather than as absent. An unparseable value
    # is likewise untrusted.
    candidate_host = None if candidate == "null" else _host_of(candidate)
    if candidate_host is None:
        return False

    allowed = {host.lower()} if host else set()
    # A wildcard CORS origin must not blanket-disable CSRF checking.
    allowed |= {_host_of(t) or t.lower() for t in trusted_origins if t != "*"}
    return candidate_host in allowed


class CsrfOriginMiddleware:
    """Reject state-changing requests from an untrusted browser origin."""

    def __init__(self, app: ASGIApp, *, trusted_origins: Iterable[str] = ()) -> None:
        self.app = app
        self.trusted_origins = tuple(trusted_origins)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        if not is_allowed_origin(
            method=scope.get("method", "GET"),
            origin=headers.get("origin"),
            referer=headers.get("referer"),
            host=headers.get("host"),
            trusted_origins=self.trusted_origins,
        ):
            await send(
                {
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(_DENIED_BODY)).encode()),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": _DENIED_BODY})
            return

        await self.app(scope, receive, send)
