"""Pure-ASGI security-headers middleware (SC-8/SI-10).

Deliberately does NOT use ``starlette.middleware.base.BaseHTTPMiddleware`` — that
wrapper is known to re-enter/hang under certain streaming-response and
cancellation conditions. Instead this wraps ``send`` directly and appends the
headers on the ``http.response.start`` message, only when a header of the same
name is not already present in the response.
"""

from __future__ import annotations

from starlette.types import ASGIApp, Message, Receive, Scope, Send

_HEADERS = {
    b"x-content-type-options": b"nosniff",
    b"x-frame-options": b"DENY",
    # `same-origin`, NOT `no-referrer`.
    #
    # Both withhold the referrer from cross-origin requests, which is the whole
    # privacy goal here. But per the Fetch standard's "append a request `Origin`
    # header" step, a request whose method is neither GET nor HEAD has its
    # serialized origin replaced with the literal `null` when the referrer
    # policy is `no-referrer`. So `no-referrer` silently made every browser
    # send `Origin: null` on every form submission in the application, and
    # `CsrfOriginMiddleware` -- correctly -- treats a present-but-opaque origin
    # as untrusted and refuses it.
    #
    # The result was that two security headers, each defensible alone, combined
    # to reject every state-changing form in the product while every GET still
    # worked. `same-origin` keeps the cross-origin referrer suppressed and
    # leaves the Origin intact.
    b"referrer-policy": b"same-origin",
    b"content-security-policy": (
        b"default-src 'self'; img-src 'self' data:; "
        # 'unsafe-eval' is required by the vendored Alpine.js build, which compiles
        # x-data/@click/etc. expressions via the Function constructor. Without it a
        # CSP-enforcing browser silently disables all Alpine reactivity. 'unsafe-inline'
        # covers the templates' inline <script>/<style>. Tightenable later by moving to
        # the Alpine CSP build + nonce-based inline scripts.
        b"style-src 'self' 'unsafe-inline'; "
        b"script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        b"connect-src 'self'; frame-ancestors 'none'"
    ),
}


class SecurityHeadersMiddleware:
    """Append baseline security headers to every HTTP response.

    ``hsts`` should be ``False`` in dev/test environments (no TLS) and ``True``
    otherwise — see ``config.is_dev_env``.
    """

    def __init__(self, app: ASGIApp, *, hsts: bool = True) -> None:
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                existing = {k.lower() for k, _ in headers}
                for k, v in _HEADERS.items():
                    if k not in existing:
                        headers.append((k, v))
                if self.hsts and b"strict-transport-security" not in existing:
                    headers.append(
                        (
                            b"strict-transport-security",
                            b"max-age=31536000; includeSubDomains",
                        )
                    )
            await send(message)

        await self.app(scope, receive, send_wrapper)
