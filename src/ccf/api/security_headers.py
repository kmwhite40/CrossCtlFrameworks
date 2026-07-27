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
    b"referrer-policy": b"no-referrer",
    b"content-security-policy": (
        b"default-src 'self'; img-src 'self' data:; "
        b"style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
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
