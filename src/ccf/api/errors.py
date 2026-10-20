"""Readable error pages for people, unchanged JSON for everything else.

A browser that followed a link to a page it may not see used to get
``{"detail": "..."}`` as raw text. That is correct for an API client and a dead
end for a person. This handler renders the shell with what happened and where
to go instead -- but only when the request asks for HTML (a browser's
``Accept``) and is not an API or static path, so every API client, test and
integration keeps the exact JSON error it relied on.

The status code and any headers on the exception (``WWW-Authenticate``,
``Retry-After``) are preserved: a 403 page is still a 403.
"""

from __future__ import annotations

from fastapi import Request
from fastapi.exception_handlers import (
    http_exception_handler,
    request_validation_exception_handler,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import Response
from starlette.exceptions import HTTPException as StarletteHTTPException

_TITLES = {
    401: "Sign in to continue",
    403: "You don't have access to this page",
    404: "We couldn't find that",
    405: "That action isn't available here",
    409: "That conflicts with the record's current state",
    422: "Some of what was sent isn't valid",
    429: "Too many requests",
}


def wants_html(request: Request) -> bool:
    path = request.url.path
    if path.startswith(("/api/", "/static/", "/metrics", "/healthz", "/readyz")):
        return False
    accept = request.headers.get("accept", "")
    return "text/html" in accept and request.headers.get("hx-request") != "true"


def _render(request: Request, status: int, detail: str | None, headers: dict | None) -> Response:
    from .routes.ui import templates  # noqa: PLC0415 - avoid an import cycle at app build

    principal = getattr(request.state, "principal", None)
    return templates.TemplateResponse(
        request,
        "error.html",
        {
            "active": None,
            "status": status,
            "title": _TITLES.get(status, "Something went wrong"),
            "detail": detail,
            "role": getattr(principal, "role", None),
        },
        status_code=status,
        headers=headers,
    )


async def html_aware_http_exception(request: Request, exc: StarletteHTTPException) -> Response:
    if not wants_html(request):
        return await http_exception_handler(request, exc)
    detail = exc.detail if isinstance(exc.detail, str) else None
    return _render(request, exc.status_code, detail, getattr(exc, "headers", None))


async def html_aware_validation_error(request: Request, exc: RequestValidationError) -> Response:
    """A malformed link a person followed (a bad query value) gets the page;
    the field-level JSON stays for clients. The detail names the fields only:
    the submitted values are not echoed back."""
    if not wants_html(request):
        return await request_validation_exception_handler(request, exc)
    fields = sorted(
        {".".join(str(p) for p in err.get("loc", ())[1:]) or "request" for err in exc.errors()}
    )
    return _render(request, 422, f"Check: {', '.join(fields)}", None)
