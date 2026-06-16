"""Auth dependencies + gate middleware: resolve the Principal, enforce roles."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.base import RequestResponseEndpoint

from ..auth import SYSTEM_PRINCIPAL, Principal, verify_session
from ..config import get_settings
from ..db import get_session_factory
from ..models import System, User
from .deps import get_session

SESSION_COOKIE = "concord_session"

# Paths reachable without authentication even when auth is enabled.
_PUBLIC_PREFIXES = (
    "/api/auth",
    "/login",
    "/logout",
    "/healthz",
    "/readyz",
    "/livez",
    "/metrics",
    "/static",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/favicon",
)


async def _lookup_principal(request: Request, session: AsyncSession) -> Principal | None:
    """Resolve a Principal from a bearer token or signed session cookie (or None)."""
    settings = get_settings()
    user: User | None = None
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if token:
            user = (
                await session.execute(
                    select(User).where(User.api_token == token, User.active.is_(True))
                )
            ).scalar_one_or_none()
    if user is None:
        cookie = request.cookies.get(SESSION_COOKIE)
        if cookie:
            uid = verify_session(cookie, settings.auth_session_secret)
            if uid is not None:
                user = (
                    await session.execute(
                        select(User).where(User.id == uid, User.active.is_(True))
                    )
                ).scalar_one_or_none()
    if user is None:
        return None
    return Principal(
        user_id=user.id, email=user.email, org_id=user.organization_id, role=user.role
    )


async def get_principal(
    request: Request, session: AsyncSession = Depends(get_session)
) -> Principal:
    """Dependency: the authenticated caller (open SYSTEM principal when auth off)."""
    if not get_settings().auth_enabled:
        request.state.principal = SYSTEM_PRINCIPAL
        return SYSTEM_PRINCIPAL
    existing = getattr(request.state, "principal", None)
    if isinstance(existing, Principal):
        return existing
    principal = await _lookup_principal(request, session)
    if principal is None:
        raise HTTPException(401, "authentication required")
    request.state.principal = principal
    return principal


def org_systems_subq(principal: Principal) -> Any:
    """Subquery of System ids in the principal's org. Callers apply it only when
    ``principal.org_id`` is set (global principals are unscoped)."""
    return select(System.id).where(System.organization_id == principal.org_id)


def require_role(*roles: str) -> Callable[..., Awaitable[Principal]]:
    """Dependency factory enforcing one of ``roles`` (SYSTEM principal bypasses)."""

    async def _dep(principal: Principal = Depends(get_principal)) -> Principal:
        if principal.is_global or principal.role in roles:
            return principal
        raise HTTPException(403, f"requires role: {', '.join(roles)}")

    return _dep


async def auth_gate_middleware(
    request: Request, call_next: RequestResponseEndpoint
) -> Response:
    """When auth is enabled, require a valid principal for non-public paths.

    API paths get a 401; browser paths are redirected to ``/login``. Sets
    ``request.state.principal`` so downstream deps/audit reuse it.
    """
    if not get_settings().auth_enabled:
        return await call_next(request)
    path = request.url.path
    if path != "/" and not any(path.startswith(p) for p in _PUBLIC_PREFIXES):
        factory = get_session_factory()
        async with factory() as session:
            principal = await _lookup_principal(request, session)
        if principal is None:
            if path.startswith("/api"):
                return JSONResponse({"detail": "authentication required"}, status_code=401)
            return RedirectResponse("/login", status_code=303)
        request.state.principal = principal
    return await call_next(request)
