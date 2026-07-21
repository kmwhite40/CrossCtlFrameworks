"""Auth dependencies + gate middleware: resolve the Principal, enforce roles."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.base import RequestResponseEndpoint

from ..auth import SYSTEM_PRINCIPAL, Principal, hash_token, verify_session
from ..config import get_settings
from ..db import get_session_factory, set_session_tenant
from ..models import System, User

SESSION_COOKIE = "concord_session"

# Paths reachable without authentication even when auth is enabled.
_PUBLIC_PREFIXES = (
    "/api/auth",
    "/auth/login",
    "/auth/callback",
    "/auth/logout",
    "/api/scim",  # SCIM uses its own bearer token, not the user session
    "/api/portal",  # external portal API — the grant token is the credential
    "/portal",  # external portal UI — token supplied via ?token=
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
                    select(User).where(
                        User.api_token_hash == hash_token(token), User.active.is_(True)
                    )
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


async def get_principal_optional(request: Request) -> Principal | None:
    """Resolve the caller without forcing auth (returns ``None`` if anonymous).

    Used to bind the request session's tenant context. Resolution runs on its own
    short-lived, unscoped (bypass) session so it can read ``users`` across orgs
    *before* the tenant context is known. Pre-auth/public routes (e.g. login) get
    ``None`` and therefore an unscoped session; protected routes are already gated
    by ``auth_gate_middleware`` (which sets ``request.state.principal``).
    """
    if not get_settings().auth_enabled:
        request.state.principal = SYSTEM_PRINCIPAL
        return SYSTEM_PRINCIPAL
    existing = getattr(request.state, "principal", None)
    if isinstance(existing, Principal):
        return existing
    factory = get_session_factory()
    async with factory() as session:
        await set_session_tenant(session, None)
        principal = await _lookup_principal(request, session)
    if principal is not None:
        request.state.principal = principal
    return principal


async def get_principal(request: Request) -> Principal:
    """Dependency: the authenticated caller (open SYSTEM principal when auth off).

    Raises 401 when auth is enabled and the caller is anonymous.
    """
    principal = await get_principal_optional(request)
    if principal is None:
        raise HTTPException(401, "authentication required")
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
            await set_session_tenant(session, None)
            principal = await _lookup_principal(request, session)
        if principal is None:
            if path.startswith("/api"):
                return JSONResponse({"detail": "authentication required"}, status_code=401)
            return RedirectResponse("/login", status_code=303)
        request.state.principal = principal
    return await call_next(request)
