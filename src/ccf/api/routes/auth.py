"""Authentication endpoints: login (session cookie), logout, whoami."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal, sign_session
from ...config import get_settings, is_dev_env
from ..auth_deps import SESSION_COOKIE, get_principal
from ..deps import get_session
from ..limiter import limiter
from ..login_service import LoginResult, authenticate, revoke_sessions_for_request

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginIn(BaseModel):
    email: str
    password: str


def _set_session_cookie(response: Response, user_id: int, session_version: int = 0) -> None:
    settings = get_settings()
    token = sign_session(
        user_id,
        settings.auth_session_secret,
        ttl_hours=settings.auth_session_ttl_hours,
        session_version=session_version,
    )
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=settings.auth_session_ttl_hours * 3600,
        httponly=True,
        samesite="lax",
        secure=not is_dev_env(settings),
    )


@router.post("/login")
@limiter.limit("10/minute")
async def login(
    request: Request,
    body: LoginIn,
    response: Response,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    user, result = await authenticate(session, body.email, body.password)
    if result is LoginResult.LOCKED:
        raise HTTPException(429, "account temporarily locked")
    if user is None:
        raise HTTPException(401, "invalid credentials")
    _set_session_cookie(response, user.id, user.session_version or 0)
    # IA-09: the API token is stored hashed and shown only once, at
    # issuance (CLI `user-create`) — a login response can no longer include
    # it, since the plaintext isn't recoverable from `user.api_token_hash`.
    return {
        "email": user.email,
        "role": user.role,
        "organization_id": user.organization_id,
    }


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_session),
) -> dict[str, bool]:
    """Clear the cookie *and* revoke it server-side (AC-12).

    Deleting the cookie only affects the caller's own browser. Bumping
    ``session_version`` is what stops a copy of the token that was captured
    elsewhere from continuing to work for the rest of its TTL.

    Stays callable while anonymous — logging out is never an error.
    """
    await revoke_sessions_for_request(request, session)
    response.delete_cookie(SESSION_COOKIE)
    return {"ok": True}


@router.get("/me")
async def me(principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    return {
        "user_id": principal.user_id,
        "email": principal.email,
        "organization_id": principal.org_id,
        "role": principal.role,
        "is_global": principal.is_global,
    }
