"""Authentication endpoints: login (session cookie), logout, whoami."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal, sign_session, verify_password
from ...config import get_settings, is_dev_env
from ...models import User
from ..auth_deps import SESSION_COOKIE, get_principal
from ..deps import get_session

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginIn(BaseModel):
    email: str
    password: str


def _set_session_cookie(response: Response, user_id: int) -> None:
    settings = get_settings()
    token = sign_session(
        user_id, settings.auth_session_secret, ttl_hours=settings.auth_session_ttl_hours
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
async def login(
    body: LoginIn, response: Response, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    user = (
        await session.execute(
            select(User).where(User.email == body.email, User.active.is_(True))
        )
    ).scalar_one_or_none()
    now = datetime.now(UTC)
    if user is not None and user.locked_until is not None and user.locked_until > now:
        raise HTTPException(429, "account temporarily locked")
    if user is None or not verify_password(body.password, user.password_hash):
        if user is not None:
            s = get_settings()
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            if user.failed_login_attempts >= s.auth_lockout_threshold:
                user.locked_until = now + timedelta(minutes=s.auth_lockout_minutes)
                user.failed_login_attempts = 0
            await session.commit()
        raise HTTPException(401, "invalid credentials")
    if user.failed_login_attempts or user.locked_until:
        user.failed_login_attempts = 0
        user.locked_until = None
        await session.commit()
    _set_session_cookie(response, user.id)
    # IA-09: the API token is stored hashed and shown only once, at
    # issuance (CLI `user-create`) — a login response can no longer include
    # it, since the plaintext isn't recoverable from `user.api_token_hash`.
    return {
        "email": user.email,
        "role": user.role,
        "organization_id": user.organization_id,
    }


@router.post("/logout")
async def logout(response: Response) -> dict[str, bool]:
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
