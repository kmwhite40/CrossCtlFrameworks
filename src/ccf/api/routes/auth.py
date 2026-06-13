"""Authentication endpoints: login (session cookie), logout, whoami."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal, sign_session, verify_password
from ...config import get_settings
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
        secure=settings.env == "prod",
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
    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(401, "invalid credentials")
    _set_session_cookie(response, user.id)
    return {
        "email": user.email,
        "role": user.role,
        "organization_id": user.organization_id,
        "api_token": user.api_token,
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
