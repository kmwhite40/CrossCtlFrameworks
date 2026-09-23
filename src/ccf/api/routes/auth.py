"""Authentication endpoints: login, the second factor, logout, and /me.

TOTP enrolment and verification live here rather than in a module of their own
because the second factor is a step of login, and splitting it would put the
two halves of one decision in two files.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ... import mfa
from ...auth import Principal, sign_session
from ...config import get_settings, is_dev_env
from ...identity import mfa_service
from ...models import User
from ..audit import record_event
from ..auth_deps import SESSION_COOKIE, get_principal
from ..deps import get_session
from ..limiter import limiter
from ..login_service import (
    LoginResult,
    authenticate,
    complete_login,
    mint_mfa_pending,
    read_mfa_pending,
    record_failed_factor,
    revoke_sessions_for_request,
)

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
    if result is LoginResult.MFA_REQUIRED and user is not None:
        # Deliberately no session cookie. The pending token is signed with a
        # derived key (see login_service._mfa_pending_secret) so it cannot be
        # replayed as one.
        return {"mfa_required": True, "mfa_token": mint_mfa_pending(user)}
    # Tested against OK rather than ``user is None``: MFA_REQUIRED also carries
    # a user, and a truthiness check here would issue a session for it.
    if result is not LoginResult.OK or user is None:
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


# --- second factor ------------------------------------------------------------


class MfaVerifyIn(BaseModel):
    mfa_token: str
    code: str


@router.post("/mfa/verify")
@limiter.limit("10/minute")
async def mfa_verify(
    request: Request,
    body: MfaVerifyIn,
    response: Response,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Exchange a pending token plus a code for a real session.

    A TOTP code or a recovery code; both are accepted here so a user who has
    lost their authenticator has a way in that does not involve an
    administrator, and both are audited distinctly.
    """
    claims = read_mfa_pending(body.mfa_token)
    if claims is None:
        raise HTTPException(401, "invalid or expired login")
    user_id, session_version = claims
    user = await session.get(User, user_id)
    if user is None or not user.active:
        raise HTTPException(401, "invalid or expired login")
    # The pending token predates any revocation that has happened since.
    if (user.session_version or 0) != session_version:
        raise HTTPException(401, "invalid or expired login")
    if user.locked_until is not None and user.locked_until > datetime.now(UTC):
        raise HTTPException(429, "account temporarily locked")

    now = time.time()
    method = "totp"
    ok = await mfa_service.verify_code(session, user.id, body.code, now=now)
    if not ok:
        method = "recovery_code"
        ok = await mfa_service.consume_recovery_code(session, user.id, body.code)
    if not ok:
        result = await record_failed_factor(session, user)
        if result is LoginResult.LOCKED:
            raise HTTPException(429, "account temporarily locked")
        raise HTTPException(401, "invalid code")

    await record_event(
        session,
        actor=user.email,
        action="mfa_verify",
        entity_type="identity",
        entity_id=str(user.id),
        diff={"event": "mfa_verify", "method": method},
        organization_id=user.organization_id,
    )
    await complete_login(session, user)
    _set_session_cookie(response, user.id, user.session_version or 0)
    return {
        "email": user.email,
        "role": user.role,
        "organization_id": user.organization_id,
        "mfa_method": method,
    }


@router.get("/mfa")
async def mfa_status(
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    if principal.user_id is None:
        raise HTTPException(401, "not signed in")
    cred = await mfa_service.credential_for(session, principal.user_id)
    user = await session.get(User, principal.user_id)
    return {
        "enrolled": cred is not None,
        "active": cred is not None and cred.activated_at is not None,
        "recovery_codes_remaining": await mfa_service.unused_recovery_code_count(
            session, principal.user_id
        ),
        "required_by_policy": (
            await mfa_service.policy_requires_enrolment(session, user) if user else False
        ),
    }


@router.post("/mfa/enroll")
async def mfa_enroll(
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Begin enrolment. The secret is returned exactly once, here."""
    if principal.user_id is None:
        raise HTTPException(401, "not signed in")
    user = await session.get(User, principal.user_id)
    if user is None:
        raise HTTPException(401, "not signed in")
    try:
        secret, uri = await mfa_service.begin_enrolment(session, user)
    except ValueError as e:
        raise HTTPException(409, str(e)) from e
    await session.commit()
    return {
        "secret": secret,
        "manual_entry": mfa.format_for_manual_entry(secret),
        "otpauth_uri": uri,
    }


class MfaActivateIn(BaseModel):
    code: str


@router.post("/mfa/activate")
async def mfa_activate(
    body: MfaActivateIn,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Prove the authenticator works, then turn it on.

    Recovery codes are returned here and never again -- only their digests are
    stored.
    """
    if principal.user_id is None:
        raise HTTPException(401, "not signed in")
    user = await session.get(User, principal.user_id)
    if user is None:
        raise HTTPException(401, "not signed in")
    codes = await mfa_service.activate(session, user, body.code, now=time.time())
    if codes is None:
        raise HTTPException(400, "that code did not match; the authenticator is not active")
    await record_event(
        session,
        actor=user.email,
        action="mfa_activate",
        entity_type="identity",
        entity_id=str(user.id),
        diff={"event": "mfa_activate"},
        organization_id=user.organization_id,
    )
    await session.commit()
    return {"active": True, "recovery_codes": codes}


@router.delete("/mfa", status_code=204)
async def mfa_disable(
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> Response:
    """Remove the authenticator, unless the organization requires one."""
    if principal.user_id is None:
        raise HTTPException(401, "not signed in")
    user = await session.get(User, principal.user_id)
    if user is None:
        raise HTTPException(401, "not signed in")
    if await mfa_service.policy_requires_enrolment(session, user):
        raise HTTPException(409, "your organization requires a second factor")
    cred = await mfa_service.credential_for(session, user.id)
    if cred is not None:
        await session.delete(cred)
        await record_event(
            session,
            actor=user.email,
            action="mfa_disable",
            entity_type="identity",
            entity_id=str(user.id),
            diff={"event": "mfa_disable"},
            organization_id=user.organization_id,
        )
        await session.commit()
    return Response(status_code=204)
