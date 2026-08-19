"""Shared credential verification for both login surfaces (AC-7 / IA-5).

Concord exposes two ways to sign in: the JSON API (``POST /api/auth/login``) and
the browser form (``POST /login``). The brute-force controls — failed-attempt
counting and time-boxed account lockout — must be identical on both, otherwise
an attacker simply aims a password spray at whichever surface lacks them.

Keeping the logic here (rather than duplicating it per route) means a future
change to the lockout policy cannot drift between the two entry points.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum

from fastapi import Request
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import read_session, verify_password
from ..config import get_settings
from ..models import User


class LoginResult(StrEnum):
    """Outcome of a credential check.

    ``LOCKED`` is deliberately distinct from ``INVALID`` so each surface can map
    it to its own idiom (HTTP 429 for the API, an error banner for the form)
    without re-deriving the lockout state.
    """

    OK = "ok"
    INVALID = "invalid"
    LOCKED = "locked"


async def authenticate(
    session: AsyncSession, email: str, password: str
) -> tuple[User | None, LoginResult]:
    """Verify credentials and apply the AC-7 lockout policy.

    Returns ``(user, LoginResult.OK)`` on success, and ``(None, ...)`` otherwise.
    On failure the attempt counter is incremented and, once
    ``auth_lockout_threshold`` is reached, ``locked_until`` is set. A successful
    login clears both counters.

    A locked account is refused **before** the password is checked, so a correct
    password cannot shorten an active lockout window.
    """
    settings = get_settings()
    user = (
        await session.execute(select(User).where(User.email == email, User.active.is_(True)))
    ).scalar_one_or_none()
    now = datetime.now(UTC)

    if user is not None and user.locked_until is not None and user.locked_until > now:
        return None, LoginResult.LOCKED

    if user is None or not verify_password(password, user.password_hash):
        if user is not None:
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            if user.failed_login_attempts >= settings.auth_lockout_threshold:
                user.locked_until = now + timedelta(minutes=settings.auth_lockout_minutes)
                user.failed_login_attempts = 0
            await session.commit()
        return None, LoginResult.INVALID

    if user.failed_login_attempts or user.locked_until:
        user.failed_login_attempts = 0
        user.locked_until = None
        await session.commit()
    return user, LoginResult.OK


async def revoke_sessions(session: AsyncSession, user_id: int) -> None:
    """Invalidate every session cookie already issued for ``user_id`` (AC-12).

    Issued as an atomic ``session_version = session_version + 1`` so concurrent
    logouts cannot read-modify-write over each other.
    """
    await session.execute(
        update(User).where(User.id == user_id).values(session_version=User.session_version + 1)
    )
    await session.commit()


async def revoke_sessions_for_request(request: Request, session: AsyncSession) -> None:
    """Revoke the sessions of whoever owns the request's session cookie.

    Used by the logout routes, which stay reachable while anonymous — an
    unparseable, expired, or absent cookie is simply a no-op.
    """
    # Imported here to avoid a circular import: auth_deps imports this module's
    # siblings, and deps.get_session depends on auth_deps.
    from .auth_deps import SESSION_COOKIE  # noqa: PLC0415

    cookie = request.cookies.get(SESSION_COOKIE)
    if not cookie:
        return
    claims = read_session(cookie, get_settings().auth_session_secret)
    if claims is None:
        return
    await revoke_sessions(session, claims[0])
