"""Shared credential verification for both login surfaces (AC-7 / IA-5).

Concord exposes two ways to sign in: the JSON API (``POST /api/auth/login``) and
the browser form (``POST /login``). The brute-force controls — failed-attempt
counting and time-boxed account lockout — must be identical on both, otherwise
an attacker simply aims a password spray at whichever surface lacks them.

Keeping the logic here (rather than duplicating it per route) means a future
change to the lockout policy cannot drift between the two entry points.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from fastapi import Request
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import read_session, sign_session, verify_password
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
    #: Password correct, second factor outstanding. **Not** a success: the only
    #: branch on either surface that issues a session tests for ``OK``, so a
    #: surface that fails to handle this cannot fall through into one.
    MFA_REQUIRED = "mfa_required"


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

    # The counter is NOT cleared yet when a second factor is outstanding.
    # Clearing here would give an attacker a fresh lockout budget for the code
    # step -- six digits is a million guesses, so a separate budget per factor
    # is most of the factor given away. It is cleared by ``complete_login``
    # once the whole authentication succeeds.
    from ..identity import mfa_service  # noqa: PLC0415  (circular at module level)

    if await mfa_service.is_challenged(session, user.id):
        await session.commit()
        return user, LoginResult.MFA_REQUIRED

    await complete_login(session, user)
    return user, LoginResult.OK


async def complete_login(session: AsyncSession, user: User) -> None:
    """Clear the AC-7 counters once authentication has fully succeeded.

    Called by ``authenticate`` for a single-factor account and by the
    second-factor step for an enrolled one, so both paths land in one place.
    """
    if user.failed_login_attempts or user.locked_until:
        user.failed_login_attempts = 0
        user.locked_until = None
    await session.commit()


async def record_failed_factor(session: AsyncSession, user: User) -> LoginResult:
    """Count a failed **second** factor against the same AC-7 budget.

    A second factor with unlimited attempts is not a second factor. This shares
    ``failed_login_attempts`` with the password step deliberately: two separate
    budgets would let an attacker spend one and then the other.
    """
    settings = get_settings()
    user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
    locked = user.failed_login_attempts >= settings.auth_lockout_threshold
    if locked:
        user.locked_until = datetime.now(UTC) + timedelta(minutes=settings.auth_lockout_minutes)
        user.failed_login_attempts = 0
    await session.commit()
    return LoginResult.LOCKED if locked else LoginResult.INVALID


_MFA_PENDING_LABEL = b"ccf-mfa-pending-v1"

#: A step in a flow, not a session. Long enough to read a code off a phone.
MFA_PENDING_TTL_SECONDS = 300


def _mfa_pending_secret(base_secret: str) -> str:
    """A signing key cryptographically independent of the session key.

    ``sign_session``/``read_session`` carry no audience or type claim, so a
    half-authenticated token minted with the *same* secret verifies as a full
    session cookie -- which would make the second factor a redirect a caller
    could simply skip, with the password alone sufficing.

    This is the same hazard ``api/routes/portal.py:_portal_secret`` was written
    for, and the same answer. Derivation rather than an audience claim on
    purpose: an audience check fails **open** the first time a new reader
    forgets it, while a derived key fails closed -- the signature does not
    verify and nobody has to remember anything.
    """
    return hmac.new(base_secret.encode(), _MFA_PENDING_LABEL, hashlib.sha256).hexdigest()


def mint_mfa_pending(user: User, *, now: float | None = None) -> str:
    """A short-lived token that can be exchanged for a session and nothing else.

    Carries ``session_version``, so revoking a user's sessions also kills a
    login already in flight.
    """
    secret = _mfa_pending_secret(get_settings().auth_session_secret)
    token = sign_session(
        user.id,
        secret,
        ttl_hours=1,
        session_version=user.session_version or 0,
        now=now,
    )
    # sign_session's granularity is hours; the real bound is enforced here so
    # the window is minutes rather than an hour.
    stamp = int(now if now is not None else time.time())
    return f"{stamp}.{token}"


def read_mfa_pending(token: str, *, now: float | None = None) -> tuple[int, int] | None:
    """Verify a pending token and return ``(user_id, session_version)``."""
    try:
        stamp_raw, inner = token.split(".", 1)
        stamp = int(stamp_raw)
    except (ValueError, TypeError):
        return None
    current = now if now is not None else time.time()
    if current - stamp > MFA_PENDING_TTL_SECONDS or current + 1 < stamp:
        return None
    secret = _mfa_pending_secret(get_settings().auth_session_secret)
    return read_session(inner, secret, now=now)


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
