"""TOTP enrolment, verification and recovery, against the database.

Spec: ``docs/superpowers/specs/2026-09-23-mfa-totp-design.md``.

``ccf.mfa`` holds the algorithm and knows nothing about storage; this module
holds the storage and knows nothing about HTTP. Every function takes an
explicit ``now`` for the same reason ``ccf.mfa`` does -- a replay or drift
assertion driven by the wall clock is a test that passes for the wrong reason
at the end of a step.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import mfa
from ..ai.cipher import AAD_MFA, CredentialCipher, build_cipher
from ..config import get_settings
from ..models import Organization, User
from ..models_identity import UserMfaCredential, UserMfaRecoveryCode

#: Shown in the authenticator app's account list.
ISSUER = "Concord"


def _cipher() -> CredentialCipher:
    """The envelope cipher, bound to the MFA context rather than the credential one."""
    return build_cipher(get_settings(), aad=AAD_MFA)


async def credential_for(session: AsyncSession, user_id: int) -> UserMfaCredential | None:
    """This user's authenticator, activated or not."""
    return (
        await session.execute(
            select(UserMfaCredential).where(UserMfaCredential.user_id == user_id)
        )
    ).scalar_one_or_none()


async def is_challenged(session: AsyncSession, user_id: int) -> bool:
    """Whether a password alone is insufficient for this user.

    An enrolled-but-not-activated credential returns False. That is the whole
    point of ``activated_at``: a user who scanned a code and never proved they
    held it must not be locked out by it.
    """
    cred = await credential_for(session, user_id)
    return cred is not None and cred.activated_at is not None


async def begin_enrolment(session: AsyncSession, user: User) -> tuple[str, str]:
    """Mint a secret and return ``(secret, otpauth_uri)``.

    Replaces any credential that has not been activated. An *active* credential
    is never silently replaced -- that would let anyone who reaches an
    authenticated session swap the second factor out from under its owner.
    """
    existing = await credential_for(session, user.id)
    if existing is not None:
        if existing.activated_at is not None:
            raise ValueError("this account already has an active authenticator")
        await session.delete(existing)
        await session.flush()

    secret = mfa.generate_secret()
    session.add(
        UserMfaCredential(
            organization_id=user.organization_id,
            user_id=user.id,
            secret_encrypted=_cipher().encrypt(secret),
        )
    )
    await session.flush()
    return secret, mfa.provisioning_uri(secret, account=user.email, issuer=ISSUER)


async def activate(
    session: AsyncSession, user: User, code: str, *, now: float
) -> list[str] | None:
    """Turn a pending credential on, returning the recovery codes once.

    ``None`` means the code was wrong and nothing changed. The codes are
    returned in plaintext here and nowhere else -- only their digests persist.
    """
    cred = await credential_for(session, user.id)
    if cred is None or cred.activated_at is not None:
        return None
    secret = _cipher().decrypt(cred.secret_encrypted)
    step = mfa.verify(secret, code, now=now, last_used_step=cred.last_used_step)
    if step is None:
        return None

    cred.activated_at = datetime.now(UTC)
    cred.last_used_step = step
    # Any codes still live belong to a previous authenticator: activating a new
    # one retires them, so a re-enrolment does not leave two disjoint sets of
    # working bypass credentials.
    await revoke_recovery_codes(session, user.id)
    codes = mfa.generate_recovery_codes()
    for code_value in codes:
        session.add(
            UserMfaRecoveryCode(
                organization_id=user.organization_id,
                user_id=user.id,
                code_hash=mfa.hash_recovery_code(code_value),
            )
        )
    await session.flush()
    return codes


async def verify_code(session: AsyncSession, user_id: int, code: str, *, now: float) -> bool:
    """Check a TOTP code and spend its step.

    The step is written before this returns True. RFC 6238 §5.2 requires that a
    code accepted once is not accepted again, and a check that does not persist
    what it spent is not enforcing anything.
    """
    cred = await credential_for(session, user_id)
    if cred is None or cred.activated_at is None:
        return False
    secret = _cipher().decrypt(cred.secret_encrypted)
    step = mfa.verify(secret, code, now=now, last_used_step=cred.last_used_step)
    if step is None:
        return False
    cred.last_used_step = step
    await session.flush()
    return True


async def revoke_recovery_codes(session: AsyncSession, user_id: int) -> int:
    """Retire every unused recovery code for a user. Returns how many.

    Called when the authenticator they belong to goes away -- disabled, or
    replaced at re-enrolment. Rotating a second factor has to rotate the
    credentials that bypass it, or a code that leaked before the rotation is
    still a way in afterwards.

    Marked ``revoked_at``, never ``used_at``: the second means somebody signed
    in with it, and writing it here would answer an audit question wrongly.
    """
    rows = (
        await session.execute(
            select(UserMfaRecoveryCode).where(
                UserMfaRecoveryCode.user_id == user_id,
                UserMfaRecoveryCode.used_at.is_(None),
                UserMfaRecoveryCode.revoked_at.is_(None),
            )
        )
    ).scalars().all()
    now = datetime.now(UTC)
    for row in rows:
        row.revoked_at = now
    await session.flush()
    return len(rows)


async def consume_recovery_code(session: AsyncSession, user_id: int, code: str) -> bool:
    """Spend one single-use recovery code.

    Marked used rather than deleted: "did somebody sign in without their
    authenticator, and when" is an audit question a deleted row cannot answer.

    Refuses outright when the user has no ACTIVE authenticator. Revocation on
    disable is the primary fix; this is the second rung, so a row that escapes
    it by any route -- a direct database edit, a future write path, a partially
    applied migration -- still cannot produce a session for an account whose
    second factor is gone.
    """
    if not await is_challenged(session, user_id):
        return False
    digest = mfa.hash_recovery_code(code)
    row = (
        await session.execute(
            select(UserMfaRecoveryCode).where(
                UserMfaRecoveryCode.user_id == user_id,
                UserMfaRecoveryCode.code_hash == digest,
                UserMfaRecoveryCode.used_at.is_(None),
                UserMfaRecoveryCode.revoked_at.is_(None),
            )
        )
    ).scalar_one_or_none()
    if row is None:
        return False
    row.used_at = datetime.now(UTC)
    await session.flush()
    return True


async def unused_recovery_code_count(session: AsyncSession, user_id: int) -> int:
    rows = (
        await session.execute(
            select(UserMfaRecoveryCode.id).where(
                UserMfaRecoveryCode.user_id == user_id,
                UserMfaRecoveryCode.used_at.is_(None),
                UserMfaRecoveryCode.revoked_at.is_(None),
            )
        )
    ).scalars().all()
    return len(rows)


async def policy_requires_enrolment(session: AsyncSession, user: User) -> bool:
    """Whether this user's organization SAYS they should hold an authenticator.

    **Advisory.** Callers display this, and two of them refuse to remove an
    authenticator it covers. Nothing here or above gates a session, a route or
    a redirect: a user in scope who has not enrolled signs in with a password
    alone and reaches everything.

    The docstring used to say the user "must enrol before doing anything
    else". That was the design intent and was never built, which made this
    function read as a control it is not. Enforcement is its own change --
    it needs a decision about which routes stay reachable while unenrolled,
    or an organization locks all of its own users out by changing a dropdown.
    """
    org = await session.get(Organization, user.organization_id)
    policy = getattr(org, "mfa_policy", "optional") if org is not None else "optional"
    if policy == "all":
        return True
    if policy == "admins":
        return (user.role or "") in {"admin", "owner"}
    return False
