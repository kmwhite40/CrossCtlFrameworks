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


async def consume_recovery_code(session: AsyncSession, user_id: int, code: str) -> bool:
    """Spend one single-use recovery code.

    Marked used rather than deleted: "did somebody sign in without their
    authenticator, and when" is an audit question a deleted row cannot answer.
    """
    digest = mfa.hash_recovery_code(code)
    row = (
        await session.execute(
            select(UserMfaRecoveryCode).where(
                UserMfaRecoveryCode.user_id == user_id,
                UserMfaRecoveryCode.code_hash == digest,
                UserMfaRecoveryCode.used_at.is_(None),
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
            )
        )
    ).scalars().all()
    return len(rows)


async def policy_requires_enrolment(session: AsyncSession, user: User) -> bool:
    """Whether this user's organization obliges them to hold an authenticator.

    Returning True does not refuse the login -- see the spec §8. It means the
    user must enrol before doing anything else. An organization that could lock
    all of its own users out by changing a dropdown has no way back in.
    """
    org = await session.get(Organization, user.organization_id)
    policy = getattr(org, "mfa_policy", "optional") if org is not None else "optional"
    if policy == "all":
        return True
    if policy == "admins":
        return (user.role or "") in {"admin", "owner"}
    return False
