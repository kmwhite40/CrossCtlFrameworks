"""TOTP enrolment, verification and recovery, against the database.

Spec: ``docs/superpowers/specs/2026-09-23-mfa-totp-design.md``.

``ccf.mfa`` holds the algorithm and knows nothing about storage; this module
holds the storage and knows nothing about HTTP. Every function takes an
explicit ``now`` for the same reason ``ccf.mfa`` does -- a replay or drift
assertion driven by the wall clock is a test that passes for the wrong reason
at the end of a step.
"""

from __future__ import annotations

import time
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

#: The roles an ``admins`` policy covers. One definition, read by both the
#: display predicate and the gate.
_PRIVILEGED_ROLES = frozenset({"admin", "owner"})


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


#: Organization policies, cached briefly. The gate runs on EVERY authenticated
#: request, and the first version cost three queries there -- measured at 3x on
#: a request-heavy test module, which is a cost real page loads pay too.
#:
#: A policy changes almost never, and the writer clears this on every change,
#: so within one process the cache is exact. Across processes a change takes up
#: to the TTL to apply. That is the accepted cost, and it is bounded: the
#: window only ever delays *starting* to require enrolment, never delays
#: revoking a session or honouring a lockout.
_POLICY_TTL_SECONDS = 30.0
_policy_cache: dict[int, tuple[float, str]] = {}

#: Does ANY organization on this deployment require a second factor?
#:
#: The gate runs on every authenticated request, and on a deployment where
#: nobody has turned the policy on -- which is every deployment until somebody
#: does, and every test module -- this one cached boolean makes it free. One
#: cheap EXISTS refreshed on the same TTL, instead of a per-user lookup that
#: could only ever answer "no".
#: A one-slot dict rather than a module global, so updating it needs no
#: ``global`` statement.
_any_policy: dict[str, tuple[float, bool]] = {}


def forget_policy(organization_id: int) -> None:
    """Drop cached policy state. Called by the writer, so a change is immediate."""
    _policy_cache.pop(organization_id, None)
    _any_policy.clear()


async def _any_organization_requires_mfa(session: AsyncSession) -> bool:
    now = time.monotonic()
    hit = _any_policy.get("v")
    if hit is not None and now - hit[0] < _POLICY_TTL_SECONDS:
        return hit[1]
    found = (
        await session.execute(
            select(Organization.id).where(Organization.mfa_policy != "optional").limit(1)
        )
    ).first()
    _any_policy["v"] = (now, found is not None)
    return found is not None


async def _policy_for(session: AsyncSession, organization_id: int) -> str:
    now = time.monotonic()
    hit = _policy_cache.get(organization_id)
    if hit is not None and now - hit[0] < _POLICY_TTL_SECONDS:
        return hit[1]
    org = await session.get(Organization, organization_id)
    policy = str(getattr(org, "mfa_policy", "optional") or "optional") if org else "optional"
    _policy_cache[organization_id] = (now, policy)
    return policy


async def enrolment_outstanding(
    session: AsyncSession, user_id: int | None, *, organization_id: int | None, role: str
) -> bool:
    """Is this user obliged to hold an authenticator and does not?

    The question the gate asks, on every authenticated request -- so the shape
    is chosen for the common case being free rather than for reading tidily:

    * ``optional`` (the default, and what nearly every deployment runs) returns
      without touching the database at all beyond a cached policy read.
    * ``admins`` returns the same way for anyone who is not one, because the
      caller's role is already on the principal.
    * Only a user actually in scope costs a query, and it is one.

    The first version loaded the user, then the organization, then the
    credential: three round trips on every page load.
    """
    if user_id is None or organization_id is None:
        return False
    # The whole-deployment short circuit: one cached EXISTS, and nothing else
    # runs until somebody actually turns a policy on.
    if not await _any_organization_requires_mfa(session):
        return False
    policy = await _policy_for(session, organization_id)
    if policy == "optional":
        return False
    if policy == "admins" and role not in _PRIVILEGED_ROLES:
        return False
    return not await is_challenged(session, user_id)


async def policy_requires_enrolment(session: AsyncSession, user: User) -> bool:
    """Whether this user's organization obliges them to hold an authenticator.

    What the policy SAYS. Pages display this; the gate asks
    :func:`enrolment_outstanding`, which also checks whether they actually
    have one.

    A user in scope is routed to enrolment, not refused -- an organization
    that could lock all of its own users out by changing a dropdown would have
    no way back in.
    """
    org = await session.get(Organization, user.organization_id)
    policy = getattr(org, "mfa_policy", "optional") if org is not None else "optional"
    if policy == "all":
        return True
    if policy == "admins":
        return (user.role or "") in _PRIVILEGED_ROLES
    return False
