"""Transport-agnostic identity provisioning — role mapping, JIT, SCIM.

Pure-ish service logic (only touches the DB session) so it is unit-testable
without a live IdP or HTTP layer. Writes tamper-evident audit entries for every
account/role change via :func:`ccf.api.audit.record_event` (lazy-imported to
avoid an import cycle with the API layer).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import User
from ..models_identity import ExternalIdentity, GroupRoleMapping, ScimProvisioningEvent

VALID_ROLES = {"admin", "control_owner", "assessor", "viewer"}
PIV_PROVIDER = "piv"
DEFAULT_ROLE = "viewer"


class ProvisioningError(ValueError):
    """Raised when an account cannot be provisioned or a login is disallowed."""


class ProvisioningConflictError(ProvisioningError):
    """The email belongs to a different organization than the caller provisions into.

    ``User.email`` is globally unique, so an address that already exists in
    another tenant cannot be created here and must never be updated in place --
    that is a cross-tenant write. SCIM's own answer to this is 409 with
    ``scimType: uniqueness``, which is what the route returns.
    """


def extract_groups(claims: dict[str, Any]) -> list[str]:
    """Pull group/role membership out of OIDC claims (best-effort, tolerant)."""
    out: list[str] = []
    for key in ("groups", "roles", "wids"):
        val = claims.get(key)
        if isinstance(val, str):
            out.extend(p.strip() for p in val.split(",") if p.strip())
        elif isinstance(val, list):
            out.extend(str(v) for v in val)
    return out


def email_verification_ok(claims: dict[str, Any], *, require: bool) -> bool:
    """Whether this email claim may create or claim a local account.

    ``provision_from_oidc`` falls back to matching on ``User.email`` and then
    writes a permanent ``ExternalIdentity`` link. So an identity-provider
    subject presenting somebody else's address was handed that account and kept
    it. Nothing read ``email_verified`` at all.

    Three states, and the middle one is the point:

    * ``email_verified: true``  -> allowed.
    * ``email_verified: false`` -> **refused**, always. That is the provider
      stating a fact about the address, not omitting one.
    * **absent** -> allowed unless ``require`` is set. The claim is optional in
      OIDC, and treating absence as "unverified" would break every deployment
      whose provider does not send it -- absence of evidence read as evidence
      of absence, which is a defect this programme keeps finding. A deployment
      that knows its provider sends the claim sets
      ``oidc_require_email_verified``.
    """
    raw = claims.get("email_verified")
    if raw is None:
        return not require
    if isinstance(raw, str):
        return raw.strip().lower() == "true"
    return bool(raw)


def domain_allowed(email: str, allowed_domains: list[str] | None) -> bool:
    if not allowed_domains:
        return True
    domain = email.rsplit("@", 1)[-1].lower()
    return any(domain == d.strip().lower().lstrip("@") for d in allowed_domains if d)


async def resolve_role(
    session: AsyncSession, org_id: int | None, groups: list[str], default_role: str
) -> str:
    """Map the first matching IdP group to a role (lowest priority wins)."""
    if not groups:
        return default_role
    stmt = select(GroupRoleMapping).where(GroupRoleMapping.group.in_(groups))
    if org_id is not None:
        stmt = stmt.where(GroupRoleMapping.organization_id == org_id)
    stmt = stmt.order_by(GroupRoleMapping.priority, GroupRoleMapping.id)
    row = (await session.execute(stmt)).scalars().first()
    if row is not None and row.role in VALID_ROLES:
        return row.role
    return default_role


async def _audit(
    session: AsyncSession,
    *,
    actor: str,
    action: str,
    entity_id: str | None,
    diff: dict[str, Any],
    organization_id: int | None,
) -> None:
    """Append an identity audit event (see :func:`ccf.api.audit.record_event`).

    Every caller here has the target user's organization in hand, and must pass
    it: this module runs on sessions that are *not* tenant-clamped -- the OIDC
    callback has no principal yet, and the SCIM endpoints authenticate with a
    bearer token rather than a user -- so nothing downstream could infer the
    tenant. Left NULL these rows would be visible to every organization under
    migration 0044's ``tenant_isolation`` policy, publishing one tenant's JIT
    provisioning, role changes and deactivations to all of them.
    """
    from ..api.audit import record_event  # noqa: PLC0415 — lazy to avoid import cycle

    await record_event(
        session, actor=actor, action=action, entity_type="identity",
        entity_id=entity_id, diff=diff, organization_id=organization_id,
    )


async def provision_from_oidc(
    session: AsyncSession,
    *,
    claims: dict[str, Any],
    org_id: int,
    allowed_domains: list[str] | None = None,
    default_role: str = DEFAULT_ROLE,
    jit: bool = True,
    provider: str = "oidc",
    require_email_verified: bool = False,
) -> tuple[User, bool]:
    """Resolve (and, if enabled, JIT-create) a local user from OIDC claims.

    Returns ``(user, created)``. Raises :class:`ProvisioningError` on a disallowed
    domain, a deactivated account, or a missing account when JIT is disabled.
    """
    email = (claims.get("email") or "").strip().lower()
    subject = str(claims.get("sub") or "").strip()
    if not email or not subject:
        raise ProvisioningError("OIDC claims missing required 'email'/'sub'")
    if not domain_allowed(email, allowed_domains):
        raise ProvisioningError(f"email domain not allowed: {email}")
    if not email_verification_ok(claims, require=require_email_verified):
        # Checked before ANY lookup: the account this would otherwise reach is
        # somebody else's, and the link it would write is permanent.
        raise ProvisioningError(
            f"the identity provider has not verified {email}; it cannot be used "
            "to create or sign in to an account"
        )

    groups = extract_groups(claims)
    now = datetime.now(UTC)

    ident = (
        await session.execute(
            select(ExternalIdentity).where(
                ExternalIdentity.provider == provider, ExternalIdentity.subject == subject
            )
        )
    ).scalar_one_or_none()

    user: User | None = None
    if ident is not None:
        user = await session.get(User, ident.user_id)
    if user is None:
        user = (
            await session.execute(select(User).where(User.email == email))
        ).scalar_one_or_none()

    created = False
    if user is None:
        if not jit:
            raise ProvisioningError("no matching account and JIT provisioning disabled")
        # A user being created belongs to `org_id`, so its mappings are the
        # right ones -- the same rule as the existing-user branch below, which
        # resolves against the row's own organization.
        create_role = await resolve_role(session, org_id, groups, default_role)
        user = User(
            organization_id=org_id,
            email=email,
            full_name=claims.get("name"),
            role=create_role if create_role in VALID_ROLES else DEFAULT_ROLE,
            active=True,
        )
        session.add(user)
        await session.flush()
        created = True
        await _audit(
            session, organization_id=user.organization_id,
            actor=email, action="create", entity_id=str(user.id),
            diff={"event": "jit_provision", "email": email, "role": user.role, "groups": groups},
        )

    if not user.active:
        raise ProvisioningError("account is deactivated")

    # Resolved against the USER'S OWN organization, and only once the user is
    # known. It used to be resolved against the configured single-sign-on
    # organization before the lookup, and then written onto whatever tenant's
    # row the globally-unique email landed on -- so an admin of one tenant
    # creating a mapping in their own organization, which is entirely
    # legitimate for them, promoted a user of another tenant who carried that
    # group claim. A group mapping governs its own organization's users and
    # nobody else's.
    mapped_role = await resolve_role(session, user.organization_id, groups, default_role)

    # Apply role mapping when groups resolve to a different role than currently set.
    if groups and mapped_role in VALID_ROLES and user.role != mapped_role:
        old = user.role
        user.role = mapped_role
        await _audit(
            session, organization_id=user.organization_id,
            actor=email, action="update", entity_id=str(user.id),
            diff={"event": "role_change", "from": old, "to": mapped_role, "groups": groups},
        )

    if ident is None:
        ident = ExternalIdentity(
            organization_id=user.organization_id,
            user_id=user.id,
            provider=provider,
            subject=subject,
            email=email,
        )
        session.add(ident)
    ident.claims = claims
    ident.email = email
    ident.last_login_at = now
    await session.flush()
    return user, created


# --- SCIM --------------------------------------------------------------------


def scim_user_resource(user: User) -> dict[str, Any]:
    """Render a local user as a SCIM 2.0 User resource."""
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": str(user.id),
        "userName": user.email,
        "name": {"formatted": user.full_name or user.email},
        "emails": [{"value": user.email, "primary": True}],
        "active": user.active,
        "roles": [{"value": user.role}],
        "meta": {"resourceType": "User"},
    }


def _scim_email(payload: dict[str, Any]) -> str | None:
    if payload.get("userName"):
        return str(payload["userName"]).strip().lower()
    emails = payload.get("emails") or []
    if emails and isinstance(emails[0], dict) and emails[0].get("value"):
        return str(emails[0]["value"]).strip().lower()
    return None


async def user_for_certificate(session: AsyncSession, identity: Any) -> User:
    """Resolve a PIV/CAC certificate to an existing account. Never creates one.

    Holding a valid card says the federal government issued someone a
    credential. It does not say that person should have an account in this
    tenant, so there is no just-in-time provisioning on this path -- unlike
    OIDC, where an administrator has chosen to federate a directory whose
    membership already means something here.

    The link is an ``ExternalIdentity`` with ``provider="piv"``, which an
    administrator creates. A user who could link their own certificate could
    link it to somebody else's account.
    """
    from .piv import PivNotLinkedError  # noqa: PLC0415  (circular at module level)

    ident = (
        await session.execute(
            select(ExternalIdentity).where(
                ExternalIdentity.provider == PIV_PROVIDER,
                ExternalIdentity.subject == identity.subject,
            )
        )
    ).scalar_one_or_none()
    if ident is None:
        raise PivNotLinkedError(
            f"this certificate ({identity.subject}) is valid but is not linked to "
            "a Concord account; an administrator must link it"
        )
    user = await session.get(User, ident.user_id)
    if user is None:
        raise PivNotLinkedError(
            f"this certificate ({identity.subject}) is linked to an account that "
            "no longer exists"
        )
    if not user.active:
        raise ProvisioningError("account is deactivated")

    ident.last_login_at = datetime.now(UTC)
    await session.flush()
    return user


async def scim_create_or_update_user(
    session: AsyncSession, *, org_id: int, payload: dict[str, Any]
) -> tuple[User, bool]:
    """SCIM create (or idempotent update by email). Returns ``(user, created)``."""
    email = _scim_email(payload)
    if not email:
        raise ProvisioningError("SCIM payload missing userName/emails")
    name = (payload.get("name") or {}).get("formatted") or payload.get("displayName")
    active = payload.get("active", True)

    # Deliberately NOT scoped to ``org_id``. SCIM runs with RLS cleared and
    # ``User.email`` is globally unique, so a scoped lookup would miss a foreign
    # tenant's row and then fail the INSERT on the unique index -- turning a
    # cross-tenant write into an opaque 500. Look globally, then refuse.
    user = (
        await session.execute(select(User).where(User.email == email))
    ).scalar_one_or_none()
    if user is not None and user.organization_id != org_id:
        raise ProvisioningConflictError(
            f"{email} already belongs to another organization; SCIM will not "
            "modify a user outside the organization it provisions into"
        )
    created = False
    if user is None:
        user = User(organization_id=org_id, email=email, full_name=name, active=bool(active))
        session.add(user)
        await session.flush()
        created = True
    else:
        if name:
            user.full_name = name
        user.active = bool(active)

    session.add(
        ScimProvisioningEvent(
            organization_id=org_id,
            operation="create" if created else "update",
            external_id=payload.get("externalId"),
            email=email,
            user_id=user.id,
            detail={"active": bool(active)},
        )
    )
    await _audit(
        session, organization_id=user.organization_id,
        actor="scim", action="create" if created else "update", entity_id=str(user.id),
        diff={"event": "scim_provision", "email": email, "active": bool(active)},
    )
    await session.flush()
    return user, created


async def scim_deactivate_user(session: AsyncSession, *, org_id: int, user: User) -> None:
    """SCIM deactivate — sets the account inactive so it can no longer authenticate."""
    user.active = False
    session.add(
        ScimProvisioningEvent(
            organization_id=org_id, operation="deactivate", email=user.email, user_id=user.id,
        )
    )
    await _audit(
        session, organization_id=user.organization_id,
        actor="scim", action="update", entity_id=str(user.id),
        diff={"event": "scim_deactivate", "email": user.email},
    )
    await session.flush()
