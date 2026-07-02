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
DEFAULT_ROLE = "viewer"


class ProvisioningError(ValueError):
    """Raised when an account cannot be provisioned or a login is disallowed."""


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
    session: AsyncSession, *, actor: str, action: str, entity_id: str | None, diff: dict[str, Any]
) -> None:
    from ..api.audit import record_event  # noqa: PLC0415 — lazy to avoid import cycle

    await record_event(
        session, actor=actor, action=action, entity_type="identity",
        entity_id=entity_id, diff=diff,
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

    groups = extract_groups(claims)
    mapped_role = await resolve_role(session, org_id, groups, default_role)
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
        user = User(
            organization_id=org_id,
            email=email,
            full_name=claims.get("name"),
            role=mapped_role if mapped_role in VALID_ROLES else DEFAULT_ROLE,
            active=True,
        )
        session.add(user)
        await session.flush()
        created = True
        await _audit(
            session, actor=email, action="create", entity_id=str(user.id),
            diff={"event": "jit_provision", "email": email, "role": user.role, "groups": groups},
        )

    if not user.active:
        raise ProvisioningError("account is deactivated")

    # Apply role mapping when groups resolve to a different role than currently set.
    if groups and mapped_role in VALID_ROLES and user.role != mapped_role:
        old = user.role
        user.role = mapped_role
        await _audit(
            session, actor=email, action="update", entity_id=str(user.id),
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


async def scim_create_or_update_user(
    session: AsyncSession, *, org_id: int, payload: dict[str, Any]
) -> tuple[User, bool]:
    """SCIM create (or idempotent update by email). Returns ``(user, created)``."""
    email = _scim_email(payload)
    if not email:
        raise ProvisioningError("SCIM payload missing userName/emails")
    name = (payload.get("name") or {}).get("formatted") or payload.get("displayName")
    active = payload.get("active", True)

    user = (
        await session.execute(select(User).where(User.email == email))
    ).scalar_one_or_none()
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
        session, actor="scim", action="create" if created else "update", entity_id=str(user.id),
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
        session, actor="scim", action="update", entity_id=str(user.id),
        diff={"event": "scim_deactivate", "email": user.email},
    )
    await session.flush()
