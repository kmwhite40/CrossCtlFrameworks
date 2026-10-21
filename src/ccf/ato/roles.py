"""Who signs for a system: the ISSO, ISSM, AO and system owner.

An assignment is a relationship between a user and a system, not a user role:
being the AO of one system must not make anyone the AO of another. ``admin``
stays the platform floor -- an admin may act at any stage -- but separation of
duties still applies to an admin like anyone else.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..api.audit import record_event
from ..auth import Principal
from ..models import System, User
from ..models_ato import SYSTEM_ROLES, SystemRoleAssignment

ROLE_LABELS = {
    "system_owner": "System Owner",
    "isso": "ISSO",
    "issm": "ISSM",
    "authorizing_official": "Authorizing Official",
}

#: The roles a package cannot be reviewed without (auth enabled).
REVIEW_ROLES = ("isso", "issm", "authorizing_official")


class RoleError(Exception):
    """An assignment that cannot be made (unknown role, wrong org, viewer)."""


@dataclass(frozen=True)
class Holder:
    role: str
    user_id: int
    email: str
    name: str | None


async def holders(session: AsyncSession, system_id: int) -> dict[str, Holder]:
    """The current holder of each assigned role on a system."""
    rows = (
        await session.execute(
            select(SystemRoleAssignment.role, User.id, User.email, User.full_name)
            .join(User, User.id == SystemRoleAssignment.user_id)
            .where(SystemRoleAssignment.system_id == system_id)
        )
    ).all()
    return {r.role: Holder(r.role, r.id, r.email, r.full_name) for r in rows}


async def roles_of(session: AsyncSession, system_id: int, user_id: int | None) -> set[str]:
    """The system roles ``user_id`` holds on ``system_id``."""
    if user_id is None:
        return set()
    rows = (
        await session.execute(
            select(SystemRoleAssignment.role).where(
                SystemRoleAssignment.system_id == system_id,
                SystemRoleAssignment.user_id == user_id,
            )
        )
    ).scalars().all()
    return set(rows)


async def acting_as(
    session: AsyncSession,
    *,
    system_id: int | None,
    user_id: int | None,
    user_role: str | None,
    allowed: tuple[str, ...],
) -> str | None:
    """The capacity a person may act in for ``allowed`` roles, or None.

    A held system role wins over ``admin`` so the record says the AO signed as
    the AO, not as an administrator who happens to be the AO.
    """
    if system_id is not None:
        held = await roles_of(session, system_id, user_id)
        for role in allowed:
            if role in held:
                return role
    if user_role == "admin":
        return "admin"
    return None


async def _user_by_email(session: AsyncSession, email: str | None) -> User | None:
    if not email:
        return None
    return (
        await session.execute(select(User).where(User.email == email))
    ).scalar_one_or_none()


async def acting_as_email(
    session: AsyncSession, *, system_id: int | None, email: str | None, allowed: tuple[str, ...]
) -> str | None:
    """:func:`acting_as` for a person recorded only by email (e.g. a reviewer)."""
    user = await _user_by_email(session, email)
    if user is None:
        return None
    return await acting_as(
        session, system_id=system_id, user_id=user.id, user_role=user.role, allowed=allowed
    )


async def assign(
    session: AsyncSession, *, system: System, role: str, user_id: int, principal: Principal
) -> SystemRoleAssignment:
    """Make ``user_id`` the holder of ``role`` on ``system`` (replacing any holder)."""
    if role not in SYSTEM_ROLES:
        raise RoleError(f"unknown system role: {role}")
    user = (await session.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    # Same answer for "no such user" and "another tenant's user": the second
    # must not be distinguishable from the first.
    if user is None or user.organization_id != system.organization_id:
        raise RoleError("no such user in this system's organization")
    if not user.active:
        raise RoleError("an inactive user cannot hold a signing role")
    if user.role == "viewer":
        raise RoleError("a viewer is read-only and could never sign; give them a write role first")
    row = (
        await session.execute(
            select(SystemRoleAssignment).where(
                SystemRoleAssignment.system_id == system.id, SystemRoleAssignment.role == role
            )
        )
    ).scalar_one_or_none()
    previous = row.user_id if row is not None else None
    if row is None:
        row = SystemRoleAssignment(
            organization_id=system.organization_id, system_id=system.id, role=role
        )
        session.add(row)
    row.user_id = user.id
    row.assigned_by = principal.email
    await session.flush()
    await record_event(
        session,
        actor=principal.email or "system",
        action="system_role_assigned",
        entity_type="system",
        entity_id=str(system.id),
        diff={"role": role, "user_id": user.id, "previous_user_id": previous},
        organization_id=system.organization_id,
    )
    return row


async def unassign(
    session: AsyncSession, *, system: System, role: str, principal: Principal
) -> bool:
    if role not in SYSTEM_ROLES:
        raise RoleError(f"unknown system role: {role}")
    row = (
        await session.execute(
            select(SystemRoleAssignment).where(
                SystemRoleAssignment.system_id == system.id, SystemRoleAssignment.role == role
            )
        )
    ).scalar_one_or_none()
    if row is None:
        return False
    await session.delete(row)
    await session.flush()
    await record_event(
        session,
        actor=principal.email or "system",
        action="system_role_unassigned",
        entity_type="system",
        entity_id=str(system.id),
        diff={"role": role},
        organization_id=system.organization_id,
    )
    return True
