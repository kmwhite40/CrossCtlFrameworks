"""Reviewed requests for more time on a POA&M.

``POAM.original_due_on`` already records the baseline a later date deviates
from, but nothing decided whether a later date was acceptable: anyone could
PATCH ``due_on`` forward, and an overdue weakness stopped being overdue. A
deviation is a decision (FedRAMP's POA&M template records each one), so moving
an active POA&M's date later now takes a request that the system's ISSM or AO
(or an admin) decides, and the requester can never be the decider.

Risk-accepted POA&Ms are not handled here: their ``due_on`` is the acceptance's
expiry, extended through the AO-approval gate in ``api/routes/poams.py``.
"""

from __future__ import annotations

from datetime import UTC, date, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..api.audit import record_event
from ..auth import Principal
from ..config import get_settings
from ..constants import POAM_ACTIVE_STATUSES
from ..cr26.ver import is_blank
from ..governance import bus
from ..models import POAM, System
from ..models_ato import PoamExtension
from . import roles as system_roles

#: Who may decide an extension (an admin always may).
DECIDERS = ("issm", "authorizing_official")


class ExtensionError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


async def _org_of(session: AsyncSession, poam: POAM) -> int | None:
    return (
        await session.execute(select(System.organization_id).where(System.id == poam.system_id))
    ).scalar_one_or_none()


async def pending_for(session: AsyncSession, poam_id: int) -> PoamExtension | None:
    return (
        await session.execute(
            select(PoamExtension).where(
                PoamExtension.poam_id == poam_id, PoamExtension.status == "requested"
            )
        )
    ).scalar_one_or_none()


async def history(session: AsyncSession, poam_id: int) -> list[PoamExtension]:
    return list(
        (
            await session.execute(
                select(PoamExtension)
                .where(PoamExtension.poam_id == poam_id)
                .order_by(PoamExtension.id.desc())
            )
        ).scalars()
    )


async def request(
    session: AsyncSession,
    *,
    poam: POAM,
    requested_due_on: date,
    reason: str | None,
    principal: Principal,
    today: date | None = None,
) -> PoamExtension:
    today = today or date.today()
    if poam.status not in POAM_ACTIVE_STATUSES:
        raise ExtensionError(
            409,
            f"only an open or in-progress POA&M can be extended (this one is {poam.status})",
        )
    if is_blank(reason):
        raise ExtensionError(409, "an extension request needs a reason (the deviation rationale)")
    if requested_due_on <= today:
        raise ExtensionError(409, "the requested date must be after today")
    if poam.due_on is not None and requested_due_on <= poam.due_on:
        raise ExtensionError(
            409, "the requested date is not later than the current due date; just set it"
        )
    if await pending_for(session, poam.id) is not None:
        raise ExtensionError(409, "this POA&M already has an extension request awaiting a decision")
    org_id = await _org_of(session, poam)
    ext = PoamExtension(
        organization_id=org_id,
        poam_id=poam.id,
        previous_due_on=poam.due_on,
        requested_due_on=requested_due_on,
        reason=(reason or "").strip(),
        requested_by=principal.email,
    )
    session.add(ext)
    await session.flush()
    await record_event(
        session,
        actor=principal.email or "system",
        action="poam_extension_requested",
        entity_type="poam",
        entity_id=str(poam.id),
        diff={"extension_id": ext.id, "from": str(poam.due_on), "to": str(requested_due_on)},
        organization_id=org_id,
    )
    await bus.notify(
        session,
        category="approval",
        title=f"Extension requested: POA&M {poam.id}",
        body=f"{principal.email} asks to move '{poam.title}' to {requested_due_on}: {ext.reason}",
        org_id=org_id,
        severity="info",
        entity_type="poam",
        entity_id=str(poam.id),
        dedupe_key=f"poam-extension:{ext.id}",
    )
    return ext


async def decide(
    session: AsyncSession,
    *,
    poam: POAM,
    extension: PoamExtension,
    approve: bool,
    note: str | None,
    principal: Principal,
) -> PoamExtension:
    if extension.status != "requested":
        raise ExtensionError(409, f"this request is already {extension.status}")
    capacity: str | None = None
    if get_settings().auth_enabled:
        capacity = await system_roles.acting_as(
            session,
            system_id=poam.system_id,
            user_id=principal.user_id,
            user_role=principal.role,
            allowed=DECIDERS,
        )
        if capacity is None:
            raise ExtensionError(
                403, "only the system's ISSM or Authorizing Official (or an admin) can decide"
            )
        if principal.email and principal.email == extension.requested_by:
            raise ExtensionError(
                403, "separation of duties: the requester cannot decide their own extension"
            )
    if not approve and is_blank(note):
        raise ExtensionError(409, "rejecting an extension needs a note saying why")
    extension.status = "approved" if approve else "rejected"
    extension.decided_by = principal.email
    extension.decided_at = datetime.now(UTC)
    extension.decision_note = (note or "").strip() or None
    if approve:
        if poam.original_due_on is None:
            poam.original_due_on = extension.previous_due_on
        poam.due_on = extension.requested_due_on
    await session.flush()
    await record_event(
        session,
        actor=principal.email or "system",
        action=f"poam_extension_{extension.status}",
        entity_type="poam",
        entity_id=str(poam.id),
        diff={
            "extension_id": extension.id, "acted_as": capacity,
            "due_on": str(poam.due_on), "note": extension.decision_note,
        },
        organization_id=extension.organization_id,
    )
    return extension


async def withdraw(
    session: AsyncSession, *, extension: PoamExtension, principal: Principal
) -> PoamExtension:
    if extension.status != "requested":
        raise ExtensionError(409, f"this request is already {extension.status}")
    if (
        get_settings().auth_enabled
        and principal.email != extension.requested_by
        and principal.role != "admin"
    ):
        raise ExtensionError(403, "only the requester (or an admin) can withdraw a request")
    extension.status = "withdrawn"
    extension.decided_by = principal.email
    extension.decided_at = datetime.now(UTC)
    await session.flush()
    return extension
