"""Event-driven reactions — keep state self-consistent across modules.

When something changes, the dependent records update themselves: satisfying a
control auto-closes its gap POA&M and propagates the status to crosswalked
controls in other frameworks (map once, comply many). Reactions are explicit
(routes call them) and emit their own follow-up events with ``dispatch=False``
to avoid webhook storms / recursion.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import POAM, Control, ControlImplementation, FrameworkMapping
from . import bus

_MET = ("implemented", "inherited", "not_applicable")
_OPEN = ("open", "in_progress")


async def on_scoring_status_changed(
    session: AsyncSession,
    *,
    system_id: int,
    control_id: str,
    state: str,
    org_id: int | None = None,
    actor: str | None = None,
) -> dict[str, Any]:
    """A CMMC practice changed state → auto-close its gap POA&M when satisfied."""
    closed = 0
    if state in _MET:
        rows = (
            (
                await session.execute(
                    select(POAM).where(
                        POAM.system_id == system_id,
                        POAM.status.in_(_OPEN),
                        POAM.title.like(f"{control_id} —%"),
                    )
                )
            )
            .scalars()
            .all()
        )
        for p in rows:
            p.status = "completed"
            p.closed_on = date.today()
            closed += 1
            await bus.emit(
                session,
                verb="closed",
                entity_type="poam",
                entity_id=p.id,
                summary=f"POA&M auto-closed: {control_id} satisfied ({state})",
                org_id=org_id,
                actor=actor or "automation",
                dispatch=False,
            )
    await bus.emit(
        session,
        verb="updated",
        entity_type="scoring_status",
        entity_id=f"{system_id}:{control_id}",
        summary=f"{control_id} → {state}",
        org_id=org_id,
        actor=actor,
        dispatch=False,
    )
    return {"gap_poams_closed": closed}


# A mapping value shared by more controls than this is too generic to be a
# cross-framework identity (e.g. a boolean marker), so it's skipped.
_MAX_SHARE = 12
_MAX_PEERS = 60


async def crosswalk_peers(session: AsyncSession, control_id: int) -> list[int]:
    """Control ids that are genuine cross-framework equivalents of this control.

    Two controls are equivalent when they share a *specific* crosswalk mapping
    value. Values shared across many controls (generic markers like "x") are
    ignored so propagation targets true equivalents, not the whole catalog.
    """
    pairs = (
        await session.execute(
            select(FrameworkMapping.column_key, FrameworkMapping.value).where(
                FrameworkMapping.control_id == control_id
            )
        )
    ).all()
    peers: set[int] = set()
    for column_key, value in pairs:
        v = (value or "").strip()
        if len(v) < 3:  # skip boolean-ish / trivially short markers
            continue
        ids = (
            (
                await session.execute(
                    select(FrameworkMapping.control_id).where(
                        FrameworkMapping.column_key == column_key,
                        FrameworkMapping.value == value,
                    )
                )
            )
            .scalars()
            .all()
        )
        if len(ids) > _MAX_SHARE:  # value too generic to imply equivalence
            continue
        peers.update(ids)
    peers.discard(control_id)
    return sorted(peers)[:_MAX_PEERS]


async def propagate_implementation(
    session: AsyncSession,
    *,
    system_id: int,
    control_id: int,
    status: str,
    org_id: int | None = None,
    actor: str | None = None,
) -> dict[str, Any]:
    """Copy a control's implementation status to crosswalked peer controls.

    Realises "map once, comply many": implement a control and its equivalents
    across other frameworks inherit the same status for this system.
    """
    peers = await crosswalk_peers(session, control_id)
    if not peers:
        return {"peers": 0, "updated": 0}
    existing = {
        i.control_id: i
        for i in (
            await session.execute(
                select(ControlImplementation).where(
                    ControlImplementation.system_id == system_id,
                    ControlImplementation.control_id.in_(peers),
                )
            )
        )
        .scalars()
        .all()
    }
    updated = 0
    for cid in peers:
        impl = existing.get(cid)
        if impl is None:
            session.add(
                ControlImplementation(
                    system_id=system_id,
                    control_id=cid,
                    status=status,
                    responsibility="inherited",
                    narrative="Propagated from a crosswalked control (map once, comply many).",
                )
            )
            updated += 1
        elif impl.status != status:
            impl.status = status
            updated += 1
    await bus.emit(
        session,
        verb="propagated",
        entity_type="control_implementation",
        entity_id=control_id,
        summary=f"Status '{status}' propagated to {updated} crosswalked control(s)",
        org_id=org_id,
        actor=actor or "automation",
        dispatch=False,
    )
    return {"peers": len(peers), "updated": updated}


async def resolve_control_id(session: AsyncSession, identifier: str) -> int | None:
    return (
        await session.execute(select(Control.id).where(Control.identifier == identifier))
    ).scalar_one_or_none()
