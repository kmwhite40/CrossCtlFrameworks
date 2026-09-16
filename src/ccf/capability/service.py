"""Read-side queries over the capability graph.

Cross-framework reach goes *through* Concord's existing ``framework_mappings``
crosswalk rather than a second mapping table: a capability maps only to the
canonical 800-53 control, and every other framework is reached by traversal.
Mapping a capability directly to each framework would fork the crosswalk and
guarantee the two drift apart.

Both sides of every control comparison are canonicalized, because
``controls.identifier`` is zero-padded (``AC-01``) while a capability stores
the canonical form (``AC-2``) -- a raw string compare would match nothing.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..catalog.canonical import canonicalize
from ..models import Control, Framework, FrameworkMapping
from ..models_capability import Capability, CapabilityControl


async def _canonical_edges(session: AsyncSession, capability_id: int) -> set[str]:
    raw = (
        await session.execute(
            select(CapabilityControl.control_id).where(
                CapabilityControl.capability_id == capability_id
            )
        )
    ).scalars().all()
    out: set[str] = set()
    for r in raw:
        c = canonicalize(r)
        if c is not None:
            out.add(c.value)
    return out


async def framework_reach(
    session: AsyncSession, *, capability_id: int
) -> dict[str, list[str]]:
    """``{framework_code: [mapped values]}`` for one capability.

    Empty when the capability has no control edges, or when its controls are
    absent from this deployment's catalog -- a capability may legitimately
    target a control the workbook lacks.
    """
    canonical = await _canonical_edges(session, capability_id)
    if not canonical:
        return {}

    rows = (
        await session.execute(
            select(Control.identifier, Framework.code, FrameworkMapping.value)
            .join(FrameworkMapping, FrameworkMapping.control_id == Control.id)
            .join(Framework, Framework.id == FrameworkMapping.framework_id)
        )
    ).all()

    reach: dict[str, list[str]] = {}
    for identifier, code, value in rows:
        c = canonicalize(identifier)
        if c is None or c.value not in canonical or not value:
            continue
        reach.setdefault(code, [])
        if value not in reach[code]:
            reach[code].append(value)
    for values in reach.values():
        values.sort()
    return reach


async def capabilities_for_control(
    session: AsyncSession, *, control_id: str
) -> list[Capability]:
    """Capabilities claiming ``control_id``, in any spelling of it.

    Accepts the canonical (``AC-2``) or zero-padded (``AC-02``) form, since
    callers hold whichever the surrounding data gave them.
    """
    target = canonicalize(control_id)
    if target is None:
        return []
    rows = (
        await session.execute(
            select(Capability, CapabilityControl.control_id).join(
                CapabilityControl, CapabilityControl.capability_id == Capability.id
            )
        )
    ).all()
    out: list[Capability] = []
    for cap, raw in rows:
        c = canonicalize(raw)
        if c is not None and c.value == target.value:
            out.append(cap)
    return out
