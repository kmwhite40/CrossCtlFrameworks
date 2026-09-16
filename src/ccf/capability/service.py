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
from ..models import Control, Framework, FrameworkMapping, SystemComponent
from ..models_capability import Capability, CapabilityComponent, CapabilityControl


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


async def capability_statements_by_control(
    session: AsyncSession, *, system_id: int
) -> dict[str, list[tuple[str, str, str]]]:
    """Authored capability statements for one system, by canonical control id.

    Loaded as one query so a caller rendering 400 controls does not make 400
    round trips -- ``governance.automation.generate_statements`` pre-loads this
    beside the maps it already builds for captures, vendors, and policies.

    Each value is a list of ``(capability_key, statement, status)`` triples --
    key so a caller can render deterministically ordered by the capability's
    stable identity rather than by statement text (editing a statement must
    not reorder the clause on every other control the capability shares), and
    status so a caller can distinguish a genuinely complete implementation
    from a partial one instead of narrating both identically.

    Filtered to an allow-list, not a block-list: a capability's statement
    describes this system's *implementation* only when its status actually
    says something has been done. ``implemented`` and ``inherited`` clearly
    qualify. ``partial`` also qualifies -- a partial implementation is real
    and belongs in the narrative -- but the caller renders it under a
    distinct "Partial implementation:" lead so the SSP does not overstate it
    as complete. ``not_implemented`` -- the column's default, so it is the
    status of every capability an author has created but not yet acted on --
    and ``planned`` describe work that has not happened, not this system's
    current implementation, and rendering their text as a present-tense
    implementation claim would be a false statement in an authorization
    package. ``not_applicable`` does not describe this system's
    implementation at all. An empty or ``None`` statement has nothing to
    contribute regardless of status. And an edge whose control id does not
    canonicalize is skipped rather than keyed under a value nothing will
    look up.

    The map has exactly one key space -- canonical ids. Reconciling the two id
    forms an ``SSPControlEntry`` may carry is the caller's job.
    """
    rows = (
        await session.execute(
            select(
                CapabilityControl.control_id,
                Capability.key,
                Capability.statement,
                Capability.status,
            )
            .join(Capability, Capability.id == CapabilityControl.capability_id)
            .join(
                CapabilityComponent,
                CapabilityComponent.capability_id == Capability.id,
            )
            .join(
                SystemComponent,
                SystemComponent.id == CapabilityComponent.component_id,
            )
            .where(
                SystemComponent.system_id == system_id,
                Capability.status.in_(("implemented", "inherited", "partial")),
            )
        )
    ).all()

    out: dict[str, list[tuple[str, str, str]]] = {}
    seen: dict[str, set[str]] = {}
    for raw_control, key, statement, status in rows:
        if not statement or not statement.strip():
            continue
        c = canonicalize(raw_control)
        if c is None:
            continue
        # A capability bound through two components would otherwise appear
        # twice for the same control.
        dedup = seen.setdefault(c.value, set())
        if key in dedup:
            continue
        dedup.add(key)
        out.setdefault(c.value, []).append((key, statement.strip(), status))
    return out
