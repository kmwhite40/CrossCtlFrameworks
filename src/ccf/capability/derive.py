"""Derive control status from capability coverage.

Annotates, never asserts. For each control a system's capabilities claim, the
rolled-up status is written to ``ControlImplementation.derived_status`` --
alongside the authored ``status``, never over it -- so divergence between what
an SSP says and what the capabilities show stays visible and actionable.

Two rules this module must never break:

* **It never writes ``status``.** That column is what every existing reader
  (SSP, scoring, analytics, OSCAL export) consumes.
* **It never creates a ``ControlImplementation`` row.** ``status`` is
  ``NOT NULL DEFAULT 'not_implemented'``, so a created row would assert
  ``not_implemented`` for a control that previously had *no row at all* --
  and "absent" is not "not_implemented" to the coverage and analytics queries.
  Fabricating rows could silently change reported coverage.

Coverage for controls with no implementation row is answered live by the read
API instead, so there are no stale derived rows.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..catalog.canonical import canonicalize
from ..logging import get_logger
from ..models import Control, ControlImplementation, System, SystemComponent
from ..models_capability import Capability, CapabilityComponent, CapabilityControl
from .rollup import roll_up

log = get_logger(__name__)


async def _capabilities_for_system(
    session: AsyncSession, *, system_id: int
) -> list[tuple[Capability, str]]:
    """``(capability, raw_control_id)`` pairs bound to this system.

    Binding runs capability -> component -> system, which is also how a
    policy- or process-backed capability attaches: ``SystemComponent.type``
    already includes ``policy`` and ``process``.

    Joined to ``System`` and filtered on ``Capability.organization_id ==
    System.organization_id`` -- an edge's FK check does not consult RLS, so
    without this predicate a capability from one tenant bound (by id, e.g.
    ``set_components``) to another tenant's component would fold into that
    other tenant's derived control status. This is the only defense for the
    CLI/scheduler paths that call this through ``session_scope()``, which runs
    unscoped (RLS bypass) by design.
    """
    rows = (
        await session.execute(
            select(Capability, CapabilityControl.control_id)
            .join(CapabilityComponent, CapabilityComponent.capability_id == Capability.id)
            .join(SystemComponent, SystemComponent.id == CapabilityComponent.component_id)
            .join(System, System.id == SystemComponent.system_id)
            .join(CapabilityControl, CapabilityControl.capability_id == Capability.id)
            .where(
                SystemComponent.system_id == system_id,
                Capability.organization_id == System.organization_id,
            )
        )
    ).all()
    return [(r[0], r[1]) for r in rows]


async def _control_rows_by_canonical(
    session: AsyncSession, canonical_ids: set[str]
) -> dict[str, int]:
    """Map canonical id -> ``controls.id``.

    ``controls.identifier`` is zero-padded (``AC-01``) while the canonical form
    is ``AC-1``, so both sides are canonicalized before comparison rather than
    string-matched -- a raw compare would silently match nothing.
    """
    if not canonical_ids:
        return {}
    out: dict[str, int] = {}
    for ctl_id, identifier in (
        await session.execute(select(Control.id, Control.identifier))
    ).all():
        c = canonicalize(identifier)
        if c is not None and c.value in canonical_ids:
            out[c.value] = ctl_id
    return out


async def derive_for_system(session: AsyncSession, *, system_id: int) -> int:
    """Annotate this system's control implementations from capability coverage.

    Returns the number of rows whose derived values actually changed, so an
    idempotent re-run reports zero.
    """
    pairs = await _capabilities_for_system(session, system_id=system_id)

    # canonical control id -> the capabilities claiming it
    grouped: dict[str, list[Capability]] = {}
    for cap, raw_control in pairs:
        c = canonicalize(raw_control)
        if c is None:
            continue
        grouped.setdefault(c.value, []).append(cap)

    control_ids = await _control_rows_by_canonical(session, set(grouped))
    now = datetime.now(UTC)
    touched = 0

    # Controls this system's capabilities currently cover with a real rollup
    # (not None, i.e. not just not_applicable contributors). Anything else
    # that still carries a derived_status is stale: the capability was
    # deleted, its component/control edge removed, or its status flipped to
    # not_applicable -- and the loop below only ever visits *current*
    # coverage, so a row it no longer reaches would otherwise keep naming a
    # capability that may no longer back it. Clear those first.
    covered_ctl_ids = {
        control_ids[canonical_id]
        for canonical_id, caps in grouped.items()
        if control_ids.get(canonical_id) is not None
        and roll_up([c.status for c in caps]) is not None
    }
    stale = (
        await session.execute(
            select(ControlImplementation).where(
                ControlImplementation.system_id == system_id,
                ControlImplementation.derived_status.is_not(None),
                ControlImplementation.control_id.not_in(covered_ctl_ids),
            )
        )
    ).scalars().all()
    for row in stale:
        row.derived_status = None
        row.derived_at = None
        row.derived_from = {}
        touched += 1

    for canonical_id, caps in grouped.items():
        ctl_row_id = control_ids.get(canonical_id)
        if ctl_row_id is None:
            continue  # capability targets a control this deployment lacks
        derived = roll_up([c.status for c in caps])
        if derived is None:
            continue

        impl = (
            await session.execute(
                select(ControlImplementation).where(
                    ControlImplementation.system_id == system_id,
                    ControlImplementation.control_id == ctl_row_id,
                )
            )
        ).scalars().first()
        if impl is None:
            continue  # never create a row -- see the module docstring

        contributors: dict[str, Any] = {
            "capabilities": sorted(c.key for c in caps),
            # Status per contributor, so a conservative rollup is explainable:
            # the reader can see which capability lowered the result.
            "detail": sorted(f"{c.key}={c.status}" for c in caps),
        }
        if impl.derived_status == derived and impl.derived_from == contributors:
            continue  # unchanged -- keep derived_at stable so re-runs are no-ops

        impl.derived_status = derived
        impl.derived_at = now
        impl.derived_from = contributors
        touched += 1

    if touched:
        await session.flush()
        log.info("capability.derived", system_id=system_id, rows=touched)
    return touched


async def derive_for_org(session: AsyncSession, *, organization_id: int) -> dict[str, Any]:
    """Derive every live system in one organization.

    The org-level sibling of :func:`derive_for_system`, shaped like
    ``collection.collect_for_org`` so the scheduler can run it as one
    per-tenant step inside its own savepoint.

    Soft-deleted systems are skipped: a deleted system is not something the
    platform should still be annotating.
    """
    from ..models import System  # noqa: PLC0415 -- avoids a models import cycle

    system_ids = (
        await session.execute(
            select(System.id)
            .where(System.organization_id == organization_id, System.deleted_at.is_(None))
            .order_by(System.id)
        )
    ).scalars().all()

    rows = 0
    for sid in system_ids:
        rows += await derive_for_system(session, system_id=sid)
    return {
        "organization_id": organization_id,
        "systems": len(system_ids),
        "rows_annotated": rows,
    }
