"""Event-driven reactions — keep state self-consistent across modules.

When something changes, the dependent records update themselves: satisfying a
control proposes closure of its gap POA&M (a human closes it through the
ISSM-08/09 gate), and a control's status change suggests (never writes) the
crosswalked controls it may also apply to. Reactions are explicit
(routes call them) and emit their own follow-up events with ``dispatch=False``
to avoid webhook storms / recursion.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..constants import POAM_ACTIVE_STATUSES
from ..models import POAM, Control, FrameworkMapping
from . import bus

_MET = ("implemented", "inherited", "not_applicable")
_OPEN = POAM_ACTIVE_STATUSES


async def on_scoring_status_changed(
    session: AsyncSession,
    *,
    system_id: int,
    control_id: str,
    state: str,
    previous_state: str | None = None,
    org_id: int | None = None,
    actor: str | None = None,
) -> dict[str, Any]:
    """A CMMC practice changed state → propose closure of its POA&Ms when satisfied.

    Never closes them. The title match also catches the POA&M an assessment
    opened for an other-than-satisfied result, so closing here let whoever set
    the practice state retire an assessor's finding with no milestone, evidence
    or approval. Closing a POA&M asserts the weakness is remediated; a practice
    state is one person's claim, so this does what
    ``control_tests._resolve_on_recovery`` does on a passing test -- a dated
    note and a notification -- and a human closes it through
    ``api/routes/poams.py``'s gate.
    """
    flagged = 0
    # On the transition into a satisfied state only: re-saving an already
    # satisfied practice (to edit its notes, say) appended another dated note
    # to every matching POA&M's remediation plan, which is exported.
    if state in _MET and previous_state not in _MET:
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
            note = (
                f"{control_id} marked {state} on {date.today().isoformat()}"
                f" by {actor or 'automation'} -- review for closure."
            )
            p.remediation_plan = f"{p.remediation_plan}\n{note}" if p.remediation_plan else note
            flagged += 1
            await bus.notify(
                session,
                category="conmon",
                title=f"POA&M ready for closure review: {p.title}"[:512],
                body=note,
                org_id=org_id,
                severity="info",
                entity_type="poam",
                entity_id=p.id,
                dedupe_key=f"poam-practice-met:{p.id}",
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
    return {"gap_poams_flagged_for_review": flagged}


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
    """Suggest the crosswalked peers a control's new status may also apply to.

    Writes nothing. It used to copy the status onto every peer: creating rows
    with ``responsibility="inherited"`` and overwriting what a person had set.
    A shared mapping value says two controls are related, not that one
    satisfies the other, so the copy fabricated implementation (and
    inheritance) claims for controls nobody assessed, and coverage rose with
    them. The capability layer is where one implementation reaches other
    frameworks; it traverses the crosswalk at read time instead of copying.
    """
    peers = await crosswalk_peers(session, control_id)
    if not peers:
        return {"peers": 0, "updated": 0, "suggested": []}
    await bus.emit(
        session,
        verb="suggested",
        entity_type="control_implementation",
        entity_id=control_id,
        summary=f"Status '{status}' may also apply to {len(peers)} crosswalked control(s)",
        org_id=org_id,
        actor=actor or "automation",
        dispatch=False,
    )
    return {"peers": len(peers), "updated": 0, "suggested": peers}


async def resolve_control_id(session: AsyncSession, identifier: str) -> int | None:
    return (
        await session.execute(select(Control.id).where(Control.identifier == identifier))
    ).scalar_one_or_none()
