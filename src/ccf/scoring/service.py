"""Shared DB-backed SPRS scoring helpers (used by the API and analytics)."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import ScoringControl, ScoringStatus
from .engine import ASSESSED, DERIVED, score_system


async def system_score_summary(session: AsyncSession, system_id: int) -> dict[str, Any]:
    """Compute the live SPRS summary for one system as a plain dict.

    Single source of truth for both ``/api/scoring`` and the posture analytics
    so the two never diverge.
    """
    controls = (
        (await session.execute(select(ScoringControl).order_by(ScoringControl.sort_order)))
        .scalars()
        .all()
    )
    recorded = (
        await session.execute(
            select(ScoringControl.control_id, ScoringStatus.state, ScoringStatus.source)
            .join(ScoringStatus, ScoringStatus.scoring_control_id == ScoringControl.id)
            .where(ScoringStatus.system_id == system_id)
        )
    ).all()
    states = {cid: state for cid, state, _ in recorded}
    sources = {cid: source for cid, _, source in recorded}
    refs = [
        {"control_id": c.control_id, "domain": c.domain, "point_value": c.point_value}
        for c in controls
    ]
    return score_system(refs, states, sources=sources).as_dict()


def record_assessed_state(
    status: ScoringStatus,
    state: str,
    *,
    notes: str | None = None,
    evidence_ref: str | None = None,
) -> None:
    """Apply a human (or evidence-backed) state, taking ownership of provenance.

    Both write paths -- the JSON API and the HTMX matrix -- go through here, so
    a new caller cannot forget the part that matters: a state a person sets is
    ``assessed``, and the derivation's label must not survive it. Before this
    existed the label lived only in ``notes`` and nothing cleared it, so three
    rows on one tenant read ``derived: platform:m365_gcc_high`` while holding
    ``implemented`` -- a state the derivation cannot produce. Microsoft was
    being credited for somebody's own claim.

    A derived note is dropped when the caller supplies none; a note the caller
    wrote is never touched, because it is theirs.
    """
    status.state = state
    status.source = ASSESSED
    status.derived_from = None
    if notes is not None:
        status.notes = notes
    elif (status.notes or "").startswith("derived: "):
        status.notes = None
    if evidence_ref is not None:
        status.evidence_ref = evidence_ref


def record_derived_state(status: ScoringStatus, state: str, *, derived_from: str) -> None:
    """Apply a state the profile derivation computed, labelled as derived."""
    status.state = state
    status.source = DERIVED
    status.derived_from = derived_from[:64]
    status.notes = f"derived: {derived_from}"
