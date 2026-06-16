"""Shared DB-backed SPRS scoring helpers (used by the API and analytics)."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import ScoringControl, ScoringStatus
from .engine import score_system


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
    states = {
        cid: state
        for cid, state in (
            await session.execute(
                select(ScoringControl.control_id, ScoringStatus.state)
                .join(ScoringStatus, ScoringStatus.scoring_control_id == ScoringControl.id)
                .where(ScoringStatus.system_id == system_id)
            )
        ).all()
    }
    refs = [
        {"control_id": c.control_id, "domain": c.domain, "point_value": c.point_value}
        for c in controls
    ]
    return score_system(refs, states).as_dict()
