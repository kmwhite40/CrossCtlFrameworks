"""Live CMMC L2 SPRS scoring API.

Replaces the static scoring-matrix spreadsheet: the reference matrix lives in
``ccf.scoring_controls`` and each system carries per-control implementation
states in ``ccf.scoring_statuses``. Setting a state recomputes the SPRS score on
the spot, so the matrix is always live rather than a stale workbook.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...models import ScoringControl, ScoringStatus, System
from ...scoring.engine import STATES
from ...scoring.seed import seed_scoring_controls
from ...scoring.service import system_score_summary
from ..deps import get_session

router = APIRouter(prefix="/api/scoring", tags=["scoring"])


class ScoringControlOut(BaseModel):
    control_id: str
    nist_id: str | None
    domain: str
    title: str | None
    point_value: str
    scoring_bucket: str | None
    m365_coverage_status: str | None
    m365_primary_services: list[str] = []
    m365_implementation_statement: str | None = None
    recommended_customer_evidence: str | None = None
    recommended_provider_evidence: str | None = None
    objective_parts: list[dict[str, Any]] = []

    model_config = {"from_attributes": True}


class StateUpdate(BaseModel):
    state: str = Field(..., description=f"One of: {', '.join(STATES)}")
    notes: str | None = None
    evidence_ref: str | None = None


async def _require_system(session: AsyncSession, system_id: int) -> System:
    sys = (await session.execute(select(System).where(System.id == system_id))).scalar_one_or_none()
    if sys is None:
        raise HTTPException(404, "system not found")
    return sys


async def compute_summary(session: AsyncSession, system_id: int) -> dict[str, Any]:
    """Live SPRS summary for a system (delegates to the shared scoring service)."""
    return await system_score_summary(session, system_id)


@router.get("/controls", response_model=list[ScoringControlOut])
async def list_scoring_controls(
    session: AsyncSession = Depends(get_session),
    domain: str | None = Query(None),
    point_value: str | None = Query(None),
    coverage: str | None = Query(None),
    q: str | None = Query(None),
) -> list[ScoringControlOut]:
    stmt = select(ScoringControl).order_by(ScoringControl.sort_order)
    if domain:
        stmt = stmt.where(ScoringControl.domain == domain.upper())
    if point_value:
        stmt = stmt.where(ScoringControl.point_value == point_value)
    if coverage:
        stmt = stmt.where(ScoringControl.m365_coverage_status == coverage)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(ScoringControl.control_id.ilike(like) | ScoringControl.title.ilike(like))
    rows = (await session.execute(stmt)).scalars().all()
    return [ScoringControlOut.model_validate(r) for r in rows]


@router.post("/seed")
async def seed(session: AsyncSession = Depends(get_session)) -> dict[str, int]:
    """Load (or refresh) the reference scoring matrix from the committed seed."""
    return await seed_scoring_controls(session)


@router.get("/systems/{system_id}/score")
async def system_score(
    system_id: int, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    await _require_system(session, system_id)
    return await compute_summary(session, system_id)


@router.get("/systems/{system_id}/matrix")
async def system_matrix(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    domain: str | None = Query(None),
) -> dict[str, Any]:
    """The full matrix for a system: each control plus its current live state."""
    await _require_system(session, system_id)
    stmt = select(ScoringControl).order_by(ScoringControl.sort_order)
    if domain:
        stmt = stmt.where(ScoringControl.domain == domain.upper())
    controls = (await session.execute(stmt)).scalars().all()
    states = {
        cid: (state, notes)
        for cid, state, notes in (
            await session.execute(
                select(ScoringControl.control_id, ScoringStatus.state, ScoringStatus.notes)
                .join(ScoringStatus, ScoringStatus.scoring_control_id == ScoringControl.id)
                .where(ScoringStatus.system_id == system_id)
            )
        ).all()
    }
    rows = []
    for c in controls:
        state, notes = states.get(c.control_id, ("not_assessed", None))
        rows.append(
            {
                "control_id": c.control_id,
                "nist_id": c.nist_id,
                "domain": c.domain,
                "title": c.title,
                "point_value": c.point_value,
                "scoring_bucket": c.scoring_bucket,
                "m365_coverage_status": c.m365_coverage_status,
                "state": state,
                "notes": notes,
            }
        )
    summary = await compute_summary(session, system_id)
    return {"system_id": system_id, "controls": rows, "summary": summary}


@router.put("/systems/{system_id}/controls/{control_id}")
async def set_control_state(
    system_id: int,
    control_id: str,
    body: StateUpdate,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Set a control's implementation state and return the recomputed live score."""
    if body.state not in STATES:
        raise HTTPException(422, f"state must be one of {', '.join(STATES)}")
    await _require_system(session, system_id)
    ctrl = (
        await session.execute(select(ScoringControl).where(ScoringControl.control_id == control_id))
    ).scalar_one_or_none()
    if ctrl is None:
        raise HTTPException(404, "scoring control not found")

    status = (
        await session.execute(
            select(ScoringStatus)
            .where(ScoringStatus.system_id == system_id)
            .where(ScoringStatus.scoring_control_id == ctrl.id)
        )
    ).scalar_one_or_none()
    if status is None:
        status = ScoringStatus(system_id=system_id, scoring_control_id=ctrl.id)
        session.add(status)
    status.state = body.state
    if body.notes is not None:
        status.notes = body.notes
    if body.evidence_ref is not None:
        status.evidence_ref = body.evidence_ref
    await session.commit()

    return {
        "control_id": control_id,
        "state": status.state,
        "summary": await compute_summary(session, system_id),
    }
