"""FedRAMP 20x VDR: record evaluations, read a system's deadlines.

Writes go through :mod:`ccf.vdr.service`; viewers are refused by the app's
read-only gate like every other write. See
docs/superpowers/specs/2026-11-05-vdr-engine-design.md.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...models_vdr import VulnerabilityEvaluation
from ...vdr import service
from ..auth_deps import get_principal
from ..deps import get_session
from .poams import _require_poam
from .systems import require_system_in_scope

router = APIRouter(tags=["vdr"])


class EvaluationIn(BaseModel):
    pain_rating: int = Field(ge=0, le=5)
    internet_reachable: bool
    likely_exploitable: bool
    false_positive: bool = False
    rationale: str = Field(min_length=1, max_length=20000)


def _eval_out(e: VulnerabilityEvaluation) -> dict[str, Any]:
    return {
        "id": e.id,
        "poam_id": e.poam_id,
        "pain_rating": e.pain_rating,
        "internet_reachable": e.internet_reachable,
        "likely_exploitable": e.likely_exploitable,
        "false_positive": e.false_positive,
        "rationale": e.rationale,
        "evaluated_by": e.evaluated_by,
        "evaluated_at": e.evaluated_at,
        "requires_confirmation": e.requires_confirmation,
        "confirmed_by": e.confirmed_by,
        "confirmed_at": e.confirmed_at,
        "effective": e.effective,
    }


def _done_out(obj: Any, done: service.Recorded) -> dict[str, Any]:
    return {
        "evaluation": _eval_out(done.evaluation),
        "status": service.status_out(obj, done.status),
        "pending_confirmation": done.pending_confirmation,
        "due_on_changed": done.due_on_changed,
        "previous_due_on": done.tightened_from,
    }


@router.get("/api/poams/{pid}/evaluations")
async def list_evaluations(
    pid: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    obj = await _require_poam(session, pid, principal)
    return [_eval_out(e) for e in await service.history(session, obj.id)]


@router.post("/api/poams/{pid}/evaluations", status_code=201)
async def record_evaluation(
    pid: int,
    body: EvaluationIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    obj = await _require_poam(session, pid, principal)
    try:
        done = await service.record_evaluation(
            session,
            poam=obj,
            pain_rating=body.pain_rating,
            internet_reachable=body.internet_reachable,
            likely_exploitable=body.likely_exploitable,
            false_positive=body.false_positive,
            rationale=body.rationale,
            principal=principal,
        )
    except service.EvaluationError as e:
        raise HTTPException(e.status, str(e)) from e
    await session.commit()
    return _done_out(obj, done)


@router.post("/api/poams/{pid}/evaluations/{eid}/confirm")
async def confirm_evaluation(
    pid: int,
    eid: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Put an evaluation that relaxes a deadline into effect (not its author)."""
    obj = await _require_poam(session, pid, principal)
    try:
        done = await service.confirm_evaluation(
            session, poam=obj, evaluation_id=eid, principal=principal
        )
    except service.EvaluationError as e:
        raise HTTPException(e.status, str(e)) from e
    await session.commit()
    return _done_out(obj, done)


@router.get("/api/systems/{sid}/vdr")
async def system_vdr(
    sid: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    system = await require_system_in_scope(session, sid, principal)
    return await service.system_vdr(session, system)
