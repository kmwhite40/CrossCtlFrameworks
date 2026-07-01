"""Risk register CRUD."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...governance.risk import band, compute_scores
from ...models import Risk, System
from ..auth_deps import get_principal, org_systems_subq
from ..deps import get_session

router = APIRouter(prefix="/api/risks", tags=["risks"])

LEVEL = r"^(low|moderate|high)$"
TREATMENT = r"^(mitigate|transfer|accept|avoid)$"
STATUS = r"^(open|mitigated|accepted|closed)$"


class RiskCreate(BaseModel):
    title: str
    system_id: int | None = None
    description: str | None = None
    likelihood: str | None = Field(None, pattern=LEVEL)
    impact: str | None = Field(None, pattern=LEVEL)
    treatment: str | None = Field(None, pattern=TREATMENT)
    status: str = Field("open", pattern=STATUS)


class RiskUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    likelihood: str | None = Field(None, pattern=LEVEL)
    impact: str | None = Field(None, pattern=LEVEL)
    treatment: str | None = Field(None, pattern=TREATMENT)
    status: str | None = Field(None, pattern=STATUS)


async def _require_risk(session: AsyncSession, rid: int, principal: Principal) -> Risk:
    obj = (await session.execute(select(Risk).where(Risk.id == rid))).scalar_one_or_none()
    if obj is None:
        raise HTTPException(404, "risk not found")
    if principal.org_id is not None:
        ok = (
            await session.execute(
                select(System.id).where(
                    System.id == obj.system_id, System.organization_id == principal.org_id
                )
            )
        ).scalar_one_or_none()
        if ok is None:
            raise HTTPException(404, "risk not found")
    return obj


@router.get("")
async def list_risks(
    session: AsyncSession = Depends(get_session),
    system_id: int | None = None,
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    stmt = select(Risk).order_by(Risk.created_at.desc())
    if principal.org_id is not None:
        stmt = stmt.where(Risk.system_id.in_(org_systems_subq(principal)))
    if system_id is not None:
        stmt = stmt.where(Risk.system_id == system_id)
    rows = (await session.execute(stmt)).scalars().all()
    return [
        {
            "id": r.id,
            "system_id": r.system_id,
            "title": r.title,
            "description": r.description,
            "likelihood": r.likelihood,
            "impact": r.impact,
            "treatment": r.treatment,
            "status": r.status,
            "inherent_score": r.inherent_score,
            "residual_score": r.residual_score,
            "residual_band": band(r.residual_score),
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]


def _rescore(obj: Risk) -> None:
    obj.inherent_score, obj.residual_score = compute_scores(
        obj.likelihood, obj.impact, obj.treatment
    )


@router.post("", status_code=201)
async def create_risk(
    body: RiskCreate,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    if principal.org_id is not None and body.system_id is not None:
        ok = (
            await session.execute(
                select(System.id).where(
                    System.id == body.system_id, System.organization_id == principal.org_id
                )
            )
        ).scalar_one_or_none()
        if ok is None:
            raise HTTPException(404, "system not found")
    obj = Risk(**body.model_dump(exclude_none=True))
    _rescore(obj)
    session.add(obj)
    await session.commit()
    await session.refresh(obj)
    return {
        "id": obj.id,
        "title": obj.title,
        "status": obj.status,
        "inherent_score": obj.inherent_score,
        "residual_score": obj.residual_score,
        "residual_band": band(obj.residual_score),
    }


@router.patch("/{rid}")
async def update_risk(
    rid: int,
    body: RiskUpdate,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    obj = await _require_risk(session, rid, principal)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(obj, k, v)
    _rescore(obj)
    await session.commit()
    await session.refresh(obj)
    return {
        "id": obj.id,
        "status": obj.status,
        "inherent_score": obj.inherent_score,
        "residual_score": obj.residual_score,
        "residual_band": band(obj.residual_score),
    }
