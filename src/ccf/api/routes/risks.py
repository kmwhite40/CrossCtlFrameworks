"""Risk register CRUD."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...models import Risk
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


@router.get("")
async def list_risks(
    session: AsyncSession = Depends(get_session),
    system_id: int | None = None,
) -> list[dict[str, Any]]:
    stmt = select(Risk).order_by(Risk.created_at.desc())
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
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]


@router.post("", status_code=201)
async def create_risk(
    body: RiskCreate,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    obj = Risk(**body.model_dump(exclude_none=True))
    session.add(obj)
    await session.commit()
    await session.refresh(obj)
    return {"id": obj.id, "title": obj.title, "status": obj.status}


@router.patch("/{rid}")
async def update_risk(
    rid: int,
    body: RiskUpdate,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    obj = (await session.execute(select(Risk).where(Risk.id == rid))).scalar_one_or_none()
    if obj is None:
        raise HTTPException(404, "risk not found")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(obj, k, v)
    await session.commit()
    await session.refresh(obj)
    return {"id": obj.id, "status": obj.status}
