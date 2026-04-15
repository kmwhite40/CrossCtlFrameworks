"""POA&M CRUD."""
from __future__ import annotations

from datetime import date

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...models import POAM
from ...schemas import POAMOut
from ..deps import get_session

router = APIRouter(prefix="/api/poams", tags=["poams"])

SEVERITIES = r"^(low|moderate|high|critical)$"
STATUSES = r"^(open|in_progress|completed|risk_accepted|closed)$"


class POAMCreate(BaseModel):
    system_id: int
    control_id: int | None = None
    title: str
    weakness: str | None = None
    severity: str = Field("moderate", pattern=SEVERITIES)
    status: str = Field("open", pattern=STATUSES)
    identified_on: date | None = None
    due_on: date | None = None
    owner_user_id: int | None = None


class POAMUpdate(BaseModel):
    title: str | None = None
    weakness: str | None = None
    severity: str | None = Field(None, pattern=SEVERITIES)
    status: str | None = Field(None, pattern=STATUSES)
    identified_on: date | None = None
    due_on: date | None = None
    closed_on: date | None = None
    owner_user_id: int | None = None


@router.get("", response_model=list[POAMOut])
async def list_poams(
    session: AsyncSession = Depends(get_session),
    system_id: int | None = None,
    status: str | None = None,
) -> list[POAMOut]:
    stmt = select(POAM).order_by(POAM.due_on.nulls_last())
    if system_id is not None:
        stmt = stmt.where(POAM.system_id == system_id)
    if status:
        stmt = stmt.where(POAM.status == status)
    rows = (await session.execute(stmt)).scalars().all()
    return [POAMOut.model_validate(r) for r in rows]


@router.post("", response_model=POAMOut, status_code=201)
async def create_poam(
    body: POAMCreate,
    session: AsyncSession = Depends(get_session),
) -> POAMOut:
    obj = POAM(**body.model_dump(exclude_none=True))
    session.add(obj)
    await session.commit()
    await session.refresh(obj)
    return POAMOut.model_validate(obj)


@router.patch("/{pid}", response_model=POAMOut)
async def update_poam(
    pid: int, body: POAMUpdate,
    session: AsyncSession = Depends(get_session),
) -> POAMOut:
    obj = (await session.execute(select(POAM).where(POAM.id == pid))).scalar_one_or_none()
    if obj is None:
        raise HTTPException(404, "poam not found")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(obj, k, v)
    await session.commit()
    await session.refresh(obj)
    return POAMOut.model_validate(obj)


@router.post("/{pid}/close", response_model=POAMOut)
async def close_poam(
    pid: int, session: AsyncSession = Depends(get_session),
) -> POAMOut:
    from datetime import date as _d
    obj = (await session.execute(select(POAM).where(POAM.id == pid))).scalar_one_or_none()
    if obj is None:
        raise HTTPException(404, "poam not found")
    obj.status = "closed"
    obj.closed_on = _d.today()
    await session.commit()
    await session.refresh(obj)
    return POAMOut.model_validate(obj)
