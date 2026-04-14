"""Control catalog endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ...models import Control, ControlFamily, FrameworkMapping
from ...schemas import (
    ControlDetail,
    ControlFamilyOut,
    ControlPage,
    ControlSummary,
    FrameworkMappingOut,
)
from ..deps import get_session

router = APIRouter(prefix="/api/controls", tags=["controls"])


@router.get("", response_model=ControlPage)
async def list_controls(
    session: AsyncSession = Depends(get_session),
    family: str | None = Query(None, description="Family code (e.g. AC, AU)"),
    baseline: str | None = Query(None, pattern="^(low|mod|high)$"),
    q: str | None = Query(None, description="Free-text filter on name/identifier"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> ControlPage:
    stmt = select(Control).options(selectinload(Control.family))
    count_stmt = select(func.count(Control.id))

    if family:
        stmt = stmt.join(Control.family).where(ControlFamily.code == family.upper())
        count_stmt = count_stmt.join(Control.family).where(
            ControlFamily.code == family.upper()
        )
    if baseline:
        col = {"low": Control.fisma_low, "mod": Control.fisma_mod, "high": Control.fisma_high}[baseline]
        stmt = stmt.where(col.is_(True))
        count_stmt = count_stmt.where(col.is_(True))
    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            (Control.identifier.ilike(like)) | (Control.control_name.ilike(like))
        )
        count_stmt = count_stmt.where(
            (Control.identifier.ilike(like)) | (Control.control_name.ilike(like))
        )

    stmt = stmt.order_by(Control.sort_as.nulls_last(), Control.identifier).limit(limit).offset(offset)

    total = (await session.execute(count_stmt)).scalar_one()
    rows = (await session.execute(stmt)).scalars().all()
    return ControlPage(total=total, items=[ControlSummary.model_validate(r) for r in rows])


@router.get("/families", response_model=list[ControlFamilyOut])
async def list_families(session: AsyncSession = Depends(get_session)) -> list[ControlFamilyOut]:
    rows = (
        await session.execute(select(ControlFamily).order_by(ControlFamily.code))
    ).scalars().all()
    return [ControlFamilyOut.model_validate(r) for r in rows]


@router.get("/{identifier}", response_model=ControlDetail)
async def get_control(
    identifier: str,
    session: AsyncSession = Depends(get_session),
) -> ControlDetail:
    ctl = (
        await session.execute(
            select(Control)
            .where(Control.identifier == identifier)
            .options(
                selectinload(Control.family),
                selectinload(Control.mappings).selectinload(FrameworkMapping.framework),
            )
        )
    ).scalar_one_or_none()
    if ctl is None:
        raise HTTPException(status_code=404, detail="control not found")

    detail = ControlDetail.model_validate(ctl)
    detail.mappings = [FrameworkMappingOut.model_validate(m) for m in ctl.mappings]
    return detail
