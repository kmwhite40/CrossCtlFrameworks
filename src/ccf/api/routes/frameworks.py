"""Framework catalog endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...models import Control, Framework, FrameworkMapping
from ...schemas import FrameworkOut
from ..deps import get_session

router = APIRouter(prefix="/api/frameworks", tags=["frameworks"])


@router.get("", response_model=list[dict])
async def list_frameworks(
    session: AsyncSession = Depends(get_session),
) -> list[dict]:
    stmt = (
        select(
            Framework.id, Framework.code, Framework.name, Framework.family,
            Framework.description, func.count(FrameworkMapping.id).label("mapping_count"),
        )
        .join(FrameworkMapping, FrameworkMapping.framework_id == Framework.id, isouter=True)
        .group_by(Framework.id)
        .order_by(Framework.family, Framework.name)
    )
    rows = (await session.execute(stmt)).all()
    return [dict(r._mapping) for r in rows]


@router.get("/{code}/controls")
async def framework_controls(
    code: str,
    session: AsyncSession = Depends(get_session),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> dict:
    fw = (
        await session.execute(select(Framework).where(Framework.code == code.upper()))
    ).scalar_one_or_none()
    if fw is None:
        raise HTTPException(404, "framework not found")

    stmt = (
        select(Control.identifier, Control.control_name,
               FrameworkMapping.column_key, FrameworkMapping.value)
        .join(FrameworkMapping, FrameworkMapping.control_id == Control.id)
        .where(FrameworkMapping.framework_id == fw.id)
        .order_by(Control.sort_as.nulls_last(), Control.identifier)
        .limit(limit).offset(offset)
    )
    total = (
        await session.execute(
            select(func.count()).select_from(FrameworkMapping).where(
                FrameworkMapping.framework_id == fw.id,
            )
        )
    ).scalar_one()
    rows = (await session.execute(stmt)).all()
    return {
        "framework": FrameworkOut.model_validate(fw).model_dump(),
        "total": total,
        "items": [dict(r._mapping) for r in rows],
    }
