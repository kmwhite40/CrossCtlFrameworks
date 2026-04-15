"""Cross-framework mapping search (#39)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...models import Control, Framework, FrameworkMapping
from ..deps import get_session

router = APIRouter(prefix="/api/mappings", tags=["mappings"])


@router.get("/search")
async def search_mappings(
    q: str = Query(..., min_length=2),
    framework: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    stmt = (
        select(
            Control.identifier,
            Control.control_name,
            Framework.code.label("framework_code"),
            Framework.name.label("framework_name"),
            FrameworkMapping.column_key,
            FrameworkMapping.value,
        )
        .select_from(FrameworkMapping)
        .join(Control, Control.id == FrameworkMapping.control_id)
        .join(Framework, Framework.id == FrameworkMapping.framework_id, isouter=True)
        .where(FrameworkMapping.value.ilike(f"%{q}%"))
        .order_by(Control.sort_as.nulls_last(), Control.identifier)
        .limit(limit)
    )
    if framework:
        stmt = stmt.where(Framework.code == framework.upper())
    rows = (await session.execute(stmt)).all()
    return {
        "query": q,
        "framework": framework,
        "results": [{str(k): v for k, v in r._mapping.items()} for r in rows],
    }
