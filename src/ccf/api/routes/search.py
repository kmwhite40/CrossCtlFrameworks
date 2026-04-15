"""Full-text search endpoint."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...models import Control
from ..deps import get_session

router = APIRouter(prefix="/api/search", tags=["search"])


@router.get("")
async def search(
    q: str = Query(..., min_length=2),
    limit: int = Query(25, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    tsq = func.plainto_tsquery("english", q)
    stmt = (
        select(
            Control.identifier,
            Control.control_name,
            Control.description,
            func.ts_rank(Control.search_vector, tsq).label("rank"),
        )
        .where(Control.search_vector.op("@@")(tsq))
        .order_by(func.ts_rank(Control.search_vector, tsq).desc())
        .limit(limit)
    )
    rows = (await session.execute(stmt)).all()
    return {
        "query": q,
        "results": [
            {
                "identifier": r.identifier,
                "control_name": r.control_name,
                "description": (r.description or "")[:240],
                "rank": float(r.rank),
            }
            for r in rows
        ],
    }
