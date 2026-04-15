"""Generic workbook tab viewer endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...models import Worksheet, WorksheetRow
from ...schemas import WorksheetOut, WorksheetRowOut
from ..deps import get_session

router = APIRouter(prefix="/api/worksheets", tags=["worksheets"])


@router.get("", response_model=list[WorksheetOut])
async def list_worksheets(
    session: AsyncSession = Depends(get_session),
) -> list[WorksheetOut]:
    rows = (await session.execute(select(Worksheet).order_by(Worksheet.name))).scalars().all()
    return [WorksheetOut.model_validate(r) for r in rows]


@router.get("/{slug}")
async def get_worksheet(
    slug: str,
    session: AsyncSession = Depends(get_session),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    sheet = (
        await session.execute(select(Worksheet).where(Worksheet.slug == slug))
    ).scalar_one_or_none()
    if sheet is None:
        raise HTTPException(404, "worksheet not found")

    total = (
        await session.execute(
            select(func.count(WorksheetRow.id)).where(WorksheetRow.worksheet_id == sheet.id)
        )
    ).scalar_one()
    rows = (
        (
            await session.execute(
                select(WorksheetRow)
                .where(WorksheetRow.worksheet_id == sheet.id)
                .order_by(WorksheetRow.row_index)
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )

    return {
        "worksheet": WorksheetOut.model_validate(sheet).model_dump(),
        "total": total,
        "items": [WorksheetRowOut.model_validate(r).model_dump() for r in rows],
    }
