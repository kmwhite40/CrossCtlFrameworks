"""GRC insights API — data quality, unified controls, executive rollup, export."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...governance import exporter, insights
from ..auth_deps import get_principal
from ..deps import get_session

router = APIRouter(prefix="/api", tags=["insights"])


@router.get("/admin/data-quality")
async def data_quality(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """GRC data-completeness checks (systems, evidence, POA&M, risk, vendor, policy)."""
    return await insights.data_quality(session, org_id=principal.org_id)


@router.get("/controls/unified")
async def unified(
    limit: int = Query(25, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Implement-once, satisfy-many: controls ranked by cross-framework coverage."""
    return await insights.unified_controls(session, limit=limit)


@router.get("/reports/executive")
async def executive(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Consolidated executive rollup (posture, risk bands, POA&M aging, data quality)."""
    return await insights.executive(session, org_id=principal.org_id)


@router.get("/export/{dataset}", response_model=None)
async def export_dataset(
    dataset: str,
    fmt: str = Query("csv"),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> Response:
    """Export a register (poams|risks|vendors|policies) as csv|json|md."""
    try:
        content, media, filename = await exporter.export(
            session, dataset=dataset, fmt=fmt, org_id=principal.org_id
        )
    except ValueError as e:
        raise HTTPException(422, str(e)) from e
    return Response(
        content=content,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
