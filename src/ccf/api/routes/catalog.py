"""Catalog currency — inspect authoritative sources and trigger drift checks.

Read endpoints surface the last-known drift status per source (safe in the
read-only Reader build). The ``check`` endpoint runs a poll on demand; it is a
POST, so the read-only guard blocks it automatically.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...etl.sources import check_source
from ...models import CatalogCheck, CatalogSource
from ..deps import get_session

router = APIRouter(prefix="/api/catalog", tags=["catalog"])


def _source_out(s: CatalogSource) -> dict[str, Any]:
    return {
        "id": s.id,
        "key": s.key,
        "name": s.name,
        "authority": s.authority,
        "kind": s.kind,
        "url": s.url,
        "framework_code": s.framework_code,
        "enabled": s.enabled,
        "auto_ingest": s.auto_ingest,
        "revision_label": s.revision_label,
        "item_count": s.item_count,
        "last_status": s.last_status,
        "last_error": s.last_error,
        "last_checked_at": s.last_checked_at,
        "last_changed_at": s.last_changed_at,
    }


def _check_out(c: CatalogCheck) -> dict[str, Any]:
    return {
        "id": c.id,
        "source_id": c.source_id,
        "checked_at": c.checked_at,
        "status": c.status,
        "http_status": c.http_status,
        "sha256": c.sha256,
        "duration_ms": c.duration_ms,
        "detail": c.detail,
    }


@router.get("/sources")
async def list_sources(session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    """All registered catalog sources with their last-known drift status."""
    rows = (await session.execute(select(CatalogSource).order_by(CatalogSource.id))).scalars().all()
    return [_source_out(s) for s in rows]


@router.get("/sources/{source_id}/checks")
async def list_checks(
    source_id: int,
    limit: int = 20,
    session: AsyncSession = Depends(get_session),
) -> list[dict[str, Any]]:
    """Recent drift checks for one source (most recent first)."""
    rows = (
        (
            await session.execute(
                select(CatalogCheck)
                .where(CatalogCheck.source_id == source_id)
                .order_by(CatalogCheck.id.desc())
                .limit(min(limit, 200))
            )
        )
        .scalars()
        .all()
    )
    return [_check_out(c) for c in rows]


@router.post("/sources/{source_id}/check")
async def check_now(
    source_id: int,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Poll one source immediately and return the resulting check."""
    source = (
        await session.execute(select(CatalogSource).where(CatalogSource.id == source_id))
    ).scalar_one_or_none()
    if source is None:
        raise HTTPException(status_code=404, detail="Unknown catalog source")
    check = await check_source(session, source)
    await session.commit()
    return _check_out(check)
