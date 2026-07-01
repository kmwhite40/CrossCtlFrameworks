"""Notification / alert hub API — unified inbox across every module."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...governance import digest
from ...models import Notification
from ..auth_deps import get_principal
from ..deps import get_session

router = APIRouter(prefix="/api/notifications", tags=["notifications"])


def _out(n: Notification) -> dict[str, Any]:
    return {
        "id": n.id,
        "severity": n.severity,
        "category": n.category,
        "title": n.title,
        "body": n.body,
        "entity_type": n.entity_type,
        "entity_id": n.entity_id,
        "read": n.read_at is not None,
        "created_at": n.created_at,
    }


@router.get("")
async def list_notifications(
    unread_only: bool = False,
    category: str | None = None,
    limit: int = 100,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    stmt = select(Notification).order_by(Notification.created_at.desc())
    if principal.org_id is not None:
        stmt = stmt.where(Notification.organization_id == principal.org_id)
    if unread_only:
        stmt = stmt.where(Notification.read_at.is_(None))
    if category:
        stmt = stmt.where(Notification.category == category)
    rows = (await session.execute(stmt.limit(min(limit, 500)))).scalars().all()
    unread = sum(1 for n in rows if n.read_at is None)
    return {"unread": unread, "items": [_out(n) for n in rows]}


@router.post("/{notification_id}/read")
async def mark_read(
    notification_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    n = (
        await session.execute(select(Notification).where(Notification.id == notification_id))
    ).scalar_one_or_none()
    if n is None:
        raise HTTPException(404, "notification not found")
    if n.read_at is None:
        n.read_at = datetime.now(UTC)
    await session.commit()
    return _out(n)


@router.post("/read-all")
async def mark_all_read(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, int]:
    stmt = (
        update(Notification).where(Notification.read_at.is_(None)).values(read_at=datetime.now(UTC))
    )
    if principal.org_id is not None:
        stmt = stmt.where(Notification.organization_id == principal.org_id)
    result = await session.execute(stmt)
    await session.commit()
    return {"marked_read": result.rowcount or 0}


@router.post("/scan")
async def scan(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Run the org-level alert digest (ATO expiry, catalog drift, reviews due)."""
    counts = await digest.run(session, today=datetime.now(UTC).date(), org_id=principal.org_id)
    await session.commit()
    return {"raised": counts}
