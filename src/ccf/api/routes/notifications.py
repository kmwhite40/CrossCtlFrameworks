"""Notification / alert hub API — unified inbox across every module."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...governance import digest, inbox
from ...models import Notification
from ..auth_deps import get_principal
from ..deps import get_session

router = APIRouter(prefix="/api/notifications", tags=["notifications"])


def _out(n: Notification, read: bool) -> dict[str, Any]:
    return {
        "id": n.id,
        "severity": n.severity,
        "category": n.category,
        "title": n.title,
        "body": n.body,
        "entity_type": n.entity_type,
        "entity_id": n.entity_id,
        "read": read,
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
    """The caller's inbox: org broadcasts plus what is addressed to them.

    "Read" is the caller's own read state (``ccf.governance.inbox``).
    """
    stmt = inbox.visible(principal)
    if unread_only:
        stmt = inbox.unread_only(stmt, principal)
    if category:
        stmt = stmt.where(Notification.category == category)
    rows = list((await session.execute(stmt.limit(min(limit, 500)))).scalars().all())
    read = await inbox.read_ids(session, principal, rows)
    return {
        "unread": await inbox.unread_count(session, principal),
        "items": [_out(n, n.id in read) for n in rows],
    }


@router.post("/{notification_id}/read")
async def mark_read(
    notification_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Mark one notification read **for the caller** -- nobody else's inbox changes."""
    stmt = inbox.visible(principal).where(Notification.id == notification_id)
    n = (await session.execute(stmt)).scalar_one_or_none()
    if n is None:
        raise HTTPException(404, "notification not found")
    await inbox.mark_read(session, principal, [n])
    await session.commit()
    return _out(n, True)


@router.post("/read-all")
async def mark_all_read(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, int]:
    """Mark everything in the caller's inbox read, for the caller only."""
    marked = await inbox.mark_all_read(session, principal)
    await session.commit()
    return {"marked_read": marked}


@router.post("/scan")
async def scan(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Run the org-level alert digest (ATO expiry, catalog drift, reviews due)."""
    today = datetime.now(UTC).date()
    counts = (
        await digest.run(session, today=today, org_id=principal.org_id)
        if principal.org_id is not None
        else await digest.run_all(session, today=today)
    )
    await session.commit()
    return {"raised": counts}
