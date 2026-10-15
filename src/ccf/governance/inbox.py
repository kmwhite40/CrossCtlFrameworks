"""Whose notifications, and which of them this user has read.

One definition shared by the API and the pages, so they cannot disagree.

* **Visible:** a notification broadcast to the org (``user_id`` NULL) or
  addressed to this user. A notification addressed to another member is not
  shown -- the list used to return every row in the org.
* **Read:** per user (``NotificationRead``). ``Notification.read_at`` was one
  column on a broadcast row, so marking read silenced the alert for everyone;
  it now serves only the SYSTEM principal, which has no user id.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Select, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import Principal
from ..models import Notification, NotificationRead


def visible(principal: Principal) -> Select[tuple[Notification]]:
    stmt = select(Notification).order_by(Notification.created_at.desc())
    if principal.org_id is not None:
        stmt = stmt.where(Notification.organization_id == principal.org_id)
    if principal.user_id is not None:
        stmt = stmt.where(
            or_(Notification.user_id.is_(None), Notification.user_id == principal.user_id)
        )
    return stmt


async def read_ids(
    session: AsyncSession, principal: Principal, notifications: list[Notification]
) -> set[int]:
    """Which of ``notifications`` this principal has read."""
    if principal.user_id is None:
        return {n.id for n in notifications if n.read_at is not None}
    ids = [n.id for n in notifications]
    if not ids:
        return set()
    rows = await session.execute(
        select(NotificationRead.notification_id).where(
            NotificationRead.user_id == principal.user_id,
            NotificationRead.notification_id.in_(ids),
        )
    )
    return set(rows.scalars())


def unread_only(stmt: Select[Any], principal: Principal) -> Select[Any]:
    if principal.user_id is None:
        return stmt.where(Notification.read_at.is_(None))
    already = select(NotificationRead.notification_id).where(
        NotificationRead.user_id == principal.user_id
    )
    return stmt.where(Notification.id.not_in(already))


async def mark_read(
    session: AsyncSession, principal: Principal, notifications: list[Notification]
) -> int:
    """Mark ``notifications`` read for this principal only. Returns rows newly marked."""
    if not notifications:
        return 0
    if principal.user_id is None:
        now = datetime.now(UTC)
        fresh = [n for n in notifications if n.read_at is None]
        for n in fresh:
            n.read_at = now
        return len(fresh)
    stmt = (
        insert(NotificationRead)
        .values(
            [
                {
                    "notification_id": n.id,
                    "user_id": principal.user_id,
                    "organization_id": n.organization_id,
                }
                for n in notifications
            ]
        )
        .on_conflict_do_nothing(constraint="uq_notification_read_user")
    )
    result = await session.execute(stmt)
    return int(getattr(result, "rowcount", 0) or 0)
