"""Outbox retention: finished jobs are history, dead letters are work.

Derived-view ``done``/``merged`` jobs go after a day, ``done`` webhook jobs
after 30 days. ``failed`` jobs are never deleted: they are the operator's
queue. Keyed on ``finished_at``, falling back to ``created_at`` for a row the
reaper dead-lettered without stamping it. Run on an UNSCOPED session
(``ccf_app`` has no DELETE on this table).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, delete, func
from sqlalchemy.ext.asyncio import AsyncSession

from ..models_outbox import OutboxJob

DERIVED_RETENTION = timedelta(days=1)
WEBHOOK_RETENTION = timedelta(days=30)


async def purge_outbox(session: AsyncSession, *, now: datetime | None = None) -> dict[str, int]:
    now = now or datetime.now(UTC)
    finished = func.coalesce(OutboxJob.finished_at, OutboxJob.created_at)
    derived = await session.execute(
        delete(OutboxJob).where(
            OutboxJob.consumer != "webhook",
            OutboxJob.status.in_(("done", "merged")),
            finished < now - DERIVED_RETENTION,
        )
    )
    webhook = await session.execute(
        delete(OutboxJob).where(
            and_(
                OutboxJob.consumer == "webhook",
                OutboxJob.status == "done",
                finished < now - WEBHOOK_RETENTION,
            )
        )
    )
    return {
        "derived": derived.rowcount or 0,  # type: ignore[attr-defined]
        "webhook": webhook.rowcount or 0,  # type: ignore[attr-defined]
    }
