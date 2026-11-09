"""Outbox retention: finished jobs are history, dead letters are work.

Derived-view ``done``/``merged`` jobs go after a day; ``done`` webhook jobs and
notification posts (``notify_delivery``) after 30 days. ``failed`` jobs are
never deleted: they are the operator's queue. Keyed on ``finished_at``,
falling back to ``created_at`` for a row the reaper dead-lettered without
stamping it. Run on an UNSCOPED session
(``ccf_app`` has no DELETE on this table).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, delete, func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..models_outbox import OutboxJob
from .outbox import AT_LEAST_ONCE

DERIVED_RETENTION = timedelta(days=1)
WEBHOOK_RETENTION = timedelta(days=30)


async def purge_outbox(session: AsyncSession, *, now: datetime | None = None) -> dict[str, int]:
    now = now or datetime.now(UTC)
    finished = func.coalesce(OutboxJob.finished_at, OutboxJob.created_at)
    derived = await session.execute(
        delete(OutboxJob).where(
            OutboxJob.consumer.not_in(AT_LEAST_ONCE),
            OutboxJob.status.in_(("done", "merged")),
            finished < now - DERIVED_RETENTION,
        )
    )
    webhook = await session.execute(
        delete(OutboxJob).where(
            and_(
                OutboxJob.consumer.in_(AT_LEAST_ONCE),
                OutboxJob.status == "done",
                finished < now - WEBHOOK_RETENTION,
            )
        )
    )
    return {
        "derived": derived.rowcount or 0,  # type: ignore[attr-defined]
        "webhook": webhook.rowcount or 0,  # type: ignore[attr-defined]
    }


async def failed_counts(session: AsyncSession, *, org_id: int | None) -> list[tuple[str, int]]:
    """Dead-lettered job counts per consumer; ``org_id=None`` counts every org."""
    stmt = (
        select(OutboxJob.consumer, func.count())
        .where(OutboxJob.status == "failed")
        .group_by(OutboxJob.consumer)
        .order_by(OutboxJob.consumer)
    )
    if org_id is not None:
        stmt = stmt.where(OutboxJob.organization_id == org_id)
    return [(c, n) for c, n in (await session.execute(stmt)).all()]


async def requeue_failed(session: AsyncSession, *, consumer: str, org_id: int | None) -> int:
    """Put a consumer's failed jobs back on the queue; returns how many.

    The explicit ``org_id`` filter is the guard (RLS is only the backstop);
    ``None`` is the unscoped platform admin and requeues every organization's.
    The prior error is merged into ``result``; the rest of ``result`` is kept.
    """
    stmt = (
        update(OutboxJob)
        .where(OutboxJob.consumer == consumer, OutboxJob.status == "failed")
        .values(
            status="pending",
            attempts=0,
            next_attempt_at=func.now(),
            claimed_at=None,
            claimed_by=None,
            finished_at=None,
            # Merged, never replaced: a webhook job's ``webhook_id`` lives in
            # ``result``, and without it the delivery reads as "webhook deleted".
            result=func.coalesce(OutboxJob.result, text("'{}'::jsonb")).op("||")(
                func.jsonb_build_object("requeued_from_error", OutboxJob.last_error)
            ),
            last_error=None,
        )
    )
    if org_id is not None:
        stmt = stmt.where(OutboxJob.organization_id == org_id)
    return (await session.execute(stmt)).rowcount or 0  # type: ignore[attr-defined]
