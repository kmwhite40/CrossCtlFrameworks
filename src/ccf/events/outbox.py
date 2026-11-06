"""Queue an event's derived work in the emitting transaction (the outbox).

:func:`enqueue` runs inside :func:`ccf.governance.bus.emit`, in the caller's
session and transaction, so a rolled-back change queues nothing and nothing
leaves the database before commit. It inserts one ``outbox_jobs`` row per
matching registered consumer, plus one ``webhook`` job per subscribed active
webhook. A worker claims and runs them.

Chained events (spec 6.3a): while a consumer runs, the worker sets
:data:`CURRENT_CONSUMER` and :data:`CURRENT_DEPTH`. An event emitted then reaches
no webhook, never re-triggers the consumer that emitted it, and at depth
:data:`MAX_DEPTH` or more queues nothing at all.
"""

from __future__ import annotations

from contextvars import ContextVar
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Event, Webhook
from ..models_outbox import OutboxJob
from . import consumers

#: The consumer whose ``run`` is executing (set by the worker); None in a request.
CURRENT_CONSUMER: ContextVar[str | None] = ContextVar("CURRENT_CONSUMER", default=None)
#: The depth an event emitted now would have: the trigger event's ``_depth`` + 1.
CURRENT_DEPTH: ContextVar[int] = ContextVar("CURRENT_DEPTH", default=0)

#: An event at this depth or deeper queues nothing.
MAX_DEPTH = 3

WEBHOOK_CONSUMER = "webhook"
WEBHOOK_MAX_ATTEMPTS = 8


async def _subscribed_webhooks(session: AsyncSession, ev: Event) -> list[Webhook]:
    """Today's selection rule: active, the event's org or global, and subscribed.

    An empty subscription list means every event; otherwise the verb or the
    entity type must be listed. Run in the caller's session, so a tenant session
    sees what the tenant's RLS lets it see, as the inline dispatcher did.
    """
    stmt = select(Webhook).where(Webhook.active.is_(True))
    if ev.organization_id is not None:
        stmt = stmt.where(
            (Webhook.organization_id == ev.organization_id) | (Webhook.organization_id.is_(None))
        )
    hooks = (await session.execute(stmt.order_by(Webhook.id))).scalars().all()
    return [h for h in hooks if not h.events or ev.verb in h.events or ev.entity_type in h.events]


async def enqueue(session: AsyncSession, ev: Event, *, dispatch: bool) -> list[OutboxJob]:
    """Insert the outbox jobs ``ev`` triggers, in the caller's transaction.

    A job's organization is the event's when it has one. An org-less event's
    consumer job takes its scope's organization (``None`` if the scope is gone:
    the job is still queued, and the worker skips it). A webhook job for an
    org-less event takes the webhook's organization, so only a global webhook's
    delivery of an org-less event is platform-only.
    """
    emitter = CURRENT_CONSUMER.get()
    if emitter is not None:
        if CURRENT_DEPTH.get() >= MAX_DEPTH:
            return []
        dispatch = False  # a derived recompute produces no webhook noise

    jobs: list[OutboxJob] = []
    for c in consumers.REGISTRY.values():
        if c.name == emitter or not c.matches(ev.entity_type, ev.verb):
            continue
        key = c.scope(ev)
        if key is None:
            continue
        org_id = ev.organization_id
        if org_id is None:
            resolved = await consumers.scope_org(session, key)
            org_id = resolved if isinstance(resolved, int) else None
        jobs.append(
            OutboxJob(
                organization_id=org_id,
                consumer=c.name,
                scope_key=key,
                trigger_event_id=ev.id,
                max_attempts=c.max_attempts,
                next_attempt_at=func.now() + timedelta(seconds=c.settle_seconds),
            )
        )

    if dispatch:
        for hook in await _subscribed_webhooks(session, ev):
            org = ev.organization_id if ev.organization_id is not None else hook.organization_id
            jobs.append(
                OutboxJob(
                    organization_id=org,
                    consumer=WEBHOOK_CONSUMER,
                    scope_key=f"event:{ev.id}",
                    trigger_event_id=ev.id,
                    max_attempts=WEBHOOK_MAX_ATTEMPTS,
                    next_attempt_at=func.now(),
                    result={"webhook_id": hook.id},
                )
            )

    if jobs:
        session.add_all(jobs)
        await session.flush()
    return jobs
