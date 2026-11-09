"""Queue an event's derived work in the emitting transaction (the outbox).

:func:`enqueue` runs inside :func:`ccf.governance.bus.emit`, in the caller's
session and transaction, so a rolled-back change queues nothing and nothing
leaves the database before commit. It inserts one ``outbox_jobs`` row per
matching registered consumer, plus one ``webhook`` job per subscribed active
webhook. A worker claims and runs them.

Chained events (spec 6.3a): while a consumer runs, the worker sets
:data:`CURRENT_CONSUMER` and :data:`CURRENT_DEPTH`. An event emitted then reaches
no webhook (unless emitted ``external=True``, ruling R20), never re-triggers
the consumer that emitted it, and at depth :data:`MAX_DEPTH` or more queues
nothing at all.
"""

from __future__ import annotations

from contextvars import ContextVar
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..logging import get_logger
from ..models import Event, Notification, Webhook
from ..models_outbox import OutboxJob
from . import consumers

#: The consumer whose ``run`` is executing (set by the worker); None in a request.
CURRENT_CONSUMER: ContextVar[str | None] = ContextVar("CURRENT_CONSUMER", default=None)
#: The depth an event emitted now would have: the trigger event's ``_depth`` + 1.
CURRENT_DEPTH: ContextVar[int] = ContextVar("CURRENT_DEPTH", default=0)

#: An event at this depth or deeper queues nothing.
MAX_DEPTH = 3

log = get_logger(__name__)

WEBHOOK_CONSUMER = "webhook"
WEBHOOK_MAX_ATTEMPTS = 8
#: Slack/Teams delivery of one notification (:mod:`ccf.events.notify_delivery`).
NOTIFY_CONSUMER = "notify_delivery"
#: Deliveries out of the app: each job is its own message, so the worker never
#: merges them, and they retry on the webhook schedule (8 attempts, ~6 h).
AT_LEAST_ONCE = frozenset({WEBHOOK_CONSUMER, NOTIFY_CONSUMER})


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


def _log_failure(msg: str, ev: Event, e: Exception, **kw: Any) -> None:
    log.warning(msg, event_id=ev.id, error=f"{type(e).__name__}: {str(e)[:200]}", **kw)


async def _consumer_job(
    session: AsyncSession, c: consumers.Consumer, ev: Event
) -> OutboxJob | None:
    if not c.matches(ev.entity_type, ev.verb):
        return None
    key = c.scope(ev)
    if key is None:
        return None
    org_id = ev.organization_id
    if org_id is None:
        # Its own savepoint: a failed read must not leave the caller's
        # transaction aborted when this consumer is skipped.
        async with session.begin_nested():
            resolved = await consumers.scope_org(session, key)
        org_id = resolved if isinstance(resolved, int) else None
    return OutboxJob(
        organization_id=org_id,
        consumer=c.name,
        scope_key=key,
        trigger_event_id=ev.id,
        max_attempts=c.max_attempts,
        next_attempt_at=func.now() + timedelta(seconds=c.settle_seconds),
    )


def _webhook_job(ev: Event, hook: Webhook) -> OutboxJob:
    return OutboxJob(
        organization_id=(
            ev.organization_id if ev.organization_id is not None else hook.organization_id
        ),
        consumer=WEBHOOK_CONSUMER,
        scope_key=f"event:{ev.id}",
        trigger_event_id=ev.id,
        max_attempts=WEBHOOK_MAX_ATTEMPTS,
        next_attempt_at=func.now(),
        result={"webhook_id": hook.id},
    )


async def enqueue(
    session: AsyncSession, ev: Event, *, dispatch: bool, external: bool = False
) -> list[OutboxJob]:
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
        if not external:
            dispatch = False  # a derived recompute produces no webhook noise

    jobs: list[OutboxJob] = []
    for c in consumers.REGISTRY.values():
        if c.name == emitter:
            continue
        # One consumer's bug costs that consumer's job, never the request: emit
        # runs at ~56 call sites, none of which can afford a derived view's
        # exception. Logged, never skipped silently.
        try:
            job = await _consumer_job(session, c, ev)
        except Exception as e:
            _log_failure("event_outbox.consumer_scope_failed", ev, e, consumer=c.name)
            continue
        if job is not None:
            jobs.append(job)

    if dispatch:
        try:
            async with session.begin_nested():  # a SQL error must not abort the caller
                hooks = await _subscribed_webhooks(session, ev)
        except Exception as e:
            _log_failure("event_outbox.webhook_select_failed", ev, e, consumer=WEBHOOK_CONSUMER)
            hooks = []
        for hook in hooks:
            try:
                jobs.append(_webhook_job(ev, hook))
            except Exception as e:
                _log_failure(
                    "event_outbox.webhook_job_failed",
                    ev,
                    e,
                    consumer=WEBHOOK_CONSUMER,
                    webhook_id=getattr(hook, "id", None),
                )

    if jobs:
        session.add_all(jobs)
        await session.flush()
    return jobs


async def enqueue_notification(session: AsyncSession, n: Notification, text: str) -> None:
    """Queue the outbound post of ``n`` in the caller's transaction.

    ``text`` is the message as rendered now (:func:`ccf.governance.delivery.render`),
    so a later refresh of the row cannot change what this raising said. The job
    is keyed ``notification:N`` and runs under the notification's organization;
    an org-less notification's job is platform-only, as an org-less event's
    delivery to a global webhook is. It has no trigger event.

    Its own savepoint: a failed insert costs this one post, never the caller's
    transaction (the digest raises an org's alerts in one step).
    """
    try:
        async with session.begin_nested():
            session.add(
                OutboxJob(
                    organization_id=n.organization_id,
                    consumer=NOTIFY_CONSUMER,
                    scope_key=f"notification:{n.id}",
                    trigger_event_id=None,
                    max_attempts=WEBHOOK_MAX_ATTEMPTS,
                    next_attempt_at=func.now(),
                    result={"text": text},
                )
            )
            await session.flush()
    except Exception as e:
        log.warning(
            "event_outbox.notify_job_failed",
            notification_id=n.id,
            error=f"{type(e).__name__}: {str(e)[:200]}",
        )
