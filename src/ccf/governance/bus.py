"""Interoperability backbone — events, notifications, and outbound webhooks.

Every module calls :func:`emit` when something happens; :func:`emit` records an
append-only :class:`Event` and, in the same transaction, queues its derived work
(webhook deliveries and registered consumers) in the outbox
(:func:`ccf.events.outbox.enqueue`). Nothing is sent during the request: a
worker delivers after commit, so a rolled-back change reaches no subscriber. :func:`notify`
raises a de-duplicated :class:`Notification` for a user or an org; its Slack/Teams
post is queued the same way and sent after commit. This is the
"everything can communicate" layer the other engines build on.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..events import outbox
from ..logging import get_logger
from ..models import Event, Notification, NotificationRead
from . import delivery

log = get_logger(__name__)


async def emit(
    session: AsyncSession,
    *,
    verb: str,
    entity_type: str,
    summary: str,
    org_id: int | None = None,
    actor: str | None = None,
    entity_id: str | int | None = None,
    payload: dict[str, Any] | None = None,
    dispatch: bool = True,
    external: bool = False,
) -> Event:
    """Record an event and queue the work it triggers, in the caller's transaction.

    ``dispatch=False`` queues no webhook delivery; registered consumers still
    match. While a consumer runs (``outbox.CURRENT_CONSUMER`` set) the event is
    stamped with its chain depth (``payload["_depth"]``) for the worker, and
    reaches no webhook unless ``external=True``: a recompute's bookkeeping is
    not news, but a finding a consumer makes (KSI drift) is (ruling R20).
    """
    if outbox.CURRENT_CONSUMER.get() is not None:
        payload = {**(payload or {}), "_depth": outbox.CURRENT_DEPTH.get()}
    ev = Event(
        organization_id=org_id,
        actor=actor,
        verb=verb,
        entity_type=entity_type,
        entity_id=str(entity_id) if entity_id is not None else None,
        summary=summary[:512],
        payload=payload or {},
    )
    session.add(ev)
    await session.flush()
    await outbox.enqueue(session, ev, dispatch=dispatch, external=external)
    return ev


async def system_org(session: AsyncSession, system_id: int | None) -> int | None:
    """The organization that owns ``system_id`` (``None`` if unknown).

    An event's organization is the owning record's, never the caller's: a
    global principal (``org_id is None``) writing a tenant's record would
    otherwise emit an org-less event that no org-scoped consumer can place.
    """
    if system_id is None:
        return None
    from ..models import System  # noqa: PLC0415

    return (
        await session.execute(select(System.organization_id).where(System.id == system_id))
    ).scalar_one_or_none()


#: Higher is more severe; an update that raises severity re-surfaces an alert.
_SEVERITY_RANK = {"info": 0, "warning": 1, "critical": 2}


async def notify(
    session: AsyncSession,
    *,
    category: str,
    title: str,
    org_id: int | None = None,
    user_id: int | None = None,
    severity: str = "info",
    body: str | None = None,
    entity_type: str | None = None,
    entity_id: str | int | None = None,
    dedupe_key: str | None = None,
) -> Notification | None:
    """Create a notification, de-duplicated by ``dedupe_key`` if provided.

    Returns the (new or existing) notification, or refreshes an existing one's
    severity/title in place so a re-scan doesn't spam duplicates.
    """
    eid = str(entity_id) if entity_id is not None else None
    if dedupe_key:
        existing = (
            await session.execute(select(Notification).where(Notification.dedupe_key == dedupe_key))
        ).scalar_one_or_none()
        if existing is not None:
            escalated = _SEVERITY_RANK.get(severity, 0) > _SEVERITY_RANK.get(existing.severity, 0)
            if escalated:
                # Escalated (a warning became critical): it is news again, so
                # it comes back for everyone who had read the milder version.
                await session.execute(
                    delete(NotificationRead).where(NotificationRead.notification_id == existing.id)
                )
                existing.read_at = None
            existing.title = title[:512]
            existing.severity = severity
            existing.body = body
            if escalated:
                # News again, so it is posted (if policy sends its new severity);
                # a refresh at the same or a lower severity is not.
                await _queue_delivery(session, existing)
            return existing
    n = Notification(
        organization_id=org_id,
        user_id=user_id,
        severity=severity,
        category=category,
        title=title[:512],
        body=body,
        entity_type=entity_type,
        entity_id=eid,
        dedupe_key=dedupe_key,
    )
    try:
        # Its own savepoint: under a tenant's RLS a row with this (globally
        # unique) dedupe_key can exist yet be invisible -- another tenant's, or
        # an org-less one migration 0097 has not removed yet. The insert then
        # violates the unique index; contained here, that costs this one alert
        # instead of rolling back the caller's whole step (an org's entire
        # digest, every cycle).
        async with session.begin_nested():
            session.add(n)
            await session.flush()
    except IntegrityError:
        log.warning("notify.dedupe_key_hidden_collision", dedupe_key=dedupe_key, org_id=org_id)
        return None
    await _queue_delivery(session, n)
    return n


async def _queue_delivery(session: AsyncSession, n: Notification) -> None:
    """Queue the Slack/Teams post of ``n`` if policy sends it; posted after commit."""
    text = delivery.render(n)
    if text is not None:
        await outbox.enqueue_notification(session, n, text)
