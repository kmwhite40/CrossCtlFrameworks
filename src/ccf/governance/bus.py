"""Interoperability backbone — events, notifications, and outbound webhooks.

Every module calls :func:`emit` when something happens; :func:`emit` records an
append-only :class:`Event` and fans it out to subscribed :class:`Webhook`s, so
external systems and the internal activity feed both stay in sync. :func:`notify`
raises a de-duplicated :class:`Notification` for a user or an org. This is the
"everything can communicate" layer the other engines build on.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from typing import Any

import httpx
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..logging import get_logger
from ..models import Event, Notification, NotificationRead, Webhook
from . import delivery, webhook_url

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
) -> Event:
    """Record an event and (best-effort) dispatch it to subscribed webhooks."""
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
    if dispatch:
        await _dispatch_webhooks(session, ev)
    return ev


async def _dispatch_webhooks(session: AsyncSession, ev: Event) -> None:
    stmt = select(Webhook).where(Webhook.active.is_(True))
    if ev.organization_id is not None:
        stmt = stmt.where(
            (Webhook.organization_id == ev.organization_id) | (Webhook.organization_id.is_(None))
        )
    hooks = (await session.execute(stmt)).scalars().all()
    if not hooks:
        return
    body = json.dumps(
        {
            "verb": ev.verb,
            "entity_type": ev.entity_type,
            "entity_id": ev.entity_id,
            "summary": ev.summary,
            "payload": ev.payload,
        }
    ).encode()
    for hook in hooks:
        subs = hook.events or []
        if subs and ev.verb not in subs and ev.entity_type not in subs:
            continue
        headers = {"Content-Type": "application/json"}
        if hook.secret:
            sig = hmac.new(hook.secret.encode(), body, hashlib.sha256).hexdigest()
            headers["X-CCF-Signature"] = f"sha256={sig}"
        # Re-resolved at every send: a name that now points inward is not
        # followed even if it was public when the webhook was created.
        try:
            reason, target = await asyncio.to_thread(webhook_url.pinned_target, hook.url)
        except Exception as e:  # a malformed stored URL is skipped, never raised
            reason = f"unusable URL: {type(e).__name__}"
        if reason is not None:
            log.warning("webhook.target_refused", webhook_id=hook.id, reason=reason)
            continue
        try:
            # Sent to the address that was checked, never re-resolved.
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
                await client.post(
                    target["url"],
                    content=body,
                    headers={**headers, **target["headers"]},
                    extensions=target["extensions"],
                )
        except Exception as e:  # best-effort — a bad webhook must not break the txn
            log.warning("webhook.dispatch_failed", url=hook.url, error=str(e)[:200])


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
            if _SEVERITY_RANK.get(severity, 0) > _SEVERITY_RANK.get(existing.severity, 0):
                # Escalated (a warning became critical): it is news again, so
                # it comes back for everyone who had read the milder version.
                await session.execute(
                    delete(NotificationRead).where(NotificationRead.notification_id == existing.id)
                )
                existing.read_at = None
            existing.title = title[:512]
            existing.severity = severity
            existing.body = body
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
    # Best-effort outbound delivery (Slack/Teams webhook) for severe alerts.
    await delivery.deliver(n)
    return n
