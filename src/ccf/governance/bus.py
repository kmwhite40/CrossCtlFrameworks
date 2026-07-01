"""Interoperability backbone — events, notifications, and outbound webhooks.

Every module calls :func:`emit` when something happens; :func:`emit` records an
append-only :class:`Event` and fans it out to subscribed :class:`Webhook`s, so
external systems and the internal activity feed both stay in sync. :func:`notify`
raises a de-duplicated :class:`Notification` for a user or an org. This is the
"everything can communicate" layer the other engines build on.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..logging import get_logger
from ..models import Event, Notification, Webhook

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
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.post(hook.url, content=body, headers=headers)
        except Exception as e:  # best-effort — a bad webhook must not break the txn
            log.warning("webhook.dispatch_failed", url=hook.url, error=str(e)[:200])


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
    session.add(n)
    await session.flush()
    return n
