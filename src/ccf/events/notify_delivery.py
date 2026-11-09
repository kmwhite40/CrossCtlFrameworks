"""The ``notify_delivery`` consumer: one Slack/Teams post of one notification.

:func:`ccf.governance.bus.notify` queues the job in the caller's transaction
(:func:`ccf.events.outbox.enqueue_notification`), with the message already
rendered under the delivery policy (:func:`ccf.governance.delivery.render`).
So nothing is posted before commit, and a rolled-back alert is never posted.

Like the ``webhook`` consumer it ``matches`` no event, its jobs never merge,
and it retries on the webhook schedule (8 attempts, backoff from 170 s): a
non-2xx or a transport error raises :class:`~ccf.events.webhooks.DeliveryError`
with the attempts log. A notification that is gone, or that belongs to another
organization than its job, is not posted.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..db import set_session_tenant
from ..governance import delivery
from ..logging import get_logger
from ..models import Notification
from ..models_outbox import OutboxJob
from .consumers import Consumer, register
from .outbox import NOTIFY_CONSUMER, WEBHOOK_MAX_ATTEMPTS
from .webhooks import DeliveryError

log = get_logger(__name__)

_MAX_LOG = 50


def notification_id(scope_key: str) -> int | None:
    kind, sep, raw = scope_key.partition(":")
    if kind != "notification" or not sep or not raw.isascii() or not raw.isdigit():
        return None
    return int(raw)


async def run(session: AsyncSession, scope_key: str, job: OutboxJob) -> dict[str, Any]:
    prior = dict(job.result or {})
    nid = notification_id(scope_key)
    if nid is None:
        return {"refused": f"not a notification scope: {scope_key}"}
    # Read by primary key on an unscoped session, then the tenant is restored:
    # an org-less notification is invisible to a tenant session. The
    # organizations are cross-checked instead.
    await set_session_tenant(session, None)
    try:
        n = await session.get(Notification, nid)
    finally:
        if job.organization_id is not None:
            await set_session_tenant(session, job.organization_id)
    if n is None:
        return {"skipped": "notification gone"}
    if n.organization_id != job.organization_id:
        return {"refused": "notification belongs to another organization"}
    text = prior.get("text")
    if not isinstance(text, str) or not text:
        return {"skipped": "nothing to send"}
    url = delivery.target()
    if url is None:
        return {"skipped": "delivery not configured"}

    log_: list[dict[str, Any]] = list(prior.get("attempts_log") or [])
    started = time.monotonic()
    status: int | None = None
    error: str | None = None
    try:
        status = await delivery.send(url, text)
    except Exception as e:
        error = f"{type(e).__name__}: {str(e)[:200]}"
    if error is None and not (status is not None and 200 <= status < 300):
        error = f"HTTP {status}"
    ms = int((time.monotonic() - started) * 1000)
    log_.append({"at": datetime.now(UTC).isoformat(), "status": status, "ms": ms, "error": error})
    log_ = log_[-_MAX_LOG:]
    if error is not None:
        log.warning("notify_delivery.failed", notification_id=nid, error=error)
        raise DeliveryError(error, {**prior, "attempts_log": log_})
    return {"status_code": status, "attempts_log": log_}


register(
    Consumer(
        name=NOTIFY_CONSUMER,
        matches=lambda entity_type, verb: False,
        scope=lambda ev: None,
        run=run,
        settle_seconds=0,
        max_attempts=WEBHOOK_MAX_ATTEMPTS,
    )
)
