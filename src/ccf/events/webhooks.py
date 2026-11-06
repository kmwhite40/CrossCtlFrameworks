"""The ``webhook`` consumer: one signed, SSRF-pinned delivery of one event.

:func:`ccf.events.outbox.enqueue` picks the subscribed webhooks and files one
job per webhook (``scope_key = event:N``, ``result = {"webhook_id": N}``), so
this consumer ``matches`` nothing and has no scope: it is never routed through
the consumer loop, only claimed by the worker.

Delivery is what the inline dispatcher did, plus identity: an
``X-CCF-Event-Id`` header and ``event_id`` / ``occurred_at`` body fields, so a
receiver can de-duplicate a retried delivery. The target is re-resolved and
checked at every send and the request goes to the address that was checked,
with redirects off (a redirect would be a second, unchecked target).

Outcomes: a non-2xx or a transport error raises :class:`DeliveryError`, which
the worker retries with backoff; a target that is now refused is final (retrying
cannot make it public); a deleted or deactivated webhook is a skip.
Every attempt is appended to ``result["attempts_log"]``; a failure carries the
log on the exception so the worker keeps it across the rolled-back savepoint.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import set_session_tenant
from ..governance import webhook_url
from ..logging import get_logger
from ..models import Event, Webhook
from ..models_outbox import OutboxJob
from .consumers import Consumer, register
from .outbox import WEBHOOK_CONSUMER

log = get_logger(__name__)

TIMEOUT_SECONDS = 10.0
_MAX_LOG = 50


class DeliveryError(Exception):
    """A delivery attempt that should be retried. ``result`` is what the worker
    should keep on the job (it carries the attempts log)."""

    def __init__(self, message: str, result: dict[str, Any]) -> None:
        super().__init__(message)
        self.result = result


def _body(ev: Event) -> bytes:
    occurred = ev.created_at
    return json.dumps(
        {
            "verb": ev.verb,
            "entity_type": ev.entity_type,
            "entity_id": ev.entity_id,
            "summary": ev.summary,
            "payload": ev.payload,
            "event_id": ev.id,
            "occurred_at": occurred.isoformat() if occurred is not None else None,
        }
    ).encode()


async def send(hook: Any, ev: Event) -> tuple[str | None, int | None]:
    """Post ``ev`` to ``hook``. Returns ``(refusal, status)``.

    ``refusal`` is set (and nothing is sent) when the target is refused now;
    otherwise ``status`` is the HTTP status. A transport error propagates.
    """
    body = _body(ev)
    headers = {"Content-Type": "application/json", "X-CCF-Event-Id": str(ev.id)}
    if hook.secret:
        sig = hmac.new(hook.secret.encode(), body, hashlib.sha256).hexdigest()
        headers["X-CCF-Signature"] = f"sha256={sig}"
    # Re-resolved at every send: a name that now points inward is not followed
    # even if it was public when the webhook was created.
    try:
        reason, target = await asyncio.to_thread(webhook_url.pinned_target, hook.url)
    except Exception as e:  # a malformed stored URL is refused, never raised
        reason, target = f"unusable URL: {type(e).__name__}", {}
    if reason is not None:
        return reason, None
    # Sent to the address that was checked, never re-resolved.
    async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS, follow_redirects=False) as client:
        resp = await client.post(
            target["url"],
            content=body,
            headers={**headers, **target["headers"]},
            extensions=target["extensions"],
        )
    return None, resp.status_code


def _precheck(job: OutboxJob, hook: Webhook | None, ev: Event | None) -> dict[str, Any] | None:
    """A skip or a final refusal, or ``None`` when the delivery may proceed."""
    if hook is None:
        return {"skipped": "webhook deleted"}
    if not hook.active:
        return {"skipped": "webhook deactivated"}
    if ev is None:
        return {"skipped": "event gone"}
    # A job names its webhook and event by id in a JSON blob and a column: never
    # deliver across organizations because those disagree with the job's own.
    if ev.organization_id is not None and ev.organization_id != job.organization_id:
        return {"refused": "event belongs to another organization"}
    if hook.organization_id is not None and hook.organization_id != job.organization_id:
        return {"refused": "webhook belongs to another organization"}
    return None


async def run(session: AsyncSession, scope_key: str, job: OutboxJob) -> dict[str, Any]:
    prior = dict(job.result or {})
    hook_id = prior.get("webhook_id")
    # Both rows are read by primary key on an unscoped session, then the tenant
    # is restored: a global webhook (NULL organization) and an org-less event are
    # invisible to a tenant session under RLS, yet both are legitimately
    # delivered. The organizations are cross-checked below instead.
    await set_session_tenant(session, None)
    try:
        hook = await session.get(Webhook, hook_id) if isinstance(hook_id, int) else None
        ev = await session.get(Event, job.trigger_event_id)
    finally:
        if job.organization_id is not None:
            await set_session_tenant(session, job.organization_id)
    if (early := _precheck(job, hook, ev)) is not None:
        return early
    assert hook is not None and ev is not None

    log_: list[dict[str, Any]] = list(prior.get("attempts_log") or [])
    started = time.monotonic()
    status: int | None = None
    error: str | None = None
    try:
        refusal, status = await send(hook, ev)
    except Exception as e:
        error = f"{type(e).__name__}: {str(e)[:200]}"
        refusal = None
    ms = int((time.monotonic() - started) * 1000)

    if refusal is not None:
        log.warning("webhook.target_refused", webhook_id=hook.id, reason=refusal)
        return {"refused": refusal}
    if error is None and not (status is not None and 200 <= status < 300):
        error = f"HTTP {status}"
    log_.append({"at": datetime.now(UTC).isoformat(), "status": status, "ms": ms, "error": error})
    log_ = log_[-_MAX_LOG:]
    if error is not None:
        log.warning("webhook.dispatch_failed", webhook_id=hook.id, error=error)
        raise DeliveryError(error, {**prior, "attempts_log": log_})
    return {"status_code": status, "attempts_log": log_}


register(
    Consumer(
        name=WEBHOOK_CONSUMER,
        matches=lambda entity_type, verb: False,
        scope=lambda ev: None,
        run=run,
        settle_seconds=0,
        max_attempts=8,
    )
)
