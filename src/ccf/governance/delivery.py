"""Outbound notification delivery — fan critical alerts out of the app.

Posts to a configured Slack/Teams incoming webhook (``CCF_NOTIFY_WEBHOOK_URL``)
when a notification meets the minimum severity (``CCF_NOTIFY_MIN_SEVERITY``).

Nothing here is called during a request. :func:`ccf.governance.bus.notify`
renders the message with :func:`render` and queues it in the outbox in the
caller's transaction; the ``notify_delivery`` consumer
(:mod:`ccf.events.notify_delivery`) posts it with :func:`send` after commit, so
an alert raised by a change that rolls back is never announced.
"""

from __future__ import annotations

import asyncio

import httpx

from ..config import get_settings
from ..models import Notification
from . import webhook_url

_RANK = {"info": 0, "warning": 1, "critical": 2}

TIMEOUT_SECONDS = 10.0


def format_text(notification: Notification) -> str:
    """The message line(s) for ``notification``, whatever the destination."""
    text = f"[{notification.severity.upper()}] {notification.title}"
    if notification.body:
        text += f"\n{notification.body}"
    return text


def meets(severity: str, threshold: str) -> bool:
    """Whether ``severity`` is at or above ``threshold``.

    An unknown threshold counts as ``critical``, an unknown severity as
    ``info``: a typo sends less, never more."""
    return _RANK.get(severity, 0) >= _RANK.get(threshold, 2)


def render(notification: Notification) -> str | None:
    """The ops-destination message for ``notification``, or ``None`` when policy sends nothing.

    Nothing is sent without a configured URL, or below the minimum severity
    (an unknown threshold counts as ``critical``, an unknown severity as
    ``info``).
    """
    s = get_settings()
    if not s.notify_webhook_url:
        return None
    if not meets(notification.severity, s.notify_min_severity):
        return None
    return format_text(notification)


def target() -> str | None:
    """The configured outbound URL, read at send time."""
    return get_settings().notify_webhook_url or None


async def send(url: str, text: str) -> int:
    """Post ``text`` to ``url``; returns the HTTP status. A transport error propagates."""
    async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS) as client:
        resp = await client.post(url, json={"text": text})
    return resp.status_code


async def send_pinned(url: str, text: str) -> tuple[str | None, int | None]:
    """Post ``text`` to a URL a tenant chose: ``(refusal, status)``.

    Through :func:`ccf.governance.webhook_url.pinned_target` -- resolved once,
    every address checked, sent to the checked address with the name in the
    ``Host`` header and as the TLS SNI name -- and never following a redirect.
    A refusal (the SSRF guard said no) sends nothing. A transport error
    propagates; callers must not put its text anywhere without scrubbing, as
    the request URL is the secret."""
    try:
        reason, req = await asyncio.to_thread(webhook_url.pinned_target, url)
    except Exception as e:  # a malformed stored URL is refused, never raised
        reason, req = f"unusable URL: {type(e).__name__}", {}
    if reason is not None:
        return reason, None
    async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS, follow_redirects=False) as client:
        resp = await client.post(
            req["url"],
            json={"text": text},
            headers=req["headers"],
            extensions=req["extensions"],
        )
    return None, resp.status_code
