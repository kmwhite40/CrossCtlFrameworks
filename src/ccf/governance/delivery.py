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

import httpx

from ..config import get_settings
from ..models import Notification

_RANK = {"info": 0, "warning": 1, "critical": 2}

TIMEOUT_SECONDS = 10.0


def render(notification: Notification) -> str | None:
    """The message to post for ``notification``, or ``None`` when policy sends nothing.

    Nothing is sent without a configured URL, or below the minimum severity
    (an unknown threshold counts as ``critical``, an unknown severity as
    ``info``).
    """
    s = get_settings()
    if not s.notify_webhook_url:
        return None
    threshold = _RANK.get(s.notify_min_severity, 2)
    if _RANK.get(notification.severity, 0) < threshold:
        return None
    text = f"[{notification.severity.upper()}] {notification.title}"
    if notification.body:
        text += f"\n{notification.body}"
    return text


def target() -> str | None:
    """The configured outbound URL, read at send time."""
    return get_settings().notify_webhook_url or None


async def send(url: str, text: str) -> int:
    """Post ``text`` to ``url``; returns the HTTP status. A transport error propagates."""
    async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS) as client:
        resp = await client.post(url, json={"text": text})
    return resp.status_code
