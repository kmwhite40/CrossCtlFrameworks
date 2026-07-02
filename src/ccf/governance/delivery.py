"""Outbound notification delivery — fan critical alerts out of the app.

Posts to a configured Slack/Teams incoming webhook (``CCF_NOTIFY_WEBHOOK_URL``)
when a notification meets the minimum severity. Best-effort: never raises, so a
delivery failure can't break the request that raised the alert.
"""

from __future__ import annotations

import httpx

from ..config import get_settings
from ..logging import get_logger
from ..models import Notification

log = get_logger(__name__)

_RANK = {"info": 0, "warning": 1, "critical": 2}


async def deliver(notification: Notification) -> bool:
    """Send a notification to the outbound webhook if configured + severe enough."""
    s = get_settings()
    url = s.notify_webhook_url
    if not url:
        return False
    threshold = _RANK.get(s.notify_min_severity, 2)
    if _RANK.get(notification.severity, 0) < threshold:
        return False
    text = f"[{notification.severity.upper()}] {notification.title}"
    if notification.body:
        text += f"\n{notification.body}"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(url, json={"text": text})
        return True
    except Exception as e:
        log.warning("delivery.failed", error=str(e)[:200])
        return False
