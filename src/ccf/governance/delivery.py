"""Outbound notification delivery — fan critical alerts out of the app.

The operator's ops channel receives every notification that meets the
minimum severity (``CCF_NOTIFY_MIN_SEVERITY``), in one of two modes
(:func:`ops_mode`): Slack threads, one per organization, when both
``CCF_NOTIFY_SLACK_BOT_TOKEN`` and ``CCF_NOTIFY_SLACK_CHANNEL`` are set
(:mod:`ccf.governance.slack`); otherwise the Slack/Teams incoming webhook
``CCF_NOTIFY_WEBHOOK_URL``, each post prefixed ``[Org name]``.

Nothing here is called during a request. :func:`ccf.governance.bus.notify`
renders the message with :func:`render` and queues it in the outbox in the
caller's transaction; the ``notify_delivery`` consumer
(:mod:`ccf.events.notify_delivery`) posts it with :func:`send` after commit, so
an alert raised by a change that rolls back is never announced.
"""

from __future__ import annotations

import asyncio
import re
from typing import Literal
from urllib.parse import urlsplit

import httpx

from ..config import Settings, get_settings
from ..models import Notification
from . import slack, webhook_url

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
    if ops_mode(s) is None:
        return None
    if not meets(notification.severity, s.notify_min_severity):
        return None
    return format_text(notification)


def target() -> str | None:
    """The configured outbound URL, read at send time."""
    return get_settings().notify_webhook_url or None


def slack_settings(settings: Settings | None = None) -> tuple[str, str] | None:
    """``(bot token, channel)`` when BOTH are set, read at send time; else ``None``."""
    s = settings or get_settings()
    token = s.notify_slack_bot_token.get_secret_value() if s.notify_slack_bot_token else ""
    channel = (s.notify_slack_channel or "").strip()
    return (token, channel) if token.strip() and channel else None


def ops_mode(settings: Settings | None = None) -> Literal["slack", "webhook"] | None:
    """Where ops posts go: Slack threads if both Slack settings are set, else
    the webhook URL if it is set, else nowhere."""
    s = settings or get_settings()
    if slack_settings(s) is not None:
        return "slack"
    return "webhook" if s.notify_webhook_url else None


def config_warnings(settings: Settings | None = None) -> list[str]:
    """Half-configured Slack threads: one of the two settings without the other.

    Not refused -- the webhook URL (if any) keeps working -- but said at
    startup, because the operator meant to turn threads on and has not."""
    s = settings or get_settings()
    has_token = bool(s.notify_slack_bot_token and s.notify_slack_bot_token.get_secret_value())
    has_channel = bool((s.notify_slack_channel or "").strip())
    if has_token == has_channel:
        return []
    missing = "CCF_NOTIFY_SLACK_CHANNEL" if has_token else "CCF_NOTIFY_SLACK_BOT_TOKEN"
    fallback = (
        "ops alerts go to CCF_NOTIFY_WEBHOOK_URL instead"
        if s.notify_webhook_url
        else "no ops alerts are sent at all"
    )
    return [f"Slack ops threads need {missing} as well; until it is set, {fallback}"]


# ── escaping for the destination ─────────────────────────────────────────────
#
# Alert titles and bodies, and organization names, come from data (a scan, a
# connector, a tenant). Posted raw, ``<!channel>`` pages a whole Slack channel,
# ``<https://evil|click>`` is a disguised link, and on Teams ``[x](https://evil)``
# or ``![](https://evil/b.png)`` is a link or a remote image. So every outbound
# text is escaped for where it is going, decided at send time from the URL:
#
# * **slack** -- the bot API, or an incoming webhook on ``hooks.slack.com``
#   (or GovSlack's ``hooks.slack-gov.com``): exactly ``&`` ``<`` ``>``, as
#   Slack's own docs prescribe (:func:`ccf.governance.slack.escape`). That is
#   all Slack's mrkdwn needs: mentions, links and specials all start with
#   ``<``; ``*bold*``-style formatting cannot link or ping.
# * **markdown** -- any other webhook (Teams, generic): a backslash before each
#   of :data:`MARKDOWN_SPECIALS`. That set is CommonMark's ASCII punctuation
#   that opens or shapes markup -- emphasis, code, links and images, headings,
#   lists, tables, block quotes, HTML -- and the backslash itself. A
#   backslash-escaped ASCII punctuation character renders as itself, so
#   ``\[CRITICAL\]`` still reads ``[CRITICAL]``.

Flavour = Literal["slack", "markdown"]

#: Incoming-webhook hosts that render Slack mrkdwn rather than Markdown.
SLACK_WEBHOOK_HOSTS = frozenset({"hooks.slack.com", "hooks.slack-gov.com"})

#: Backslash-escaped for a markdown destination. escape() makes one pass over
#: its input, so the backslashes it inserts are never escaped again.
MARKDOWN_SPECIALS = frozenset("\\`*_{}[]()#+-.!|<>~")


def flavour_for(url: str | None) -> Flavour:
    """``slack`` for the Slack bot API (``url=None``) or a Slack webhook host."""
    if url is None:
        return "slack"
    try:
        host = (urlsplit(url.strip()).hostname or "").rstrip(".").lower()
    except ValueError:
        host = ""
    return "slack" if host in SLACK_WEBHOOK_HOSTS else "markdown"


#: Plain-text mass mentions on the markdown path: Mattermost, Rocket.Chat and
#: Discord ping a whole channel for these, and no Markdown escape stops it. An
#: ``@`` not preceded by a word character or dot (so ``user@all.example`` is an
#: address, left alone), before one of the four words and a word boundary.
_MASS_MENTION = re.compile(r"(?<![\w.])@(?=(?:channel|here|all|everyone)\b)", re.IGNORECASE)

#: FULLWIDTH COMMERCIAL AT: reads as ``@``, is no platform's mention sigil.
_SAFE_AT = "\uff20"


def escape(text: str, flavour: Flavour) -> str:
    """``text`` made inert for ``flavour`` (see the comment above).

    Slack needs nothing for ``@channel``: in its message syntax a mention is
    ``<!channel>``, and ``<`` is escaped. On the markdown path the four mass
    mentions get a full-width ``@``; any other ``@`` (an address, ``@alice``)
    is left as it is."""
    if flavour == "slack":
        return slack.escape(text)
    text = _MASS_MENTION.sub(_SAFE_AT, text)
    return "".join(f"\\{ch}" if ch in MARKDOWN_SPECIALS else ch for ch in text)


def tag(org_name: str | None, flavour: Flavour = "slack") -> str:
    """``[Org name]`` (``[Platform]`` for an org-less alert), the name escaped.

    The brackets are Concord's and stay literal; a name alone in brackets,
    followed by a space, is neither a Slack nor a Markdown link."""
    return f"[{escape(org_name or 'Platform', flavour)}]"


#: Longest text posted, escapes and tag included. Slack refuses a long message
#: (``msg_too_long``, final: it would dead-letter the alert) and Teams cards
#: have their own limits; 3,000 characters is well inside both.
MAX_TEXT_CHARS = 3000
TRUNCATED = "\u2026 (truncated)"


def _cut(text: str, flavour: Flavour, room: int) -> str:
    """The longest prefix of ``text`` whose escaped form fits ``room``, escaped.

    Cut on the raw text, character by character, so an escape (``&amp;``,
    ``\\[``) is never split."""
    out: list[str] = []
    used = 0
    for ch in text:
        piece = escape(ch, flavour)
        if used + len(piece) > room:
            break
        out.append(piece)
        used += len(piece)
    return "".join(out)


def outbound(text: str, flavour: Flavour, *, tagged: str | None = None) -> str:
    """The text as posted: escaped for ``flavour``, after the ``tagged`` org's tag
    when one is given (``tagged=""`` tags it ``[Platform]``), and never longer
    than :data:`MAX_TEXT_CHARS` -- a longer one ends "… (truncated)"."""
    prefix = "" if tagged is None else f"{tag(tagged or None, flavour)} "
    body = escape(text, flavour)
    if len(prefix) + len(body) <= MAX_TEXT_CHARS:
        return prefix + body
    suffix = escape(TRUNCATED, flavour)
    room = max(0, MAX_TEXT_CHARS - len(prefix) - len(suffix))
    # The tag is at most an escaped 255-character name, so prefix and suffix
    # always leave room.
    return prefix + _cut(text, flavour, room) + suffix


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
