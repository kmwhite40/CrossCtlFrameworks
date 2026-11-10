"""The operator's ops channel on Slack: ``chat.postMessage`` and nothing else.

Spec: docs/superpowers/specs/2026-11-09-org-notify-channels-design.md, sections
3 and 5. Only ``https://slack.com/api/chat.postMessage`` is ever called (a
constant, never configuration), with the bot token as a Bearer header, a JSON
body ``{channel, text, thread_ts?}``, and redirects off.

The token is a secret. It is sent in one header and is never logged, returned,
put in a job result, an event or an error: :class:`SlackReply` carries Slack's
error *code* only, and a transport failure is reported by exception type,
never by its text. (httpx's own request logging is held at WARNING by
``ccf.logging.configure_logging``; it does not log headers in any case.)

**Errors.** Slack answers HTTP 200 with ``{"ok": false, "error": "<code>"}``.
:func:`classify` sorts the codes listed for chat.postMessage at
https://docs.slack.dev/reference/methods/chat.postMessage (fetched 2026-11-09):

* ``retry`` -- rate limits (``ratelimited``, ``rate_limited``, HTTP 429, with
  ``Retry-After`` honoured), Slack-side faults (``internal_error``,
  ``fatal_error``, ``service_unavailable``, ``request_timeout``), 5xx, and any
  code not listed below (the spec's "others retry");
* ``final`` -- the token, its scopes, the channel or the workspace refuse this
  app, which a retry cannot change; the operator has to act;
* ``thread_gone`` -- the stored thread parent cannot take replies any more.
  The documented table names no code for a deleted or unknown ``thread_ts``;
  ``thread_not_found`` and ``invalid_thread_ts`` are what Slack has been
  reported to return, ``message_not_found`` is the spec's, and
  ``cannot_reply_to_message`` is documented. Slack may instead accept the
  reply and post it at the top level: the caller checks the reply's
  ``thread_ts`` for that (see ``ccf.events.notify_delivery``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

import httpx

SLACK_POST_MESSAGE = "https://slack.com/api/chat.postMessage"
TIMEOUT_SECONDS = 10.0

#: Retried: Slack is busy or faulted, not refusing.
RETRY_ERRORS = frozenset(
    {
        "ratelimited",
        "rate_limited",
        "message_limit_exceeded",
        "internal_error",
        "fatal_error",
        "service_unavailable",
        "request_timeout",
        "team_added_to_org",
        "org_login_required",
    }
)

#: Final: a retry cannot fix these; the operator must (token, scope, channel).
FINAL_ERRORS = frozenset(
    {
        "invalid_auth",
        "not_authed",
        "account_inactive",
        "token_revoked",
        "token_expired",
        "not_allowed_token_type",
        "missing_scope",
        "no_permission",
        "team_access_not_granted",
        "access_denied",
        "accesslimited",
        "app_access_restricted",
        "enterprise_is_restricted",
        "two_factor_setup_required",
        "team_not_found",
        "channel_not_found",
        "not_in_channel",
        "is_archived",
        "ekm_access_denied",
        "messages_tab_disabled",
        "restricted_action",
        "restricted_action_read_only_channel",
        "restricted_action_thread_locked",
        "restricted_action_non_threadable_channel",
        "restricted_action_thread_only_channel",
        "invalid_arguments",
        "invalid_arg_name",
        "invalid_charset",
        "invalid_post_type",
        "missing_post_type",
        "invalid_form_data",
        "no_text",
        "msg_too_long",
        "as_user_not_supported",
        "deprecated_endpoint",
        "method_deprecated",
    }
)

#: The thread parent is gone or cannot take replies: open a new thread once.
THREAD_GONE_ERRORS = frozenset(
    {"thread_not_found", "invalid_thread_ts", "message_not_found", "cannot_reply_to_message"}
)

_CODE = re.compile(r"[a-z0-9_]{1,64}")


@dataclass(frozen=True)
class SlackReply:
    """What Slack answered. Never holds the token."""

    ok: bool
    #: Slack's error code, ``"HTTP <n>"``, or a transport exception's type.
    error: str | None = None
    http_status: int | None = None
    ts: str | None = None
    #: The posted message's ``thread_ts`` (absent when it went to the top level).
    thread_ts: str | None = None
    retry_after: float | None = None


def classify(error: str | None, http_status: int | None = None) -> Literal[
    "retry", "final", "thread_gone"
]:
    """How to treat a failed ``chat.postMessage``."""
    if error in THREAD_GONE_ERRORS:
        return "thread_gone"
    if error in FINAL_ERRORS:
        return "final"
    if error in RETRY_ERRORS:
        return "retry"
    if http_status is not None and 400 <= http_status < 500 and http_status not in (408, 429):
        return "final"
    return "retry"


def _retry_after(resp: httpx.Response) -> float | None:
    raw = resp.headers.get("retry-after")
    if raw is None or not raw.strip().isdigit():
        return None
    return float(min(int(raw.strip()), 24 * 3600))


def _code(value: Any) -> str:
    """Slack's error code, kept only if it looks like one (it is echoed in errors)."""
    return value if isinstance(value, str) and _CODE.fullmatch(value) else "unrecognised_error"


async def post_message(
    token: str, channel: str, text: str, *, thread_ts: str | None = None
) -> SlackReply:
    """One ``chat.postMessage``. Never raises; never returns the token."""
    body: dict[str, Any] = {"channel": channel, "text": text}
    if thread_ts:
        body["thread_ts"] = thread_ts
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS, follow_redirects=False) as client:
            resp = await client.post(
                SLACK_POST_MESSAGE,
                json=body,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json; charset=utf-8",
                },
            )
    except Exception as e:
        # The type only: an exception's text could carry request details.
        return SlackReply(ok=False, error=type(e).__name__)
    return _reply(resp)


def _reply(resp: httpx.Response) -> SlackReply:
    """Slack's answer as a :class:`SlackReply`."""
    status = resp.status_code
    if status == 429:
        return SlackReply(False, "ratelimited", status, retry_after=_retry_after(resp))
    if not 200 <= status < 300:
        return SlackReply(False, f"HTTP {status}", status)
    try:
        data = resp.json()
    except ValueError:
        data = None
    if not isinstance(data, dict):
        return SlackReply(False, "invalid_response", status)
    if not data.get("ok"):
        return SlackReply(False, _code(data.get("error")), status, retry_after=_retry_after(resp))
    raw_message = data.get("message")
    message: dict[str, Any] = raw_message if isinstance(raw_message, dict) else {}
    ts = data.get("ts") if isinstance(data.get("ts"), str) else None
    thread = message.get("thread_ts") if isinstance(message.get("thread_ts"), str) else None
    return SlackReply(True, None, status, ts=ts, thread_ts=thread)


def escape(text: str) -> str:
    """Slack's three control characters, so an org name cannot ``<!channel>``."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
