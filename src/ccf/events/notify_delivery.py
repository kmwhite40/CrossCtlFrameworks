"""The ``notify_delivery`` consumer: one Slack/Teams post of one notification.

:func:`ccf.governance.bus.notify` queues the job in the caller's transaction
(:func:`ccf.events.outbox.enqueue_notification`), with the message already
rendered under the delivery policy (:func:`ccf.governance.delivery.render`).
So nothing is posted before commit, and a rolled-back alert is never posted.

Like the ``webhook`` consumer it ``matches`` no event, its jobs never merge,
and it retries on the webhook schedule (8 attempts, backoff from 170 s): a 5xx,
408, 429 or transport error raises :class:`~ccf.events.webhooks.DeliveryError`
with the attempts log. Final, dead-lettered at once: any other 4xx (the
receiver refuses the URL), and no URL configured in this process. A
notification that is gone, or that belongs to another organization than its
job, is not posted.

**Two destinations** (``result["destination"]``, spec section 5). ``"ops"`` is
the operator's ``CCF_NOTIFY_WEBHOOK_URL``, as above; a job queued before
destinations existed carries no key and is an ops job. ``"org"`` is the
notification's organization's own channel (:mod:`ccf.governance.org_channel`),
read at send time on the job's tenant: removed or disabled since queueing is
``{"skipped": ...}`` (the admin turned it off, not an outage), a URL that does
not decrypt is final. It is posted through ``webhook_url.pinned_target``. Its
URL is a secret: no error, log line or result names it, only an exception's
type. The two are separate jobs, so a failure at one never touches the other.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..ai.cipher import KmsUnavailableError
from ..db import set_session_tenant
from ..governance import delivery, ops_threads, org_channel, slack
from ..logging import get_logger
from ..models import Notification, Organization
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
    org_name: str | None = None
    try:
        n = await session.get(Notification, nid)
        if n is not None and n.organization_id is not None:
            # The ops post's tag, read now by primary key (a rename since the
            # alert was raised shows the current name).
            org_name = (
                await session.execute(
                    select(Organization.name).where(Organization.id == n.organization_id)
                )
            ).scalar_one_or_none() or f"Organization {n.organization_id}"
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
    destination = prior.get("destination", "ops")
    if destination != "ops":
        # Each destination is its own job: this one never touches the other.
        return (
            await _run_org(session, nid, job, prior, text)
            if destination == "org"
            else {"refused": f"unknown destination: {str(destination)[:32]}"}
        )
    return await _run_ops(nid, job, prior, text, org_name)


async def _run_ops(
    nid: int, job: OutboxJob, prior: dict[str, Any], text: str, org_name: str | None
) -> dict[str, Any]:
    """The operator's post: Slack threads, else the webhook URL, tagged."""
    mode = delivery.ops_mode()
    if mode is None:
        # Queued because the api had ops settings; this process has none. Never
        # a quiet "done": the alert would vanish with the health check green.
        # Dead-lettered at once (a retry cannot conjure the setting), so the
        # reliability check FAILs and names it.
        msg = (
            "neither CCF_NOTIFY_WEBHOOK_URL nor both CCF_NOTIFY_SLACK_BOT_TOKEN and "
            "CCF_NOTIFY_SLACK_CHANNEL is set in this process (they were where the "
            "alert was queued): set the notify settings identically on every service"
        )
        log.warning("notify_delivery.unconfigured", notification_id=nid)
        raise DeliveryError(msg, prior, final=True)
    if mode == "slack":
        return await _run_slack(nid, job, prior, text, org_name)

    url = delivery.target()
    assert url is not None  # ops_mode() said "webhook"
    started = time.monotonic()
    status: int | None = None
    error: str | None = None
    try:
        out = delivery.outbound(text, delivery.flavour_for(url), tagged=org_name or "")
        status = await delivery.send(url, out)
    except Exception as e:
        # The type only: an HTTP library's message can carry the request URL,
        # and an incoming webhook's URL is its credential.
        error = type(e).__name__
    return _settle(
        nid, prior, destination="ops", started=started, status=status, error=error
    )


async def _run_slack(
    nid: int, job: OutboxJob, prior: dict[str, Any], text: str, org_name: str | None
) -> dict[str, Any]:
    """The ops post as a Slack thread reply (an org-less alert at the top level)."""
    settings = delivery.slack_settings()
    assert settings is not None  # ops_mode() said "slack"
    token, channel = settings
    started = time.monotonic()
    org_id = job.organization_id
    if org_id is None:
        out = delivery.outbound(text, "slack", tagged="")
        reply = await slack.post_message(token, channel, out)
        return _slack_settle(nid, prior, started, reply, {})
    name = org_name or f"Organization {org_id}"
    # In its org's thread: the parent names the org, so no tag; escaped.
    reply_text = delivery.outbound(text, "slack")
    extra: dict[str, Any] = {}
    try:
        ts = await ops_threads.thread_for(
            org_id=org_id, org_name=name, channel=channel, token=token
        )
    except ops_threads.ThreadOpenError as e:
        return _slack_settle(nid, prior, started, e.reply, {"step": "open_thread"})
    reply = await slack.post_message(token, channel, reply_text, thread_ts=ts)
    if not reply.ok and slack.classify(reply.error, reply.http_status) == "thread_gone":
        # The parent was deleted (or can no longer take replies): drop it and
        # open a new thread, once. A second refusal is retried like any other.
        await ops_threads.forget(org_id=org_id, channel=channel, thread_ts=ts)
        extra["thread_reopened"] = True
        try:
            ts = await ops_threads.thread_for(
                org_id=org_id, org_name=name, channel=channel, token=token
            )
        except ops_threads.ThreadOpenError as e:
            return _slack_settle(nid, prior, started, e.reply, {**extra, "step": "open_thread"})
        reply = await slack.post_message(token, channel, reply_text, thread_ts=ts)
    elif reply.ok and reply.thread_ts != ts:
        # Slack accepted the reply but posted it at the top level: the parent
        # is gone and Slack said nothing. This alert is out (untagged, at the
        # top); forget the thread so the next one opens a new parent.
        await ops_threads.forget(org_id=org_id, channel=channel, thread_ts=ts)
        extra["thread_reset"] = True
    return _slack_settle(nid, prior, started, reply, extra)


def _slack_settle(
    nid: int,
    prior: dict[str, Any],
    started: float,
    reply: slack.SlackReply,
    extra: dict[str, Any],
) -> dict[str, Any]:
    """The attempts log and outcome of a Slack post. Names Slack's error code,
    never the token."""
    log_: list[dict[str, Any]] = list(prior.get("attempts_log") or [])
    ms = int((time.monotonic() - started) * 1000)
    log_.append(
        {
            "at": datetime.now(UTC).isoformat(),
            "status": reply.http_status,
            "ms": ms,
            "error": reply.error,
            "via": "slack",
        }
    )
    log_ = log_[-_MAX_LOG:]
    if reply.ok:
        return {
            "status_code": reply.http_status,
            "slack_ts": reply.ts,
            "attempts_log": log_,
            **extra,
        }
    kind = slack.classify(reply.error, reply.http_status)
    msg = f"Slack chat.postMessage: {reply.error}"
    log.warning("notify_delivery.failed", notification_id=nid, destination="ops", error=msg)
    raise DeliveryError(
        msg,
        {**prior, "attempts_log": log_, **extra},
        final=kind == "final",
        retry_after=reply.retry_after,
    )


def _settle(
    nid: int,
    prior: dict[str, Any],
    *,
    destination: str,
    started: float,
    status: int | None,
    error: str | None,
) -> dict[str, Any]:
    """The attempts log, and the outcome: a dict, or a :class:`DeliveryError`."""
    log_: list[dict[str, Any]] = list(prior.get("attempts_log") or [])
    if error is None and not (status is not None and 200 <= status < 300):
        error = f"HTTP {status}"
    # A 4xx other than 408/429 is the receiver refusing this request (a revoked
    # or mistyped URL): it will refuse every retry too, so dead-letter it once.
    final = status is not None and 400 <= status < 500 and status not in (408, 429)
    ms = int((time.monotonic() - started) * 1000)
    log_.append({"at": datetime.now(UTC).isoformat(), "status": status, "ms": ms, "error": error})
    log_ = log_[-_MAX_LOG:]
    if error is not None:
        log.warning(
            "notify_delivery.failed", notification_id=nid, destination=destination, error=error
        )
        raise DeliveryError(error, {**prior, "attempts_log": log_}, final=final)
    return {"status_code": status, "attempts_log": log_}


async def _run_org(
    session: AsyncSession, nid: int, job: OutboxJob, prior: dict[str, Any], text: str
) -> dict[str, Any]:
    """Post to the organization's own channel, read now on the job's tenant."""
    org_id = job.organization_id
    if org_id is None:
        return {"refused": "an organization-less notification has no organization channel"}
    ch = await org_channel.get(session, org_id)
    if ch is None:
        return {"skipped": "organization channel removed"}
    if not ch.enabled:
        return {"skipped": "organization channel disabled"}
    try:
        url = org_channel.cipher().decrypt(ch.encrypted_url)
    except KmsUnavailableError:
        # KMS could not answer (throttling, a network failure, ...): a retry may
        # well work, so this is not the dead letter an unreadable value is.
        log.warning("notify_delivery.kms_unavailable", notification_id=nid, org_id=org_id)
        raise DeliveryError(
            "the key service could not decrypt the organization channel URL now", prior
        ) from None
    except Exception as e:
        # A retry cannot make a ciphertext decrypt (or conjure a missing key):
        # PayloadAuthenticationError, UnknownKeyError, a malformed token.
        msg = f"the organization channel URL could not be decrypted ({type(e).__name__})"
        log.warning("notify_delivery.undecryptable", notification_id=nid, org_id=org_id)
        raise DeliveryError(msg, prior, final=True) from None

    started = time.monotonic()
    status: int | None = None
    error: str | None = None
    try:
        reason, status = await delivery.send_pinned(
            url, delivery.outbound(text, delivery.flavour_for(url))
        )
        if reason is not None:
            # The guard's reason names the host at most, never the path (the
            # secret). Retried: a name may resolve, or stop pointing inward.
            error = f"refused by the URL guard: {reason}"
    except Exception as e:
        # The type only: an HTTP library's message can carry the request URL.
        error = type(e).__name__
    return _settle(
        nid, prior, destination="org", started=started, status=status, error=error
    )


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
