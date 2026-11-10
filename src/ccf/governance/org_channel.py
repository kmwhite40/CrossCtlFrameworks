"""An organization's own Slack/Teams alert channel.

Set by that organization's admins (or a platform admin acting on it); one per
organization (``org_notify_channels``). The URL is a credential -- anyone who
holds it can post to the channel -- so:

* it is sealed with its own associated data (``AAD_NOTIFY_CHANNEL``), never
  the connector credential's, and opened only to send;
* nothing here returns it, logs it, or puts it in an event, an audit entry or
  an error. Only :func:`url_hint` (scheme and host, nothing from the path) is
  shown, and an error names an exception's type, never its text (an HTTP
  library's message can carry the request URL);
* every post goes through :func:`ccf.governance.delivery.send_pinned` (the SSRF
  guard, DNS pinned, no redirects).

Saving is proven: a URL is stored only after a test post to it succeeds, so a
mistyped URL is refused while the admin is still looking at the form, not
discovered by the first critical alert that silently goes nowhere.

Delivery (spec section 5): :func:`org_job_text` decides at queue time, in the
caller's transaction, whether a notification goes to its organization's channel;
``ccf.events.notify_delivery`` reads the channel again at send time.

See docs/superpowers/specs/2026-11-09-org-notify-channels-design.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import literal_column, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from ..ai.cipher import (
    AAD_NOTIFY_CHANNEL,
    CredentialCipher,
    KmsUnavailableError,
    build_cipher,
)
from ..config import get_settings
from ..logging import get_logger
from ..models import Notification, Organization, OrgNotifyChannel
from . import delivery, webhook_url

log = get_logger(__name__)

SEVERITIES = ("info", "warning", "critical")

#: Longer than any real Slack or Teams incoming-webhook URL.
MAX_URL_LENGTH = 2048

ENTITY_TYPE = "org_notify_channel"


class ChannelRefusedError(ValueError):
    """The request cannot be honoured; the message is safe to show (no URL)."""


@dataclass(frozen=True)
class ProbeResult:
    """The outcome of a test post. ``error`` never contains the URL."""

    ok: bool
    status_code: int | None
    error: str | None


def cipher() -> CredentialCipher:
    """The channel URL's cipher: its own associated data, never a connector's."""
    return build_cipher(get_settings(), aad=AAD_NOTIFY_CHANNEL)


#: ``org_notify_channels.url_hint`` is ``String(160)``.
MAX_HINT_LENGTH = 160


def url_hint(url: str) -> str:
    """What is shown instead of the URL: ``https://host``, never more.

    Nothing from the path or query: a Slack webhook's path is its token and a
    Teams webhook's query carries its ``sig``, and the hint is written for good
    into the hash-chained audit trail and into event payloads. A host too long
    for the column is cut with an ellipsis, so saving can never fail on it
    after the test post has already been sent."""
    parts = urlsplit(url.strip())
    scheme, host = parts.scheme or "?", parts.hostname or "?"
    room = MAX_HINT_LENGTH - len(f"{scheme}://")
    if len(host) > room:
        host = host[: room - 1] + "…"
    return f"{scheme}://{host}"


def refusal(url: str) -> str | None:
    """Why ``url`` may not be an alert channel, or ``None``. Never echoes it."""
    clean = url.strip()
    if not clean:
        return "a channel URL is required"
    if len(clean) > MAX_URL_LENGTH:
        return f"a channel URL is at most {MAX_URL_LENGTH} characters"
    try:
        scheme = urlsplit(clean).scheme
    except ValueError:
        return "not a valid URL"
    if scheme != "https":
        return "the channel URL must use https"
    try:
        return webhook_url.refusal(clean)
    except Exception as e:  # malformed beyond what the guard parses
        return f"not a valid URL ({type(e).__name__})"


def masked_view(ch: OrgNotifyChannel | None) -> dict[str, Any]:
    """The channel as the API and UI show it: never the URL or its ciphertext."""
    if ch is None:
        return {"configured": False}
    return {
        "configured": True,
        "organization_id": ch.organization_id,
        "url_hint": ch.url_hint,
        "min_severity": ch.min_severity,
        "enabled": ch.enabled,
        "created_by": ch.created_by,
        "created_at": ch.created_at.isoformat() if ch.created_at else None,
        "updated_by": ch.updated_by,
        "updated_at": ch.updated_at.isoformat() if ch.updated_at else None,
    }


async def get(session: AsyncSession, org_id: int) -> OrgNotifyChannel | None:
    """``org_id``'s channel. Filtered on the org explicitly: RLS is not the guard."""
    return (
        await session.execute(
            select(OrgNotifyChannel).where(OrgNotifyChannel.organization_id == org_id)
        )
    ).scalar_one_or_none()


async def _org_name(session: AsyncSession, org_id: int) -> str:
    name = (
        await session.execute(select(Organization.name).where(Organization.id == org_id))
    ).scalar_one_or_none()
    return name or f"organization {org_id}"


async def send_test(url: str, org_name: str, min_severity: str) -> ProbeResult:
    """Post a test message to ``url``. The result never contains the URL."""
    text = (
        f"Concord: this channel will receive {org_name}'s alerts at {min_severity} "
        "severity and above. (Test post.)"
    )
    try:
        reason, status = await delivery.send_pinned(url, text)
    except Exception as e:
        return ProbeResult(False, None, f"the test post could not be sent ({type(e).__name__})")
    if reason is not None:
        return ProbeResult(False, None, f"the test post was refused: {reason}")
    if status is None or not 200 <= status < 300:
        return ProbeResult(False, status, f"the receiver answered the test post with HTTP {status}")
    return ProbeResult(True, status, None)


async def _record(
    session: AsyncSession,
    ch: OrgNotifyChannel | None,
    *,
    org_id: int,
    actor: str,
    action: str,
    verb: str,
    summary: str,
    diff: dict[str, Any],
) -> None:
    """An audit entry and a settings event (no webhook): never the URL."""
    from ..api.audit import record_event  # noqa: PLC0415 -- the api imports governance
    from . import bus  # noqa: PLC0415 -- bus imports this module

    await record_event(
        session,
        actor=actor,
        action=action,
        entity_type=ENTITY_TYPE,
        entity_id=str(ch.id) if ch is not None else None,
        diff=diff,
        organization_id=org_id,
    )
    await bus.emit(
        session,
        verb=verb,
        entity_type=ENTITY_TYPE,
        entity_id=ch.id if ch is not None else None,
        summary=summary,
        org_id=org_id,
        actor=actor,
        payload=diff,
        dispatch=False,
    )


async def save(
    session: AsyncSession,
    org_id: int,
    *,
    actor: str,
    url: str | None,
    min_severity: str,
    enabled: bool,
) -> OrgNotifyChannel:
    """Create or change ``org_id``'s channel. Caller owns commit.

    A new ``url`` is checked (https, the SSRF guard) and proven by a test post
    before anything is written. ``url=None`` keeps the stored URL and changes
    only the severity and the on/off switch. Raises :class:`ChannelRefusedError`.
    """
    if min_severity not in SEVERITIES:
        raise ChannelRefusedError(f"min_severity must be one of {', '.join(SEVERITIES)}")
    existing = await get(session, org_id)
    sealed: str | None = None
    hint: str | None = None
    if url is not None and url.strip():
        clean = url.strip()
        reason = refusal(clean)
        if reason is not None:
            raise ChannelRefusedError(reason)
        # Fail before the test post: a post to a channel that then cannot be
        # stored would announce a channel that does not exist.
        sealed = cipher().encrypt(clean)
        hint = url_hint(clean)
        result = await send_test(clean, await _org_name(session, org_id), min_severity)
        if not result.ok:
            raise ChannelRefusedError(f"{result.error}; the channel was not saved")
    elif existing is None:
        raise ChannelRefusedError("a channel URL is required")

    now = datetime.now(UTC)
    created = existing is None
    if existing is None:
        assert sealed is not None and hint is not None
        # An upsert, not an add: two admins saving the first channel at once
        # both read "none" above, and the second insert would hit the unique
        # key and answer a 500. ``xmax = 0`` is true only for a fresh insert.
        stmt: Any = (
            pg_insert(OrgNotifyChannel)
            .values(
                organization_id=org_id,
                encrypted_url=sealed,
                url_hint=hint,
                min_severity=min_severity,
                enabled=enabled,
                created_by=actor,
                updated_by=actor,
            )
            .on_conflict_do_update(
                index_elements=[OrgNotifyChannel.organization_id],
                set_={
                    "encrypted_url": sealed,
                    "url_hint": hint,
                    "min_severity": min_severity,
                    "enabled": enabled,
                    "updated_by": actor,
                    "updated_at": now,
                },
            )
            .returning(OrgNotifyChannel.id, literal_column("(xmax = 0)"))
        )
        row_id, created = (await session.execute(stmt)).one()
        found = (
            await session.execute(
                select(OrgNotifyChannel)
                .where(OrgNotifyChannel.id == row_id)
                .execution_options(populate_existing=True)
            )
        ).scalar_one()
        ch = found
    else:
        ch = existing
        if sealed is not None and hint is not None:
            ch.encrypted_url = sealed
            ch.url_hint = hint
        ch.min_severity = min_severity
        ch.enabled = enabled
        ch.updated_by = actor
        ch.updated_at = now
    await session.flush()
    diff = {
        "url_hint": ch.url_hint,
        "url_changed": sealed is not None,
        "min_severity": ch.min_severity,
        "enabled": ch.enabled,
    }
    await _record(
        session,
        ch,
        org_id=org_id,
        actor=actor,
        action="notify_channel_set",
        verb="created" if created else "updated",
        summary=f"Alert channel {'set' if created else 'changed'}: {ch.url_hint}",
        diff=diff,
    )
    return ch


async def remove(session: AsyncSession, org_id: int, *, actor: str) -> bool:
    """Delete ``org_id``'s channel; False if there was none. Caller owns commit."""
    ch = await get(session, org_id)
    if ch is None:
        return False
    hint = ch.url_hint
    await _record(
        session,
        ch,
        org_id=org_id,
        actor=actor,
        action="notify_channel_remove",
        verb="deleted",
        summary=f"Alert channel removed: {hint}",
        diff={"url_hint": hint},
    )
    await session.delete(ch)
    await session.flush()
    return True


async def send_stored_test(session: AsyncSession, org_id: int) -> ProbeResult:
    """A test post to ``org_id``'s stored channel. Raises :class:`ChannelRefusedError`."""
    ch = await get(session, org_id)
    if ch is None:
        raise ChannelRefusedError("this organization has no alert channel")
    try:
        url = cipher().decrypt(ch.encrypted_url)
    except KmsUnavailableError:
        raise ChannelRefusedError(
            "the key service could not be reached to read the channel URL; try again later"
        ) from None
    except Exception as e:
        raise ChannelRefusedError(
            f"the stored channel URL could not be decrypted ({type(e).__name__}); set it again"
        ) from None
    return await send_test(url, await _org_name(session, org_id), ch.min_severity)


async def org_job_text(session: AsyncSession, n: Notification) -> str | None:
    """The message to queue for ``n``'s organization channel, or ``None``.

    ``None`` for an org-less notification, an organization without a channel,
    a disabled channel, or a severity below the channel's minimum. Looked up
    in its own savepoint: a database error here (the table absent on a
    half-migrated deploy, a lock timeout) costs this one post, never the
    caller's transaction, and never the ops post. Nothing else is swallowed:
    ``MultipleResultsFound`` means the org filter is broken, and hiding it
    would make every tenant guard test pass for the wrong reason.
    """
    if n.organization_id is None:
        return None
    try:
        async with session.begin_nested():
            ch = await get(session, n.organization_id)
    except DBAPIError as e:
        log.warning(
            "org_channel.lookup_failed",
            notification_id=n.id,
            org_id=n.organization_id,
            error=type(e).__name__,
        )
        return None
    if ch is None or not ch.enabled or not delivery.meets(n.severity, ch.min_severity):
        return None
    return delivery.format_text(n)
