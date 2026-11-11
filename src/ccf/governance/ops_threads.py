"""One Slack thread per organization in the operator's ops channel.

``ops_notify_threads`` is platform-only (migration 0120), so every read and
write here runs on its own unscoped session, never the job's tenant session.

Two first alerts for one organization, drained by two workers at once, must
open ONE thread. :func:`thread_for` takes a transaction-scoped advisory lock on
the organization before it looks: the second waits until the first's
transaction commits, then finds the row the first wrote. The lock is held until
that transaction commits, i.e. across the parent post only.
"""

from __future__ import annotations

from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session_factory, set_session_tenant
from ..models import OpsNotifyThread
from . import slack

#: ``pg_advisory_xact_lock(int, int)``: this namespace, then the organization id.
_LOCK = "SELECT pg_advisory_xact_lock(hashtext('ccf.ops_notify_thread'), :org)"


class ThreadOpenError(Exception):
    """Slack refused the thread parent. Carries the reply (never the token)."""

    def __init__(self, reply: slack.SlackReply) -> None:
        super().__init__(reply.error or "no ts in Slack's answer")
        self.reply = reply


async def stored(session: AsyncSession, org_id: int, channel: str) -> str | None:
    """The thread ``ts`` for (org, channel), or ``None``. Needs an unscoped session."""
    return (
        await session.execute(
            select(OpsNotifyThread.thread_ts).where(
                OpsNotifyThread.organization_id == org_id, OpsNotifyThread.channel == channel
            )
        )
    ).scalar_one_or_none()


async def thread_for(*, org_id: int, org_name: str, channel: str, token: str) -> str:
    """The thread to reply in, opening it ("Alerts for <org>") if there is none.

    Its own unscoped session and transaction, committed before returning: the
    thread outlives the alert that opened it. Were it written in the job's
    transaction, a reply that failed and retried would roll the row back and
    the retry would open a second parent for the same organization.

    Raises :class:`ThreadOpenError` if Slack refuses the parent; nothing is
    stored then."""
    async with get_session_factory()() as session:
        await set_session_tenant(session, None)
        await session.execute(text(_LOCK), {"org": org_id})
        found = await stored(session, org_id, channel)
        if found is not None:
            await session.commit()
            return found
        reply = await slack.post_message(token, channel, f"Alerts for {slack.escape(org_name)}")
        if not reply.ok or not reply.ts:
            await session.rollback()
            raise ThreadOpenError(reply)
        session.add(OpsNotifyThread(organization_id=org_id, channel=channel, thread_ts=reply.ts))
        await session.commit()
        return reply.ts


async def forget(*, org_id: int, channel: str, thread_ts: str) -> None:
    """Drop a thread whose parent is gone, so the next alert opens a new one.

    Matched on the ``ts`` too: a row another worker has already replaced is
    left alone. Its own unscoped session, under the same lock."""
    async with get_session_factory()() as session:
        await set_session_tenant(session, None)
        await session.execute(text(_LOCK), {"org": org_id})
        await session.execute(
            delete(OpsNotifyThread).where(
                OpsNotifyThread.organization_id == org_id,
                OpsNotifyThread.channel == channel,
                OpsNotifyThread.thread_ts == thread_ts,
            )
        )
        await session.commit()
