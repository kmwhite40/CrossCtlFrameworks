"""Test teardown's one way past the portal log's six-month retention.

Migration 0109's trigger refuses to delete a portal audit event younger than
six months (FedRAMP CDS-TRC-ACL), so hard-deleting an organization with recent
portal activity is refused -- the cascade would erase it. Production never
hard-deletes an organization (soft delete, DATA-04); test teardown does.

This suspends the trigger for the rest of the caller's transaction only (ALTER
TABLE is transactional, and it needs the table owner, which ``ccf_app`` is
not). Use it in teardown and nowhere else; a test of the retention itself must
not.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

_TABLE = "ccf.external_portal_audit_events"
_TRIGGER = "portal_audit_append_only"


@asynccontextmanager
async def portal_log_retention_suspended(session: AsyncSession) -> AsyncIterator[None]:
    await session.execute(text(f"ALTER TABLE {_TABLE} DISABLE TRIGGER {_TRIGGER}"))
    yield
    # Only on success. On failure the transaction is aborted, the rollback
    # restores the trigger, and an ENABLE here would fail and hide the real error.
    await session.execute(text(f"ALTER TABLE {_TABLE} ENABLE TRIGGER {_TRIGGER}"))
