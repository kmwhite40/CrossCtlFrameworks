"""Test teardown's one way past the retention triggers (portal log, snapshots).

Migration 0109's trigger refuses to delete a portal audit event younger than
six months (FedRAMP CDS-TRC-ACL), and 0111's refuse to delete a certification
snapshot at all (CDS-CSO-HAD), so hard-deleting an organization with recent
portal activity or any snapshot is refused -- the cascade would erase them. Production never
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

#: (table, row trigger) pairs whose retention a test teardown may suspend:
#: the portal access log (0109) and the certification snapshots (0111).
_TRIGGERS = (
    ("ccf.external_portal_audit_events", "portal_audit_append_only"),
    ("ccf.certification_snapshots", "certification_snapshots_append_only"),
    ("ccf.certification_snapshot_documents", "certification_snapshot_documents_append_only"),
    ("ccf.certification_snapshot_filings", "certification_snapshot_filings_append_only"),
)


@asynccontextmanager
async def portal_log_retention_suspended(session: AsyncSession) -> AsyncIterator[None]:
    for table, trigger in _TRIGGERS:
        await session.execute(text(f"ALTER TABLE {table} DISABLE TRIGGER {trigger}"))
    yield
    # Only on success. On failure the transaction is aborted, the rollback
    # restores the triggers, and an ENABLE here would fail and hide the real error.
    for table, trigger in _TRIGGERS:
        await session.execute(text(f"ALTER TABLE {table} ENABLE TRIGGER {trigger}"))
