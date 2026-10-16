"""Remove digest alerts stored with no organization; the digest now raises them per org.

Revision ID: 0097_orgless_digest_alerts
Revises: 0096_notification_reads
Create Date: 2026-10-15

The scheduler ran ``digest.run`` unscoped, so every overdue-task, ATO,
POA&M, review and personnel alert was stored with ``organization_id`` NULL --
invisible to every member (RLS hides NULL-org rows from a tenant session, and
the inbox filters on the member's organization). The digest now runs per
organization under that organization's tenant.

Those orphaned rows must go, not merely stay hidden: ``dedupe_key`` is
globally unique, and a tenant-bound session cannot see a NULL-org row with
the same key, so the per-org digest would try to insert it and fail on the
unique constraint every cycle. Only rows the digest itself wrote are deleted
(matched on its dedupe-key prefixes, NULL organization); catalog-drift
alerts are platform-level and stay. Every one is a recomputation of current
state, so the next digest run raises whatever still applies -- now visible.

Not reversible: the deleted rows were unreachable by any member.
"""

from __future__ import annotations

from alembic import op

revision = "0097_orgless_digest_alerts"
down_revision = "0096_notification_reads"
branch_labels = None
depends_on = None

#: ``ccf.governance.digest`` dedupe-key prefixes for organization alerts.
_DIGEST_PREFIXES = (
    "task-overdue:",
    "training-overdue:",
    "screening-gap:",
    "access-review-overdue:",
    "questionnaire-overdue:",
    "ato:",
    "poam-overdue:",
    "policy-review:",
    "vendor-review:",
    "risk-review:",
    "regulatory-due:",
    "audit-overdue:",
)


def upgrade() -> None:
    likes = " OR ".join(f"dedupe_key LIKE '{p}%'" for p in _DIGEST_PREFIXES)
    op.execute(f"DELETE FROM ccf.notifications WHERE organization_id IS NULL AND ({likes})")


def downgrade() -> None:
    # Nothing to restore: the rows were unreachable, and the old unscoped
    # digest would re-create them on its next run after a code downgrade.
    pass
