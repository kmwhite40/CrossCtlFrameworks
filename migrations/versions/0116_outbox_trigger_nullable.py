"""Outbox jobs need not have a trigger event: a notification's outbound post.

Revision ID: 0116_outbox_trigger_nullable
Revises: 0115_outbox_jobs
Create Date: 2026-11-09

``ccf.governance.bus.notify`` queues its Slack/Teams post in the outbox
(consumer ``notify_delivery``) instead of posting during the request. That job
is about a notification, not an event, so ``trigger_event_id`` becomes
nullable. Grants and RLS are unchanged.
"""

from __future__ import annotations

from alembic import op

revision = "0116_outbox_trigger_nullable"
down_revision = "0115_outbox_jobs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE ccf.outbox_jobs ALTER COLUMN trigger_event_id DROP NOT NULL")


def downgrade() -> None:
    op.execute("DELETE FROM ccf.outbox_jobs WHERE trigger_event_id IS NULL")
    op.execute("ALTER TABLE ccf.outbox_jobs ALTER COLUMN trigger_event_id SET NOT NULL")
