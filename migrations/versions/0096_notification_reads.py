"""Notification read-state is per user, not per notification.

Revision ID: 0096_notification_reads
Revises: 0095_marketplace_products
Create Date: 2026-10-15

``notifications.read_at`` is one column on an org-wide broadcast row, so any
member who marked a notification read -- or pressed "read all" -- marked it
read for **everyone** in the organization, and ``bus.notify`` re-notification
never clears it. One user could silence every user's overdue-task, access-
review and ATO-expiry alerts. Found by independent review of the viewer
read-only gate (764e87e), which had wrongly allowlisted it as "per-user".

``notification_reads`` holds one row per (notification, user). The routes and
pages read and write only the caller's rows. ``notifications.read_at`` stays
for the SYSTEM principal (auth disabled), which has no user to key on.

No backfill: who read a broadcast under the old model is unknowable -- the
column records only that *someone* did -- so every user starts with each
existing notification unread. That re-surfaces alerts one user had silenced
for all, which is the point.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0096_notification_reads"
down_revision = "0095_marketplace_products"
branch_labels = None
depends_on = None

_TABLE = "notification_reads"
_PREDICATE = "(ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant())"


def upgrade() -> None:
    op.create_table(
        _TABLE,
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "notification_id",
            sa.BigInteger(),
            sa.ForeignKey("ccf.notifications.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("ccf.users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "read_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint("notification_id", "user_id", name="uq_notification_read_user"),
        schema="ccf",
    )
    op.create_index("ix_notification_reads_user", _TABLE, ["user_id"], schema="ccf")
    op.create_index(
        "ix_notification_reads_organization_id", _TABLE, ["organization_id"], schema="ccf"
    )
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    op.execute(f"ALTER TABLE ccf.{_TABLE} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE ccf.{_TABLE} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation ON ccf.{_TABLE} "
        f"FOR ALL USING {_PREDICATE} WITH CHECK {_PREDICATE}"
    )


def downgrade() -> None:
    op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON ccf.{_TABLE}")
    op.drop_table(_TABLE, schema="ccf")
