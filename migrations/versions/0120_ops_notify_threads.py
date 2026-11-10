"""The operator's Slack thread per organization (and channel).

Revision ID: 0120_ops_notify_threads
Revises: 0119_org_notify_channels
Create Date: 2026-11-09

``ops_notify_threads`` maps an organization to the ``ts`` of the "Alerts for
<org>" parent message in the operator's ops channel, so each organization's
alerts land in one thread. Keyed on (organization, channel): pointing
``CCF_NOTIFY_SLACK_CHANNEL`` elsewhere starts new threads there instead of
replying to parents in a channel no longer used.

**Platform-only.** The ops channel is the operator's (spec section 2.4), so no
tenant may read or write a row. Two layers: ``ccf_app`` -- the role every tenant
session runs as -- holds no privilege on the table (0010's default privileges
grant it SELECT/INSERT/UPDATE/DELETE on every new table, so they are revoked),
and RLS is enabled and forced with a policy that admits only an unscoped
session. The ``notify_delivery`` consumer writes it unscoped.

See docs/superpowers/specs/2026-11-09-org-notify-channels-design.md.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0120_ops_notify_threads"
down_revision = "0119_org_notify_channels"
branch_labels = None
depends_on = None

_PLATFORM_ONLY = "(ccf.current_tenant() IS NULL)"


def upgrade() -> None:
    op.create_table(
        "ops_notify_threads",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("channel", sa.String(128), nullable=False),
        sa.Column("thread_ts", sa.String(64), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint("organization_id", "channel", name="uq_ops_notify_threads_org_channel"),
        schema="ccf",
    )
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "REVOKE ALL ON ccf.ops_notify_threads FROM ccf_app; END IF; END $$"
    )
    op.execute("ALTER TABLE ccf.ops_notify_threads ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE ccf.ops_notify_threads FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY platform_only ON ccf.ops_notify_threads "
        f"FOR ALL USING {_PLATFORM_ONLY} WITH CHECK {_PLATFORM_ONLY}"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS ccf.ops_notify_threads")
