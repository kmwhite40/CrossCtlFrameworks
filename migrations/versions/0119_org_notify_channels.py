"""An organization's own Slack/Teams alert channel.

Revision ID: 0119_org_notify_channels
Revises: 0118_cr26_rationale_authors
Create Date: 2026-11-09

``org_notify_channels`` holds at most one channel per organization, set by that
organization's admins. ``encrypted_url`` is envelope-encrypted under its own
associated data (``ccf.ai.cipher.AAD_NOTIFY_CHANNEL``): the URL is the
credential, so it is never stored or shown in clear; ``url_hint`` (scheme and
host only: the path carries the token) is what the settings page shows.

Tenant table: the standard ``tenant_isolation`` predicate, forced. ``ccf_app``
may delete a row (an admin removes the channel); it holds no TRUNCATE.

See docs/superpowers/specs/2026-11-09-org-notify-channels-design.md.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0119_org_notify_channels"
down_revision = "0118_cr26_rationale_authors"
branch_labels = None
depends_on = None

_PREDICATE = "(ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant())"


def upgrade() -> None:
    op.create_table(
        "org_notify_channels",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("encrypted_url", sa.Text(), nullable=False),
        sa.Column("url_hint", sa.String(160), nullable=False),
        sa.Column("min_severity", sa.String(16), nullable=False, server_default="critical"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by", sa.String(255)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("updated_by", sa.String(255)),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint("organization_id", name="uq_org_notify_channels_org"),
        sa.CheckConstraint(
            "min_severity IN ('info', 'warning', 'critical')",
            name="ck_org_notify_channels_min_severity",
        ),
        schema="ccf",
    )
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        # DELETE is needed: an admin removes the channel. TRUNCATE (which RLS
        # does not filter) is not granted, by this or by 0010's defaults.
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ccf.org_notify_channels TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    op.execute("ALTER TABLE ccf.org_notify_channels ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE ccf.org_notify_channels FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON ccf.org_notify_channels "
        f"FOR ALL USING {_PREDICATE} WITH CHECK {_PREDICATE}"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS ccf.org_notify_channels")
