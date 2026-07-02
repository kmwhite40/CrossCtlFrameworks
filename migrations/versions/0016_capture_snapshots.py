"""Connector capture snapshots — config-drift baselines for auto-collection.

Revision ID: 0016_capture_snapshots
Revises: 0015_system_profile_automation
Create Date: 2026-07-01
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0016_capture_snapshots"
down_revision = "0015_system_profile_automation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "capture_snapshots",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer,
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
        ),
        sa.Column("connector", sa.String(32), nullable=False),
        sa.Column("odp_key", sa.String(64), nullable=False),
        sa.Column("value", sa.Text, nullable=False),
        sa.Column("nist_id", sa.String(16)),
        sa.Column(
            "captured_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint(
            "organization_id", "connector", "odp_key", name="uq_capture_snapshot"
        ),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_capture_snapshots_org", "capture_snapshots", ["organization_id"], schema="ccf"
    )


def downgrade() -> None:
    op.drop_table("capture_snapshots", schema="ccf")
