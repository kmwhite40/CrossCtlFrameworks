"""Approval / separation-of-duties workflow for governed entities.

Revision ID: 0017_approvals
Revises: 0016_capture_snapshots
Create Date: 2026-07-01
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0017_approvals"
down_revision = "0016_capture_snapshots"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "approvals",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer,
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
        ),
        sa.Column("entity_type", sa.String(32), nullable=False),
        sa.Column("entity_id", sa.String(64), nullable=False),
        sa.Column("state", sa.String(16), nullable=False, server_default="draft"),
        sa.Column("submitted_by", sa.String(255)),
        sa.Column("submitted_at", sa.DateTime(timezone=True)),
        sa.Column("reviewed_by", sa.String(255)),
        sa.Column("reviewed_at", sa.DateTime(timezone=True)),
        sa.Column("decision_note", sa.Text),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("entity_type", "entity_id", name="uq_approval_entity"),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_approvals_org", "approvals", ["organization_id"], schema="ccf"
    )
    op.create_index(
        "ix_approvals_entity", "approvals", ["entity_type", "entity_id"], schema="ccf"
    )


def downgrade() -> None:
    op.drop_table("approvals", schema="ccf")
