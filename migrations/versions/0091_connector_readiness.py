"""Persist provider readiness diagnostics for live scans.

Revision ID: 0091_connector_readiness
Revises: 0090_poam_remediation_source
Create Date: 2026-09-26
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0091_connector_readiness"
down_revision = "0090_poam_remediation_source"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "connector_configs",
        sa.Column("readiness_status", sa.String(32), nullable=True),
        schema="ccf",
    )
    op.add_column(
        "connector_configs",
        sa.Column("readiness_checked_at", sa.DateTime(timezone=True), nullable=True),
        schema="ccf",
    )
    op.add_column(
        "connector_configs",
        sa.Column("readiness_detail", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        schema="ccf",
    )


def downgrade() -> None:
    op.drop_column("connector_configs", "readiness_detail", schema="ccf")
    op.drop_column("connector_configs", "readiness_checked_at", schema="ccf")
    op.drop_column("connector_configs", "readiness_status", schema="ccf")
