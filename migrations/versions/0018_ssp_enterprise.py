"""Enterprise SSP front matter — system characterization metadata + revisions.

Revision ID: 0018_ssp_enterprise
Revises: 0017_approvals
Create Date: 2026-07-01
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0018_ssp_enterprise"
down_revision = "0017_approvals"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "ssp_projects",
        sa.Column("metadata_json", postgresql.JSONB, nullable=False, server_default="{}"),
        schema="ccf",
    )
    op.add_column(
        "ssp_projects",
        sa.Column("revision_history", postgresql.JSONB, nullable=False, server_default="[]"),
        schema="ccf",
    )


def downgrade() -> None:
    op.drop_column("ssp_projects", "revision_history", schema="ccf")
    op.drop_column("ssp_projects", "metadata_json", schema="ccf")
