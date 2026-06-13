"""Add deployment platform to SSP projects.

Revision ID: 0004_ssp_platform
Revises: 0003_scoring_and_ssp
Create Date: 2026-06-13
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004_ssp_platform"
down_revision = "0003_scoring_and_ssp"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "ssp_projects",
        sa.Column("platform", sa.String(32), nullable=False, server_default="m365"),
        schema="ccf",
    )


def downgrade() -> None:
    op.drop_column("ssp_projects", "platform", schema="ccf")
