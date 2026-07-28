"""Framework selector (NIST-80053-01) — ``framework`` on ssp_projects.

Adds a ``framework`` column to ``ccf.ssp_projects`` so an SSP project can
target ``cmmc-800-171`` (today's default behavior) or ``nist-800-53r5``
(new). Existing projects keep today's behavior via the server default. No
RLS change — the ``ssp_projects`` policy is unchanged.

Revision ID: 0054_ssp_project_framework
Revises: 0053_user_lockout
Create Date: 2026-07-27
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0054_ssp_project_framework"
down_revision = "0053_user_lockout"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "ssp_projects",
        sa.Column("framework", sa.String(32), server_default="cmmc-800-171", nullable=False),
        schema="ccf",
    )


def downgrade() -> None:
    op.drop_column("ssp_projects", "framework", schema="ccf")
