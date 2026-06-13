"""Index ssp_control_entries on (project_id, sort_order) for ordered reads.

Revision ID: 0005_ssp_entry_sort_index
Revises: 0004_ssp_platform
Create Date: 2026-06-13
"""

from __future__ import annotations

from alembic import op

revision = "0005_ssp_entry_sort_index"
down_revision = "0004_ssp_platform"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_ssp_entry_project_sort",
        "ssp_control_entries",
        ["project_id", "sort_order"],
        schema="ccf",
    )


def downgrade() -> None:
    op.drop_index("ix_ssp_entry_project_sort", table_name="ssp_control_entries", schema="ccf")
