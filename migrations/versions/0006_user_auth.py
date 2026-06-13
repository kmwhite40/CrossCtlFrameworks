"""Add password hash + API token to users (authentication).

Revision ID: 0006_user_auth
Revises: 0005_ssp_entry_sort_index
Create Date: 2026-06-13
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0006_user_auth"
down_revision = "0005_ssp_entry_sort_index"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("password_hash", sa.String(255)), schema="ccf")
    op.add_column("users", sa.Column("api_token", sa.String(64)), schema="ccf")
    op.create_index(
        "ix_ccf_users_api_token", "users", ["api_token"], unique=True, schema="ccf"
    )


def downgrade() -> None:
    op.drop_index("ix_ccf_users_api_token", table_name="users", schema="ccf")
    op.drop_column("users", "api_token", schema="ccf")
    op.drop_column("users", "password_hash", schema="ccf")
