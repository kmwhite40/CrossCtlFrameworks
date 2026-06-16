"""Tamper-evident audit hash chain (prev_hash / row_hash on audit_log).

Revision ID: 0007_audit_hash_chain
Revises: 0006_user_auth
Create Date: 2026-06-13
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0007_audit_hash_chain"
down_revision = "0006_user_auth"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("audit_log", sa.Column("prev_hash", sa.String(64)), schema="ccf")
    op.add_column("audit_log", sa.Column("row_hash", sa.String(64)), schema="ccf")


def downgrade() -> None:
    op.drop_column("audit_log", "row_hash", schema="ccf")
    op.drop_column("audit_log", "prev_hash", schema="ccf")
