"""Session revocation (AC-12) — ``session_version`` on users.

Adds ``ccf.users.session_version``. The signed session cookie carries the
version it was minted with; principal lookup rejects a token whose version no
longer matches the row. Bumping the column therefore invalidates every session
cookie already issued for that user, which is what logout and password change
now do.

Existing rows default to ``0``, and session tokens minted before this change
carry no version claim and read as ``0`` — so applying this migration does not
log active users out.

Revision ID: 0065_user_session_version
Revises: 0064_engine_rls_coverage
Create Date: 2026-08-19
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0065_user_session_version"
down_revision = "0064_engine_rls_coverage"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("session_version", sa.Integer(), server_default="0", nullable=False),
        schema="ccf",
    )


def downgrade() -> None:
    op.drop_column("users", "session_version", schema="ccf")
