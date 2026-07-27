"""Account lockout (AC-7) — failed_login_attempts + locked_until on users.

Adds two columns to ``ccf.users`` used by the login route
(``ccf.api.routes.auth.login``) to lock an account out after repeated failed
password attempts (threshold/duration configurable via
``Settings.auth_lockout_threshold`` / ``auth_lockout_minutes``). No RLS
change — the ``users`` table policy is unchanged.

Revision ID: 0053_user_lockout
Revises: 0052_system_boundary_inventory
Create Date: 2026-07-27
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0053_user_lockout"
down_revision = "0052_system_boundary_inventory"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("failed_login_attempts", sa.Integer, server_default="0", nullable=False),
        schema="ccf",
    )
    op.add_column(
        "users",
        sa.Column("locked_until", sa.DateTime(timezone=True)),
        schema="ccf",
    )


def downgrade() -> None:
    op.drop_column("users", "locked_until", schema="ccf")
    op.drop_column("users", "failed_login_attempts", schema="ccf")
