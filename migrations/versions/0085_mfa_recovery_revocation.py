"""Recovery codes can be revoked, distinctly from being used.

A recovery code outlived the authenticator it was minted for: disabling MFA
deleted ``user_mfa_credentials`` and left ``user_mfa_recovery_codes`` untouched,
so a code that leaked before somebody rotated their second factor still signed
them in afterwards.

Revocation needs its own column rather than reusing ``used_at``. ``used_at``
means *somebody signed in with this code, at this time* -- it is the column an
administrator reads to answer "did anyone get in without their authenticator".
Setting it on a code nobody used would answer that question wrongly, which is
the same class of false-but-valid value this programme keeps finding.

Revision ID: 0085_mfa_recovery_revocation
Revises: 0084_mfa_totp
Create Date: 2026-09-24
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0085_mfa_recovery_revocation"
down_revision = "0084_mfa_totp"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"


def upgrade() -> None:
    op.add_column(
        "user_mfa_recovery_codes",
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        schema=_SCHEMA,
    )
    # Any code belonging to a user who has no credential right now was minted
    # for an authenticator that is gone. Revoked as of this migration, with the
    # same reasoning as the column itself: they are not "used", they are dead.
    op.execute(
        "UPDATE ccf.user_mfa_recovery_codes rc SET revoked_at = now() "
        "WHERE rc.used_at IS NULL AND rc.revoked_at IS NULL AND NOT EXISTS ("
        "  SELECT 1 FROM ccf.user_mfa_credentials c "
        "  WHERE c.user_id = rc.user_id AND c.activated_at IS NOT NULL)"
    )


def downgrade() -> None:
    op.drop_column("user_mfa_recovery_codes", "revoked_at", schema=_SCHEMA)
