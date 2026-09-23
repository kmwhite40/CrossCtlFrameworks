"""TOTP multi-factor authentication (IA-2(1)).

Two tenant tables and one column. See
``docs/superpowers/specs/2026-09-23-mfa-totp-design.md``.

``user_mfa_credentials`` holds at most one authenticator per user -- a unique
constraint, not a convention, because two active authenticators would mean two
independent replay windows and ``last_used_step`` would stop meaning "the step
already spent". ``activated_at`` is the gate rather than the row's existence:
enrolment must persist the secret before the user can prove they hold it, so a
credential that has never produced a correct code challenges nobody.

``user_mfa_recovery_codes`` stores SHA-256 digests. That is deliberately not
the PBKDF2 hashing used for passwords -- an 80-bit random code has nothing to
stretch, and 210,000 rounds across ten stored codes per login attempt is a
denial-of-service surface an unauthenticated caller controls for free. The
reasoning also lives at ``ccf.mfa.hash_recovery_code`` so it is visible where
somebody would otherwise "fix" it.

``organizations.mfa_policy`` defaults to ``optional``. Changing every existing
deployment's login behaviour in an upgrade is not a thing to do implicitly.

Tenancy: both new tables carry ``organization_id`` and take the direct
``organization_id = ccf.current_tenant()`` policy, so they join
``tests/test_rls_coverage.py``'s ``EXPECTED_TENANT_ISOLATION_TABLES``
(count 139 -> 141).

Revision ID: 0084_mfa_totp
Revises: 0083_3pao_engagements
Create Date: 2026-09-23
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0084_mfa_totp"
down_revision = "0083_3pao_engagements"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"
_PREDICATE = "(ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant())"


def upgrade() -> None:
    mfa_policy = sa.Enum("optional", "admins", "all", name="mfa_policy", schema=_SCHEMA)
    mfa_policy.create(op.get_bind(), checkfirst=True)
    op.add_column(
        "organizations",
        sa.Column("mfa_policy", mfa_policy, nullable=False, server_default="optional"),
        schema=_SCHEMA,
    )

    op.create_table(
        "user_mfa_credentials",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("ccf.users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("secret_encrypted", sa.Text(), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True)),
        sa.Column("last_used_step", sa.BigInteger()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("user_id", name="uq_user_mfa_credential"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_ccf_user_mfa_credentials_organization_id",
        "user_mfa_credentials",
        ["organization_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_ccf_user_mfa_credentials_user_id", "user_mfa_credentials", ["user_id"], schema=_SCHEMA
    )

    op.create_table(
        "user_mfa_recovery_codes",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("ccf.users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("code_hash", sa.String(64), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_ccf_user_mfa_recovery_codes_organization_id",
        "user_mfa_recovery_codes",
        ["organization_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_ccf_user_mfa_recovery_codes_user_id",
        "user_mfa_recovery_codes",
        ["user_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_ccf_user_mfa_recovery_codes_code_hash",
        "user_mfa_recovery_codes",
        ["code_hash"],
        schema=_SCHEMA,
    )

    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    for table in ("user_mfa_credentials", "user_mfa_recovery_codes"):
        op.execute(f"ALTER TABLE ccf.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE ccf.{table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON ccf.{table} "
            f"FOR ALL USING {_PREDICATE} WITH CHECK {_PREDICATE}"
        )


def downgrade() -> None:
    for table in ("user_mfa_recovery_codes", "user_mfa_credentials"):
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON ccf.{table}")
        op.drop_table(table, schema=_SCHEMA)
    op.drop_column("organizations", "mfa_policy", schema=_SCHEMA)
    sa.Enum(name="mfa_policy", schema=_SCHEMA).drop(op.get_bind(), checkfirst=True)
