"""Organization-scoped AI provider configs + envelope-encrypted credentials.

Adds ``ai_provider_configs`` (one row per organization+provider) storing the
provider, enabled flag, default/allowed models, and an envelope-encrypted
credential token (plus a masked ``key_last4``). Tenant-isolated via RLS.

Revision ID: 0037_ai_provider_configs
Revises: 0036_external_portal
Create Date: 2026-07-21
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0037_ai_provider_configs"
down_revision = "0036_external_portal"
branch_labels = None
depends_on = None

JB = postgresql.JSONB
_TABLE = "ai_provider_configs"
_PREDICATE = "organization_id = ccf.current_tenant()"


def upgrade() -> None:
    op.create_table(
        _TABLE,
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer,
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("provider", sa.String(24), nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("default_model", sa.String(64)),
        sa.Column("allowed_models", JB, server_default="[]", nullable=False),
        sa.Column("encrypted_credential", sa.Text),
        sa.Column("key_last4", sa.String(8)),
        sa.Column("created_by", sa.String(255)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("rotated_at", sa.DateTime(timezone=True)),
        sa.Column("validated_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("organization_id", "provider", name="uq_ai_provider_org"),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_ai_provider_configs_org", _TABLE, ["organization_id"], schema="ccf"
    )

    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    expr = f"(ccf.current_tenant() IS NULL OR {_PREDICATE})"
    op.execute(f"ALTER TABLE ccf.{_TABLE} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE ccf.{_TABLE} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation ON ccf.{_TABLE} "
        f"FOR ALL USING {expr} WITH CHECK {expr}"
    )


def downgrade() -> None:
    op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON ccf.{_TABLE}")
    op.drop_index("ix_ccf_ai_provider_configs_org", table_name=_TABLE, schema="ccf")
    op.drop_table(_TABLE, schema="ccf")
