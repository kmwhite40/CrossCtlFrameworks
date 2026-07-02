"""Enterprise identity — OIDC/SSO federation, JIT, and SCIM provisioning.

Adds ``identity_providers``, ``external_identities``, ``group_role_mappings``, and
``scim_provisioning_events``, all tenant-isolated under the standard
``ccf.current_tenant()`` RLS policy.

Revision ID: 0027_identity_sso_scim
Revises: 0026_vendor_questionnaires
Create Date: 2026-07-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0027_identity_sso_scim"
down_revision = "0026_vendor_questionnaires"
branch_labels = None
depends_on = None

_ORG = "organization_id = ccf.current_tenant()"
_POLICIES = {
    "identity_providers": _ORG,
    "external_identities": _ORG,
    "group_role_mappings": _ORG,
    "scim_provisioning_events": _ORG,
}


def upgrade() -> None:
    op.create_table(
        "identity_providers",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "organization_id", sa.Integer,
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
        ),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("issuer", sa.String(512), nullable=False),
        sa.Column("client_id", sa.String(255)),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("default_role", sa.String(32), nullable=False, server_default="viewer"),
        sa.Column("allowed_domains", postgresql.JSONB, server_default="[]", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_identity_providers_org", "identity_providers", ["organization_id"], schema="ccf"
    )

    op.create_table(
        "external_identities",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "organization_id", sa.Integer,
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
        ),
        sa.Column(
            "user_id", sa.Integer, sa.ForeignKey("ccf.users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("provider", sa.String(128), nullable=False, server_default="oidc"),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("email", sa.String(255)),
        sa.Column("claims", postgresql.JSONB, server_default="{}", nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("provider", "subject", name="uq_external_identity"),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_external_identities_org", "external_identities", ["organization_id"], schema="ccf"
    )
    op.create_index(
        "ix_ccf_external_identities_user", "external_identities", ["user_id"], schema="ccf"
    )

    op.create_table(
        "group_role_mappings",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "organization_id", sa.Integer,
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
        ),
        sa.Column("group", sa.String(255), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("priority", sa.Integer, nullable=False, server_default="100"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("organization_id", "group", name="uq_group_role_mapping"),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_group_role_mappings_org", "group_role_mappings", ["organization_id"], schema="ccf"
    )

    op.create_table(
        "scim_provisioning_events",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "organization_id", sa.Integer,
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
        ),
        sa.Column("operation", sa.String(16), nullable=False),
        sa.Column("external_id", sa.String(255)),
        sa.Column("email", sa.String(255)),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("ccf.users.id", ondelete="SET NULL")),
        sa.Column("detail", postgresql.JSONB, server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("note", sa.Text),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_scim_events_org", "scim_provisioning_events", ["organization_id"], schema="ccf"
    )

    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ccf.identity_providers, "
        "ccf.external_identities, ccf.group_role_mappings, ccf.scim_provisioning_events "
        "TO ccf_app; GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    for table, predicate in _POLICIES.items():
        expr = f"(ccf.current_tenant() IS NULL OR {predicate})"
        op.execute(f"ALTER TABLE ccf.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE ccf.{table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON ccf.{table} "
            f"FOR ALL USING {expr} WITH CHECK {expr}"
        )


def downgrade() -> None:
    for table in _POLICIES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON ccf.{table}")
    op.drop_table("scim_provisioning_events", schema="ccf")
    op.drop_table("group_role_mappings", schema="ccf")
    op.drop_table("external_identities", schema="ccf")
    op.drop_table("identity_providers", schema="ccf")
