"""System boundary & inventory (Keystone #1) — four tenant-scoped models.

Adds ``system_components`` (OSCAL ``component``), ``inventory_items``
(OSCAL ``inventory-item``), ``information_types`` (OSCAL
``information-type``), and ``interconnections`` (OSCAL ``component`` type
``interconnection``). All four are tenant-scoped via ``organization_id``
and carry the standard SOTA-hook columns (``oscal_uuid``, ``source``,
``last_seen_at``) used for future connector/import ingestion.

RLS mirrors migration 0039's ``tenant_isolation`` pattern (ENABLE + FORCE,
predicate ``ccf.current_tenant() IS NULL OR organization_id =
ccf.current_tenant()``) on all four tables.

Revision ID: 0052_system_boundary_inventory
Revises: 0051_catalog_integrity_reports
Create Date: 2026-07-27
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0052_system_boundary_inventory"
down_revision = "0051_catalog_integrity_reports"
branch_labels = None
depends_on = None

_TABLES = ["system_components", "inventory_items", "information_types", "interconnections"]


def _enable_rls(table: str) -> None:
    op.execute(f"ALTER TABLE ccf.{table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE ccf.{table} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation ON ccf.{table} "
        f"USING (ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant())"
    )


def upgrade() -> None:
    op.create_table(
        "system_components",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer,
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "system_id",
            sa.Integer,
            sa.ForeignKey("ccf.systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("type", sa.String(32), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("status", sa.String(32), nullable=False, server_default="operational"),
        sa.Column("purpose", sa.Text),
        sa.Column("responsible_role", sa.String(128)),
        sa.Column("props", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("oscal_uuid", sa.String(36), nullable=False, unique=True),
        sa.Column("source", sa.String(16), nullable=False, server_default="manual"),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_system_components_organization_id",
        "system_components",
        ["organization_id"],
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_system_components_system_id", "system_components", ["system_id"], schema="ccf"
    )

    op.create_table(
        "inventory_items",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer,
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "system_id",
            sa.Integer,
            sa.ForeignKey("ccf.systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "component_id",
            sa.BigInteger,
            sa.ForeignKey("ccf.system_components.id", ondelete="SET NULL"),
        ),
        sa.Column("asset_id", sa.String(255), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("asset_type", sa.String(32), nullable=False),
        sa.Column("vendor_name", sa.String(255)),
        sa.Column("model", sa.String(255)),
        sa.Column("version", sa.String(128)),
        sa.Column("serial_number", sa.String(255)),
        sa.Column("hostname", sa.String(255)),
        sa.Column("ip_address", sa.String(64)),
        sa.Column("virtual", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("public", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("baseline_config", sa.Text),
        sa.Column("props", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("oscal_uuid", sa.String(36), nullable=False, unique=True),
        sa.Column("source", sa.String(16), nullable=False, server_default="manual"),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_inventory_items_organization_id",
        "inventory_items",
        ["organization_id"],
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_inventory_items_system_id", "inventory_items", ["system_id"], schema="ccf"
    )
    op.create_index(
        "ix_ccf_inventory_items_component_id", "inventory_items", ["component_id"], schema="ccf"
    )

    op.create_table(
        "information_types",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer,
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "system_id",
            sa.Integer,
            sa.ForeignKey("ccf.systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column(
            "categorization_system",
            sa.String(255),
            nullable=False,
            server_default="https://doi.org/10.6028/NIST.SP.800-60v2r1",
        ),
        sa.Column("nist_800_60_id", sa.String(64)),
        sa.Column(
            "confidentiality_impact",
            postgresql.ENUM(name="fips199_level", schema="ccf", create_type=False),
        ),
        sa.Column(
            "integrity_impact",
            postgresql.ENUM(name="fips199_level", schema="ccf", create_type=False),
        ),
        sa.Column(
            "availability_impact",
            postgresql.ENUM(name="fips199_level", schema="ccf", create_type=False),
        ),
        sa.Column("adjustment_justification", sa.Text),
        sa.Column("props", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("oscal_uuid", sa.String(36), nullable=False, unique=True),
        sa.Column("source", sa.String(16), nullable=False, server_default="manual"),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_information_types_organization_id",
        "information_types",
        ["organization_id"],
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_information_types_system_id", "information_types", ["system_id"], schema="ccf"
    )

    op.create_table(
        "interconnections",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer,
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "system_id",
            sa.Integer,
            sa.ForeignKey("ccf.systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("remote_system_name", sa.String(255), nullable=False),
        sa.Column("remote_org", sa.String(255)),
        sa.Column("direction", sa.String(16), nullable=False),
        sa.Column("connection_type", sa.String(128)),
        sa.Column("data_description", sa.Text),
        sa.Column("agreement_type", sa.String(16), nullable=False),
        sa.Column("agreement_ref", sa.String(255)),
        sa.Column("agreement_date", sa.Date),
        sa.Column("expires_on", sa.Date),
        sa.Column("authorization_status", sa.String(64)),
        sa.Column("props", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("oscal_uuid", sa.String(36), nullable=False, unique=True),
        sa.Column("source", sa.String(16), nullable=False, server_default="manual"),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_interconnections_organization_id",
        "interconnections",
        ["organization_id"],
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_interconnections_system_id", "interconnections", ["system_id"], schema="ccf"
    )

    for t in _TABLES:
        _enable_rls(t)


def downgrade() -> None:
    for t in _TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON ccf.{t}")
        op.execute(f"ALTER TABLE ccf.{t} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE ccf.{t} DISABLE ROW LEVEL SECURITY")
    for t in reversed(_TABLES):
        op.drop_table(t, schema="ccf")
