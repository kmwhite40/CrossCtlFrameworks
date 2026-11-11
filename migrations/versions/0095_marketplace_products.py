"""FedRAMP Marketplace products, as reference data; dependencies link to one.

Revision ID: 0095_marketplace_products
Revises: 0094_ksi_methods
Create Date: 2026-10-15

``ccf.marketplace_products`` is global reference data refreshed from FedRAMP's
own published Marketplace (``FedRAMP/marketplace-fedramp-gov-data``). A
``FedRAMPDependency`` may link to one by FedRAMP ID; Concord then shows the
Marketplace record beside the operator's recorded status and names any
disagreement. It never overwrites the recorded values -- see
docs/superpowers/specs/2026-10-15-fedramp-marketplace-design.md.

A product absent from a later refresh is delisted (``delisted_at``), never
deleted: a dependency may still point at it, and "FedRAMP no longer lists
this" is the finding.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0095_marketplace_products"
down_revision = "0094_ksi_methods"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "marketplace_products",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("fedramp_id", sa.String(32), nullable=False, unique=True),
        sa.Column("csp", sa.String(512), nullable=False),
        sa.Column("cso", sa.String(512), nullable=False),
        sa.Column("status", sa.String(64), nullable=False),
        sa.Column("impact_level", sa.String(32)),
        sa.Column("auth_type", sa.String(32)),
        sa.Column("auth_date", sa.Date()),
        sa.Column("independent_assessor", sa.String(512)),
        sa.Column("service_model", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("deployment_model", sa.String(64)),
        sa.Column("leveraged_systems", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("source_commit", sa.String(64)),
        sa.Column("refreshed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("delisted_at", sa.DateTime(timezone=True)),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_marketplace_products_cso", "marketplace_products", ["cso"], schema="ccf"
    )
    op.add_column(
        "fedramp_dependencies",
        sa.Column("marketplace_id", sa.String(32), nullable=True),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_fedramp_dependencies_marketplace_id",
        "fedramp_dependencies",
        ["marketplace_id"],
        schema="ccf",
    )


def downgrade() -> None:
    op.drop_index(
        "ix_ccf_fedramp_dependencies_marketplace_id",
        table_name="fedramp_dependencies",
        schema="ccf",
    )
    op.drop_column("fedramp_dependencies", "marketplace_id", schema="ccf")
    op.drop_index(
        "ix_ccf_marketplace_products_cso", table_name="marketplace_products", schema="ccf"
    )
    op.drop_table("marketplace_products", schema="ccf")
