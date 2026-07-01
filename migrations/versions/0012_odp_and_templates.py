"""ODP fill-in-the-blank + canned statement templates for the SSP builder.

Revision ID: 0012_odp_and_templates
Revises: 0011_catalog_sources
Create Date: 2026-07-01
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0012_odp_and_templates"
down_revision = "0011_catalog_sources"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scoring_controls",
        sa.Column("odp_definitions", postgresql.JSONB, nullable=False, server_default="[]"),
        schema="ccf",
    )
    op.add_column(
        "ssp_control_entries",
        sa.Column("odp_values", postgresql.JSONB, nullable=False, server_default="{}"),
        schema="ccf",
    )
    op.create_table(
        "statement_templates",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("key", sa.String(64), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("scope", sa.String(16), nullable=False, server_default="global"),
        sa.Column("domain", sa.String(8)),
        sa.Column("control_id", sa.String(32)),
        sa.Column("platform", sa.String(32)),
        sa.Column("body", sa.Text, nullable=False),
        sa.Column("tags", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("source", sa.String(255)),
        sa.Column("sort_order", sa.Integer, nullable=False, server_default="0"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("key", name="uq_statement_template_key"),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_statement_templates_key", "statement_templates", ["key"], schema="ccf"
    )
    op.create_index(
        "ix_ccf_statement_templates_domain", "statement_templates", ["domain"], schema="ccf"
    )
    op.create_index(
        "ix_ccf_statement_templates_control", "statement_templates", ["control_id"], schema="ccf"
    )


def downgrade() -> None:
    op.drop_table("statement_templates", schema="ccf")
    op.drop_column("ssp_control_entries", "odp_values", schema="ccf")
    op.drop_column("scoring_controls", "odp_definitions", schema="ccf")
