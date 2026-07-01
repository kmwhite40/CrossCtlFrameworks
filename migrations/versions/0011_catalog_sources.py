"""Catalog currency layer — upstream source registry + drift-check log.

Revision ID: 0011_catalog_sources
Revises: 0010_row_level_security
Create Date: 2026-07-01
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0011_catalog_sources"
down_revision = "0010_row_level_security"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "catalog_sources",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("key", sa.String(64), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("authority", sa.String(64)),
        sa.Column("kind", sa.String(32), nullable=False, server_default="oscal_catalog"),
        sa.Column("url", sa.String(1024), nullable=False),
        sa.Column("framework_code", sa.String(64)),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("auto_ingest", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("etag", sa.String(255)),
        sa.Column("last_sha256", sa.String(64)),
        sa.Column("last_status", sa.String(32)),
        sa.Column("last_error", sa.Text),
        sa.Column("revision_label", sa.String(64)),
        sa.Column("item_count", sa.Integer),
        sa.Column("content_index", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("last_checked_at", sa.DateTime(timezone=True)),
        sa.Column("last_changed_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("key", name="uq_catalog_source_key"),
        schema="ccf",
    )
    op.create_index("ix_ccf_catalog_sources_key", "catalog_sources", ["key"], schema="ccf")

    op.create_table(
        "catalog_checks",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "source_id",
            sa.Integer,
            sa.ForeignKey("ccf.catalog_sources.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "checked_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("http_status", sa.Integer),
        sa.Column("sha256", sa.String(64)),
        sa.Column("duration_ms", sa.Integer),
        sa.Column("detail", postgresql.JSONB, nullable=False, server_default="{}"),
        schema="ccf",
    )
    op.create_index("ix_ccf_catalog_checks_source", "catalog_checks", ["source_id"], schema="ccf")
    op.create_index(
        "ix_ccf_catalog_checks_checked_at", "catalog_checks", ["checked_at"], schema="ccf"
    )


def downgrade() -> None:
    op.drop_table("catalog_checks", schema="ccf")
    op.drop_table("catalog_sources", schema="ccf")
