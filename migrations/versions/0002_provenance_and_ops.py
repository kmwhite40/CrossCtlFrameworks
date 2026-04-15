"""Provenance history + quarantine + operational additions.

Revision ID: 0002_provenance_and_ops
Revises: 0001_baseline
Create Date: 2026-04-15
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0002_provenance_and_ops"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS ccf_audit")

    op.create_table(
        "workbook_versions",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("sha256", sa.String(64), nullable=False, unique=True),
        sa.Column("source_path", sa.String(512), nullable=False),
        sa.Column("revision_label", sa.String(64)),
        sa.Column(
            "imported_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("imported_by", sa.String(255)),
        sa.Column("size_bytes", sa.BigInteger),
        schema="ccf_audit",
    )

    op.add_column(
        "ingestion_runs",
        sa.Column(
            "workbook_version_id",
            sa.Integer,
            sa.ForeignKey("ccf_audit.workbook_versions.id", ondelete="SET NULL"),
        ),
        schema="ccf",
    )

    op.create_table(
        "rejected_rows",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "run_id",
            sa.Integer,
            sa.ForeignKey("ccf.ingestion_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("sheet", sa.String(255), nullable=False),
        sa.Column("row_index", sa.Integer, nullable=False),
        sa.Column("rule", sa.String(128), nullable=False),
        sa.Column("payload", postgresql.JSONB, nullable=False),
        sa.Column(
            "rejected_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        schema="ccf_audit",
    )
    op.create_index(
        "ix_ccf_audit_rejected_rows_run", "rejected_rows", ["run_id"], schema="ccf_audit"
    )

    op.create_table(
        "control_history",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("identifier", sa.String(128), nullable=False),
        sa.Column(
            "workbook_version_id",
            sa.Integer,
            sa.ForeignKey("ccf_audit.workbook_versions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("payload", postgresql.JSONB, nullable=False),
        sa.Column(
            "valid_from",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        schema="ccf_audit",
    )
    op.create_index(
        "ix_control_history_ident", "control_history", ["identifier"], schema="ccf_audit"
    )
    op.create_index(
        "ix_control_history_ver", "control_history", ["workbook_version_id"], schema="ccf_audit"
    )

    op.create_table(
        "mapping_history",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("identifier", sa.String(128), nullable=False),
        sa.Column(
            "workbook_version_id",
            sa.Integer,
            sa.ForeignKey("ccf_audit.workbook_versions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("column_key", sa.String(255), nullable=False),
        sa.Column("value", sa.Text, nullable=False),
        sa.Column(
            "valid_from",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        schema="ccf_audit",
    )
    op.create_index(
        "ix_mapping_history_ident", "mapping_history", ["identifier"], schema="ccf_audit"
    )
    op.create_index("ix_mapping_history_col", "mapping_history", ["column_key"], schema="ccf_audit")

    # Users.created_at — missing in 0001
    op.add_column(
        "users",
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        schema="ccf",
    )


def downgrade() -> None:
    op.drop_column("users", "created_at", schema="ccf")
    op.drop_table("mapping_history", schema="ccf_audit")
    op.drop_table("control_history", schema="ccf_audit")
    op.drop_table("rejected_rows", schema="ccf_audit")
    op.drop_column("ingestion_runs", "workbook_version_id", schema="ccf")
    op.drop_table("workbook_versions", schema="ccf_audit")
