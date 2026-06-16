"""CMMC L2 live scoring matrix + SSP authoring tables.

Revision ID: 0003_scoring_and_ssp
Revises: 0002_provenance_and_ops
Create Date: 2026-06-13
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0003_scoring_and_ssp"
down_revision = "0002_provenance_and_ops"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scoring_controls",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("control_id", sa.String(32), nullable=False, unique=True),
        sa.Column("nist_id", sa.String(16)),
        sa.Column("domain", sa.String(8), nullable=False),
        sa.Column("title", sa.String(512)),
        sa.Column("point_value", sa.String(8), nullable=False),
        sa.Column("scoring_bucket", sa.String(64)),
        sa.Column("scoring_notes", sa.Text),
        sa.Column("requirement", sa.Text),
        sa.Column("objectives", sa.Text),
        sa.Column("objective_parts", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("examine_cases", sa.Text),
        sa.Column("interview_cases", sa.Text),
        sa.Column("test_cases", sa.Text),
        sa.Column("considerations", sa.Text),
        sa.Column("key_references", sa.Text),
        sa.Column("guide_page", sa.String(16)),
        sa.Column("pdf_page", sa.String(16)),
        sa.Column("source", sa.Text),
        sa.Column("m365_coverage_status", sa.String(64)),
        sa.Column("m365_primary_services", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("m365_secondary_services", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("m365_implementation_statement", sa.Text),
        sa.Column("m365_inheritance", sa.Text),
        sa.Column("recommended_customer_evidence", sa.Text),
        sa.Column("recommended_provider_evidence", sa.Text),
        sa.Column("evidence_notes", sa.Text),
        sa.Column("m365_source", sa.Text),
        sa.Column("sort_order", sa.Integer, nullable=False, server_default="0"),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_scoring_controls_control_id", "scoring_controls", ["control_id"], schema="ccf"
    )
    op.create_index("ix_ccf_scoring_controls_domain", "scoring_controls", ["domain"], schema="ccf")
    op.create_index(
        "ix_ccf_scoring_controls_nist_id", "scoring_controls", ["nist_id"], schema="ccf"
    )
    op.create_index(
        "ix_ccf_scoring_controls_coverage",
        "scoring_controls",
        ["m365_coverage_status"],
        schema="ccf",
    )

    op.create_table(
        "scoring_statuses",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "system_id",
            sa.Integer,
            sa.ForeignKey("ccf.systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scoring_control_id",
            sa.Integer,
            sa.ForeignKey("ccf.scoring_controls.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("state", sa.String(32), nullable=False, server_default="not_assessed"),
        sa.Column("notes", sa.Text),
        sa.Column("evidence_ref", sa.String(1024)),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("system_id", "scoring_control_id", name="uq_scoring_system_control"),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_scoring_statuses_system", "scoring_statuses", ["system_id"], schema="ccf"
    )
    op.create_index(
        "ix_ccf_scoring_statuses_control", "scoring_statuses", ["scoring_control_id"], schema="ccf"
    )

    op.create_table(
        "ssp_projects",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "system_id", sa.Integer, sa.ForeignKey("ccf.systems.id", ondelete="SET NULL")
        ),
        sa.Column("customer_name", sa.String(255), nullable=False),
        sa.Column("system_name", sa.String(255)),
        sa.Column(
            "title", sa.String(512), nullable=False, server_default="System Security Plan (SSP)"
        ),
        sa.Column("version", sa.String(32), nullable=False, server_default="0.1"),
        sa.Column("prepared_by", sa.String(255)),
        sa.Column("document_date", sa.Date),
        sa.Column("status", sa.String(32), nullable=False, server_default="draft"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        schema="ccf",
    )
    op.create_index("ix_ccf_ssp_projects_system", "ssp_projects", ["system_id"], schema="ccf")

    op.create_table(
        "ssp_control_entries",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "project_id",
            sa.Integer,
            sa.ForeignKey("ccf.ssp_projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("control_id", sa.String(32), nullable=False),
        sa.Column("nist_id", sa.String(16)),
        sa.Column("domain", sa.String(8)),
        sa.Column("title", sa.String(512)),
        sa.Column("requirement", sa.Text),
        sa.Column("responsible_role", sa.String(255)),
        sa.Column("implementation_status", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("control_origination", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("part_narratives", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("sort_order", sa.Integer, nullable=False, server_default="0"),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("project_id", "control_id", name="uq_ssp_project_control"),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_ssp_control_entries_project", "ssp_control_entries", ["project_id"], schema="ccf"
    )
    op.create_index(
        "ix_ccf_ssp_control_entries_control", "ssp_control_entries", ["control_id"], schema="ccf"
    )


def downgrade() -> None:
    op.drop_table("ssp_control_entries", schema="ccf")
    op.drop_table("ssp_projects", schema="ccf")
    op.drop_table("scoring_statuses", schema="ccf")
    op.drop_table("scoring_controls", schema="ccf")
