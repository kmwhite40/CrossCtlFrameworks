"""Assessor workflow — per-control assessment results.

Revision ID: 0009_assessment_results
Revises: 0008_ssp_project_org
Create Date: 2026-06-14
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0009_assessment_results"
down_revision = "0008_ssp_project_org"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "assessment_control_results",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "assessment_id",
            sa.Integer,
            sa.ForeignKey("ccf.assessments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("control_id", sa.String(32), nullable=False),
        sa.Column("nist_id", sa.String(16)),
        sa.Column("domain", sa.String(8)),
        sa.Column("title", sa.String(512)),
        sa.Column("requirement", sa.Text),
        sa.Column("finding", sa.String(32), nullable=False, server_default="not_assessed"),
        sa.Column("objective_findings", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("examine_note", sa.Text),
        sa.Column("interview_note", sa.Text),
        sa.Column("test_note", sa.Text),
        sa.Column("assessor_note", sa.Text),
        sa.Column("evidence_ref", sa.String(1024)),
        sa.Column("reviewed", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("reviewer", sa.String(255)),
        sa.Column("observed_on", sa.Date),
        sa.Column("sort_order", sa.Integer, nullable=False, server_default="0"),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("assessment_id", "control_id", name="uq_assess_ctrl"),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_assess_ctrl_assessment",
        "assessment_control_results",
        ["assessment_id"],
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_assess_ctrl_control", "assessment_control_results", ["control_id"], schema="ccf"
    )
    op.create_index(
        "ix_assess_ctrl_assessment_sort",
        "assessment_control_results",
        ["assessment_id", "sort_order"],
        schema="ccf",
    )


def downgrade() -> None:
    op.drop_table("assessment_control_results", schema="ccf")
