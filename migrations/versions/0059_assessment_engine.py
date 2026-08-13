"""Objective-level assessment engine — proposal and job tables.

Proposals are inert until an assessor accepts them, so these tables never feed the
SAR or POA&M creation directly; acceptance projects into assessment_control_results.
Objectives themselves are not stored -- they are read from ccf.controls sub-clause
rows -- so only a label and a SHA-256 of the objective text are kept here.

Revision ID: 0059_assessment_engine
Revises: 0058_prep_grants_gin
Create Date: 2026-08-10
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0059_assessment_engine"
down_revision = "0058_prep_grants_gin"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"
JB = postgresql.JSONB


def upgrade() -> None:
    op.create_table(
        "assessment_control_proposals",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey(f"{_SCHEMA}.organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "assessment_id",
            sa.Integer(),
            sa.ForeignKey(f"{_SCHEMA}.assessments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("control_identifier", sa.String(64), nullable=False),
        sa.Column("state", sa.String(16), nullable=False, server_default="draft"),
        sa.Column("proposed_finding", sa.String(32)),
        sa.Column("rollup_rationale", sa.Text()),
        sa.Column("config_snapshot", JB, nullable=False, server_default=sa.text("'{}'")),
        sa.Column("objectives_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("objectives_evaluated", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("accepted_by", sa.String(255)),
        sa.Column("accepted_at", sa.DateTime(timezone=True)),
        sa.Column("error", sa.Text()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "assessment_id",
            "control_identifier",
            name="uq_control_proposal_assessment_control",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_assessment_control_proposals_organization_id",
        "assessment_control_proposals",
        ["organization_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_assessment_control_proposals_assessment_id",
        "assessment_control_proposals",
        ["assessment_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_assessment_control_proposals_control_identifier",
        "assessment_control_proposals",
        ["control_identifier"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_assessment_control_proposals_state",
        "assessment_control_proposals",
        ["state"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_control_proposal_state",
        "assessment_control_proposals",
        ["organization_id", "state"],
        schema=_SCHEMA,
    )

    op.create_table(
        "assessment_objective_proposals",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey(f"{_SCHEMA}.organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "control_proposal_id",
            sa.BigInteger(),
            sa.ForeignKey(f"{_SCHEMA}.assessment_control_proposals.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("label", sa.String(64), nullable=False),
        sa.Column("objective_text", sa.Text(), nullable=False),
        sa.Column("objective_text_sha256", sa.String(64), nullable=False),
        sa.Column("sort_order", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("state", sa.String(16), nullable=False, server_default="complete"),
        sa.Column("verdict", sa.String(32)),
        sa.Column("cited_unit_ids", JB, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("retrieved_unit_ids", JB, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("gaps", JB, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("contradictions", JB, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("rationale", sa.Text()),
        sa.Column("model_name", sa.String(128)),
        sa.Column("model_confidence", sa.Float()),
        sa.Column("error", sa.Text()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "control_proposal_id", "label", name="uq_objective_proposal_label"
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_assessment_objective_proposals_organization_id",
        "assessment_objective_proposals",
        ["organization_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_assessment_objective_proposals_control_proposal_id",
        "assessment_objective_proposals",
        ["control_proposal_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_objective_proposal_sort",
        "assessment_objective_proposals",
        ["control_proposal_id", "sort_order"],
        schema=_SCHEMA,
    )

    op.create_table(
        "assessment_jobs",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey(f"{_SCHEMA}.organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "control_proposal_id",
            sa.BigInteger(),
            sa.ForeignKey(f"{_SCHEMA}.assessment_control_proposals.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("claimed_at", sa.DateTime(timezone=True)),
        sa.Column("claimed_by", sa.String(128)),
        sa.Column("last_error", sa.Text()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_assessment_jobs_organization_id",
        "assessment_jobs",
        ["organization_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_assessment_jobs_control_proposal_id",
        "assessment_jobs",
        ["control_proposal_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_assessment_jobs_status", "assessment_jobs", ["status"], schema=_SCHEMA
    )
    op.create_index(
        "ix_assessment_jobs_claimable",
        "assessment_jobs",
        ["status", "created_at"],
        schema=_SCHEMA,
    )

    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app")


def downgrade() -> None:
    op.drop_table("assessment_jobs", schema=_SCHEMA)
    op.drop_table("assessment_objective_proposals", schema=_SCHEMA)
    op.drop_table("assessment_control_proposals", schema=_SCHEMA)
