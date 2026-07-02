"""System profile (intake questionnaire) + uploadable framework controls —
the keystone for profile-driven applicability, inheritance, and scoring.

Revision ID: 0015_system_profile_automation
Revises: 0014_risk_poam_buildout
Create Date: 2026-07-01
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0015_system_profile_automation"
down_revision = "0014_risk_poam_buildout"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "system_profiles",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "system_id",
            sa.Integer,
            sa.ForeignKey("ccf.systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("environment_type", sa.String(32)),
        sa.Column("cloud_platform", sa.String(32)),
        sa.Column("tenant_ref", sa.String(255)),
        sa.Column("identity_model", sa.String(32)),
        sa.Column("connectivity", sa.String(32)),
        sa.Column("cui_present", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("workloads", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("endpoint_scope", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("data_types", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("inherited_sources", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("frameworks", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("answers", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("derivation", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("derived_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("system_id", name="uq_system_profile_system"),
        schema="ccf",
    )
    op.create_index("ix_ccf_system_profiles_system", "system_profiles", ["system_id"], schema="ccf")

    op.create_table(
        "framework_controls",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("framework_code", sa.String(64), nullable=False),
        sa.Column("identifier", sa.String(128), nullable=False),
        sa.Column("title", sa.String(512)),
        sa.Column("description", sa.Text),
        sa.Column("family", sa.String(64)),
        sa.Column("baseline", sa.String(32)),
        sa.Column("default_responsibility", sa.String(16)),
        sa.Column("metadata_json", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("source", sa.String(255)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("framework_code", "identifier", name="uq_framework_control"),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_framework_controls_code", "framework_controls", ["framework_code"], schema="ccf"
    )
    op.create_index(
        "ix_ccf_framework_controls_ident", "framework_controls", ["identifier"], schema="ccf"
    )


def downgrade() -> None:
    op.drop_table("framework_controls", schema="ccf")
    op.drop_table("system_profiles", schema="ccf")
