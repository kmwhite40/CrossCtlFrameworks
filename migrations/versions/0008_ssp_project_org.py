"""Scope SSP projects to an organization.

Revision ID: 0008_ssp_project_org
Revises: 0007_audit_hash_chain
Create Date: 2026-06-13
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0008_ssp_project_org"
down_revision = "0007_audit_hash_chain"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "ssp_projects",
        sa.Column(
            "organization_id",
            sa.Integer,
            sa.ForeignKey("ccf.organizations.id", ondelete="SET NULL"),
        ),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_ssp_projects_org", "ssp_projects", ["organization_id"], schema="ccf"
    )


def downgrade() -> None:
    op.drop_index("ix_ccf_ssp_projects_org", table_name="ssp_projects", schema="ccf")
    op.drop_column("ssp_projects", "organization_id", schema="ccf")
