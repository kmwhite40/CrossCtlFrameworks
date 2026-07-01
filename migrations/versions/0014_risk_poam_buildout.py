"""Risk register + POA&M architectural buildout — FedRAMP fields, milestones,
cross-links, ownership, review cadence.

Revision ID: 0014_risk_poam_buildout
Revises: 0013_enterprise_governance
Create Date: 2026-07-01
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0014_risk_poam_buildout"
down_revision = "0013_enterprise_governance"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- POA&M FedRAMP/eMASS fields --------------------------------------
    for col in [
        sa.Column("source", sa.String(32)),
        sa.Column("point_of_contact", sa.String(255)),
        sa.Column("remediation_plan", sa.Text),
        sa.Column("resources_required", sa.Text),
        sa.Column("cost_estimate", sa.String(64)),
        sa.Column("scheduled_completion", sa.Date),
        sa.Column("original_due_on", sa.Date),
        sa.Column("risk_id", sa.Integer, sa.ForeignKey("ccf.risks.id", ondelete="SET NULL")),
        sa.Column("vendor_id", sa.Integer, sa.ForeignKey("ccf.vendors.id", ondelete="SET NULL")),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    ]:
        op.add_column("poams", col, schema="ccf")

    op.create_table(
        "poam_milestones",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "poam_id", sa.Integer, sa.ForeignKey("ccf.poams.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("due_on", sa.Date),
        sa.Column("completed_on", sa.Date),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("sort_order", sa.Integer, nullable=False, server_default="0"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        schema="ccf",
    )
    op.create_index("ix_ccf_poam_milestones_poam", "poam_milestones", ["poam_id"], schema="ccf")

    # --- Risk register buildout ------------------------------------------
    for col in [
        sa.Column("category", sa.String(64)),
        sa.Column("source", sa.String(32)),
        sa.Column("owner_user_id", sa.Integer, sa.ForeignKey("ccf.users.id", ondelete="SET NULL")),
        sa.Column("next_review_on", sa.Date),
        sa.Column("control_id", sa.Integer, sa.ForeignKey("ccf.controls.id", ondelete="SET NULL")),
        sa.Column("vendor_id", sa.Integer, sa.ForeignKey("ccf.vendors.id", ondelete="SET NULL")),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    ]:
        op.add_column("risks", col, schema="ccf")


def downgrade() -> None:
    for name in (
        "updated_at",
        "vendor_id",
        "control_id",
        "next_review_on",
        "owner_user_id",
        "source",
        "category",
    ):
        op.drop_column("risks", name, schema="ccf")
    op.drop_table("poam_milestones", schema="ccf")
    for name in (
        "updated_at",
        "vendor_id",
        "risk_id",
        "original_due_on",
        "scheduled_completion",
        "cost_estimate",
        "resources_required",
        "remediation_plan",
        "point_of_contact",
        "source",
    ):
        op.drop_column("poams", name, schema="ccf")
