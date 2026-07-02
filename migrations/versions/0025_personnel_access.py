"""Personnel & Access layer — workforce security lifecycle.

Adds ``people`` (PS-2 risk designation + PS-3 screening + PS-4/PS-5 lifecycle),
``training_records`` (AT-2/AT-3), and ``access_reviews`` + ``access_review_items``
(AC-2 account certification). All tenant-isolated under the same
``ccf.current_tenant()`` RLS policy as the rest of the operational layer.

Revision ID: 0025_personnel_access
Revises: 0024_control_test_assertion
Create Date: 2026-07-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0025_personnel_access"
down_revision = "0024_control_test_assertion"
branch_labels = None
depends_on = None

_ORG = "organization_id = ccf.current_tenant()"
_REVIEW = (
    "review_id IN (SELECT id FROM ccf.access_reviews "
    "WHERE organization_id = ccf.current_tenant())"
)
_PERSON = "person_id IN (SELECT id FROM ccf.people WHERE organization_id = ccf.current_tenant())"

# table -> tenant predicate (org-scoped rows filter directly; children via parent).
_POLICIES = {
    "people": _ORG,
    "access_reviews": _ORG,
    "training_records": _PERSON,
    "access_review_items": _REVIEW,
}


def upgrade() -> None:
    op.create_table(
        "people",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer,
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
        ),
        sa.Column("full_name", sa.String(255), nullable=False),
        sa.Column("email", sa.String(320)),
        sa.Column("employment_type", sa.String(16), nullable=False, server_default="employee"),
        sa.Column("position", sa.String(255)),
        sa.Column("department", sa.String(255)),
        sa.Column("manager", sa.String(255)),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("start_date", sa.Date),
        sa.Column("end_date", sa.Date),
        sa.Column("risk_designation", sa.String(16), nullable=False, server_default="low"),
        sa.Column(
            "background_check_status", sa.String(16), nullable=False, server_default="not_started"
        ),
        sa.Column("background_check_completed_on", sa.Date),
        sa.Column("notes", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index("ix_ccf_people_org", "people", ["organization_id"], schema="ccf")
    op.create_index("ix_ccf_people_email", "people", ["email"], schema="ccf")

    op.create_table(
        "training_records",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "person_id", sa.Integer, sa.ForeignKey("ccf.people.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("course", sa.String(255), nullable=False),
        sa.Column("kind", sa.String(24), nullable=False, server_default="awareness"),
        sa.Column("control_ref", sa.String(32)),
        sa.Column("assigned_on", sa.Date),
        sa.Column("due_on", sa.Date),
        sa.Column("completed_on", sa.Date),
        sa.Column("status", sa.String(16), nullable=False, server_default="assigned"),
        sa.Column("evidence_ref", sa.String(1024)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_training_records_person", "training_records", ["person_id"], schema="ccf"
    )

    op.create_table(
        "access_reviews",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer,
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
        ),
        sa.Column("system_id", sa.Integer, sa.ForeignKey("ccf.systems.id", ondelete="SET NULL")),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("reviewer", sa.String(255)),
        sa.Column("status", sa.String(16), nullable=False, server_default="open"),
        sa.Column("started_on", sa.Date),
        sa.Column("due_on", sa.Date),
        sa.Column("completed_on", sa.Date),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_access_reviews_org", "access_reviews", ["organization_id"], schema="ccf"
    )

    op.create_table(
        "access_review_items",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "review_id",
            sa.Integer,
            sa.ForeignKey("ccf.access_reviews.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("person_id", sa.Integer, sa.ForeignKey("ccf.people.id", ondelete="SET NULL")),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("resource", sa.String(255)),
        sa.Column("access_level", sa.String(128)),
        sa.Column("decision", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("decided_on", sa.Date),
        sa.Column("note", sa.Text),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_access_review_items_review", "access_review_items", ["review_id"], schema="ccf"
    )

    # Grants + tenant-isolation RLS, matching the operational-layer convention.
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ccf.people, ccf.training_records, "
        "ccf.access_reviews, ccf.access_review_items TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    for table, predicate in _POLICIES.items():
        expr = f"(ccf.current_tenant() IS NULL OR {predicate})"
        op.execute(f"ALTER TABLE ccf.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE ccf.{table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON ccf.{table} "
            f"FOR ALL USING {expr} WITH CHECK {expr}"
        )


def downgrade() -> None:
    for table in _POLICIES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON ccf.{table}")
    op.drop_table("access_review_items", schema="ccf")
    op.drop_table("access_reviews", schema="ccf")
    op.drop_table("training_records", schema="ccf")
    op.drop_table("people", schema="ccf")
