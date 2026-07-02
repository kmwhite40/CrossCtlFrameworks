"""Vendor security questionnaires (CAIQ/SIG) — third-party risk assessment.

Adds ``questionnaire_templates`` (reusable weighted question sets),
``vendor_questionnaires`` (one assessment of a vendor → scored posture + risk
rating), and ``questionnaire_responses`` (per-question answers). All
tenant-isolated under the standard ``ccf.current_tenant()`` RLS policy.

Revision ID: 0026_vendor_questionnaires
Revises: 0025_personnel_access
Create Date: 2026-07-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0026_vendor_questionnaires"
down_revision = "0025_personnel_access"
branch_labels = None
depends_on = None

_ORG = "organization_id = ccf.current_tenant()"
_QNR = (
    "questionnaire_id IN (SELECT id FROM ccf.vendor_questionnaires "
    "WHERE organization_id = ccf.current_tenant())"
)
_POLICIES = {
    "questionnaire_templates": _ORG,
    "vendor_questionnaires": _ORG,
    "questionnaire_responses": _QNR,
}


def upgrade() -> None:
    op.create_table(
        "questionnaire_templates",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer,
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
        ),
        sa.Column("key", sa.String(64), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("framework", sa.String(32)),
        sa.Column("version", sa.String(16), nullable=False, server_default="1.0"),
        sa.Column("questions", postgresql.JSONB, server_default="[]", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_questionnaire_templates_org", "questionnaire_templates",
        ["organization_id"], schema="ccf",
    )
    op.create_index(
        "ix_ccf_questionnaire_templates_key", "questionnaire_templates", ["key"], schema="ccf"
    )

    op.create_table(
        "vendor_questionnaires",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer,
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
        ),
        sa.Column(
            "vendor_id", sa.Integer, sa.ForeignKey("ccf.vendors.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("template_key", sa.String(64)),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="draft"),
        sa.Column("sent_on", sa.Date),
        sa.Column("due_on", sa.Date),
        sa.Column("submitted_on", sa.Date),
        sa.Column("reviewed_on", sa.Date),
        sa.Column("reviewer", sa.String(255)),
        sa.Column("score", sa.Float),
        sa.Column("risk_rating", sa.String(16)),
        sa.Column("summary", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_vendor_questionnaires_org", "vendor_questionnaires",
        ["organization_id"], schema="ccf",
    )
    op.create_index(
        "ix_ccf_vendor_questionnaires_vendor", "vendor_questionnaires",
        ["vendor_id"], schema="ccf",
    )

    op.create_table(
        "questionnaire_responses",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "questionnaire_id",
            sa.Integer,
            sa.ForeignKey("ccf.vendor_questionnaires.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("question_id", sa.String(32), nullable=False),
        sa.Column("domain", sa.String(64)),
        sa.Column("question_text", sa.Text, nullable=False),
        sa.Column("weight", sa.Integer, nullable=False, server_default="1"),
        sa.Column("answer", sa.String(16), nullable=False, server_default="unanswered"),
        sa.Column("detail", sa.Text),
        sa.Column("evidence_ref", sa.String(1024)),
        sa.Column("sort_order", sa.Integer, nullable=False, server_default="0"),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_questionnaire_responses_qnr", "questionnaire_responses",
        ["questionnaire_id"], schema="ccf",
    )

    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ccf.questionnaire_templates, "
        "ccf.vendor_questionnaires, ccf.questionnaire_responses TO ccf_app; "
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
    op.drop_table("questionnaire_responses", schema="ccf")
    op.drop_table("vendor_questionnaires", schema="ccf")
    op.drop_table("questionnaire_templates", schema="ccf")
