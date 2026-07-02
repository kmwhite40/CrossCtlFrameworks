"""GRC operating-system layer — Trust Center, Regulatory Change, Audit
Workspace, Connector registry, and Control Tests.

Revision ID: 0021_grc_os
Revises: 0020_fedramp_20x_rls
Create Date: 2026-07-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0021_grc_os"
down_revision = "0020_fedramp_20x_rls"
branch_labels = None
depends_on = None

JB = postgresql.JSONB
TS = sa.DateTime(timezone=True)


def _org() -> sa.Column:
    return sa.Column(
        "organization_id", sa.Integer, sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE")
    )


def _created() -> sa.Column:
    return sa.Column("created_at", TS, server_default=sa.func.now(), nullable=False)


def upgrade() -> None:
    op.create_table(
        "trust_profiles",
        sa.Column("id", sa.Integer, primary_key=True),
        _org(),
        sa.Column("headline", sa.String(255)),
        sa.Column("summary", sa.Text),
        sa.Column("framework_badges", JB, nullable=False, server_default="[]"),
        sa.Column("approved_reports", JB, nullable=False, server_default="[]"),
        sa.Column("approved_policies", JB, nullable=False, server_default="[]"),
        sa.Column("approved_evidence", JB, nullable=False, server_default="[]"),
        sa.Column("faq", JB, nullable=False, server_default="[]"),
        sa.Column("published", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("updated_at", TS, server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("organization_id", name="uq_trust_profile_org"),
        schema="ccf",
    )
    op.create_table(
        "trust_access_requests",
        sa.Column("id", sa.Integer, primary_key=True),
        _org(),
        sa.Column("requester_name", sa.String(255), nullable=False),
        sa.Column("email", sa.String(255)),
        sa.Column("company", sa.String(255)),
        sa.Column("reason", sa.Text),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("decided_by", sa.String(255)),
        sa.Column("decided_at", TS),
        _created(),
        schema="ccf",
    )
    op.create_table(
        "regulatory_updates",
        sa.Column("id", sa.Integer, primary_key=True),
        _org(),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("source", sa.String(255)),
        sa.Column("framework_impacted", sa.String(64)),
        sa.Column("requirement_impacted", sa.String(255)),
        sa.Column("summary", sa.Text),
        sa.Column("applicability", sa.String(24), nullable=False, server_default="assessing"),
        sa.Column("control_impact", sa.Text),
        sa.Column("policy_impact", sa.Text),
        sa.Column("system_impact", sa.Text),
        sa.Column("owner", sa.String(255)),
        sa.Column("due_on", sa.Date),
        sa.Column("status", sa.String(16), nullable=False, server_default="new"),
        _created(),
        sa.Column("updated_at", TS, server_default=sa.func.now(), nullable=False),
        schema="ccf",
    )
    op.create_table(
        "audit_engagements",
        sa.Column("id", sa.Integer, primary_key=True),
        _org(),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("auditor_org", sa.String(255)),
        sa.Column("framework", sa.String(64)),
        sa.Column("scope", sa.Text),
        sa.Column("systems", JB, nullable=False, server_default="[]"),
        sa.Column("status", sa.String(16), nullable=False, server_default="planning"),
        sa.Column("started_on", sa.Date),
        sa.Column("target_on", sa.Date),
        _created(),
        schema="ccf",
    )
    op.create_table(
        "audit_requests",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "engagement_id",
            sa.Integer,
            sa.ForeignKey("ccf.audit_engagements.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("owner_user_id", sa.Integer, sa.ForeignKey("ccf.users.id", ondelete="SET NULL")),
        sa.Column("due_on", sa.Date),
        sa.Column("status", sa.String(16), nullable=False, server_default="open"),
        sa.Column("auditor_note", sa.Text),
        sa.Column("internal_note", sa.Text),
        sa.Column("evidence_ref", sa.String(1024)),
        _created(),
        schema="ccf",
    )
    op.create_index("ix_ccf_audit_requests_eng", "audit_requests", ["engagement_id"], schema="ccf")
    op.create_table(
        "audit_findings",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "engagement_id",
            sa.Integer,
            sa.ForeignKey("ccf.audit_engagements.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False, server_default="moderate"),
        sa.Column("status", sa.String(24), nullable=False, server_default="open"),
        sa.Column("description", sa.Text),
        sa.Column("management_response", sa.Text),
        sa.Column("closure_evidence", sa.String(1024)),
        _created(),
        schema="ccf",
    )
    op.create_index("ix_ccf_audit_findings_eng", "audit_findings", ["engagement_id"], schema="ccf")
    op.create_table(
        "connector_configs",
        sa.Column("id", sa.Integer, primary_key=True),
        _org(),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("connector_type", sa.String(32), nullable=False),
        sa.Column("environment", sa.String(64)),
        sa.Column("auth_method", sa.String(64)),
        sa.Column("status", sa.String(16), nullable=False, server_default="not_configured"),
        sa.Column("last_sync", TS),
        sa.Column("error_message", sa.Text),
        sa.Column("objects_discovered", sa.Integer, nullable=False, server_default="0"),
        sa.Column("evidence_produced", sa.Integer, nullable=False, server_default="0"),
        sa.Column("controls_impacted", JB, nullable=False, server_default="[]"),
        sa.Column("config", JB, nullable=False, server_default="{}"),
        _created(),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_connector_configs_type", "connector_configs", ["connector_type"], schema="ccf"
    )
    op.create_table(
        "control_tests",
        sa.Column("id", sa.Integer, primary_key=True),
        _org(),
        sa.Column("system_id", sa.Integer, sa.ForeignKey("ccf.systems.id", ondelete="CASCADE")),
        sa.Column("control_id", sa.String(64), nullable=False),
        sa.Column("name", sa.String(512), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("method", sa.String(16), nullable=False, server_default="manual"),
        sa.Column("connector_type", sa.String(32)),
        sa.Column("frequency", sa.String(32)),
        sa.Column("expected", sa.Text),
        sa.Column("active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("last_status", sa.String(8)),
        sa.Column("last_tested_at", TS),
        _created(),
        schema="ccf",
    )
    op.create_index("ix_ccf_control_tests_control", "control_tests", ["control_id"], schema="ccf")
    op.create_table(
        "control_test_results",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "control_test_id",
            sa.Integer,
            sa.ForeignKey("ccf.control_tests.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("run_at", TS, server_default=sa.func.now(), nullable=False),
        sa.Column("status", sa.String(8), nullable=False),
        sa.Column("detail", sa.Text),
        sa.Column("evidence_ref", sa.String(1024)),
        schema="ccf",
    )
    op.create_index(
        "ix_control_test_results_test_run",
        "control_test_results",
        ["control_test_id", "run_at"],
        schema="ccf",
    )


def downgrade() -> None:
    for t in (
        "control_test_results",
        "control_tests",
        "connector_configs",
        "audit_findings",
        "audit_requests",
        "audit_engagements",
        "regulatory_updates",
        "trust_access_requests",
        "trust_profiles",
    ):
        op.drop_table(t, schema="ccf")
