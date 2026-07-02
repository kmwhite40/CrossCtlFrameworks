"""AI agent governance.

Adds ``ai_agents`` + risk assessments + approvals + monitoring events + incidents
+ kill-switch events, all tenant-isolated by ``organization_id``.

Revision ID: 0033_ai_agents
Revises: 0032_ai_actions
Create Date: 2026-07-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0033_ai_agents"
down_revision = "0032_ai_actions"
branch_labels = None
depends_on = None

JB = postgresql.JSONB
_ORG = "organization_id = ccf.current_tenant()"
_POLICIES = {
    "ai_agents": _ORG,
    "ai_agent_risk_assessments": _ORG,
    "ai_agent_approvals": _ORG,
    "ai_agent_monitoring_events": _ORG,
    "ai_agent_incidents": _ORG,
    "ai_agent_kill_switch_events": _ORG,
}


def _org_col() -> sa.Column:
    return sa.Column(
        "organization_id", sa.Integer, sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE")
    )


def _agent_fk() -> sa.Column:
    return sa.Column(
        "agent_id", sa.Integer, sa.ForeignKey("ccf.ai_agents.id", ondelete="CASCADE"),
        nullable=False,
    )


def upgrade() -> None:
    op.create_table(
        "ai_agents",
        sa.Column("id", sa.Integer, primary_key=True),
        _org_col(),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("owner", sa.String(255)),
        sa.Column("business_purpose", sa.Text),
        sa.Column("system_id", sa.Integer, sa.ForeignKey("ccf.systems.id", ondelete="SET NULL")),
        sa.Column("model_provider", sa.String(128)),
        sa.Column("vendor_id", sa.Integer, sa.ForeignKey("ccf.vendors.id", ondelete="SET NULL")),
        sa.Column("autonomy_level", sa.String(16), nullable=False, server_default="low"),
        sa.Column("human_oversight", sa.String(24), nullable=False, server_default="human_in_loop"),
        sa.Column("external_action_capability", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("external_communication", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("production_access", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("regulated_data_access", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("data_classification", sa.String(32)),
        sa.Column("financial_impact", sa.String(16), nullable=False, server_default="low"),
        sa.Column("operational_impact", sa.String(16), nullable=False, server_default="low"),
        sa.Column("monitoring_coverage", sa.String(16), nullable=False, server_default="none"),
        sa.Column("evaluation_coverage", sa.String(16), nullable=False, server_default="none"),
        sa.Column("tools", JB, server_default="[]", nullable=False),
        sa.Column("data_stores", JB, server_default="[]", nullable=False),
        sa.Column("permissions", JB, server_default="[]", nullable=False),
        sa.Column("system_ids", JB, server_default="[]", nullable=False),
        sa.Column("vendor_ids", JB, server_default="[]", nullable=False),
        sa.Column("policy_ids", JB, server_default="[]", nullable=False),
        sa.Column("control_ids", JB, server_default="[]", nullable=False),
        sa.Column("risk_ids", JB, server_default="[]", nullable=False),
        sa.Column("approval_status", sa.String(16), nullable=False, server_default="draft"),
        sa.Column("risk_rating", sa.String(16)),
        sa.Column("risk_score", sa.Float),
        sa.Column("review_frequency", sa.String(32)),
        sa.Column("last_reviewed_on", sa.Date),
        sa.Column("next_review_on", sa.Date),
        sa.Column("kill_switch_status", sa.String(16), nullable=False, server_default="ready"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index("ix_ccf_ai_agents_org", "ai_agents", ["organization_id"], schema="ccf")

    op.create_table(
        "ai_agent_risk_assessments",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _org_col(),
        _agent_fk(),
        sa.Column("score", sa.Float, nullable=False, server_default="0"),
        sa.Column("rating", sa.String(16), nullable=False, server_default="low"),
        sa.Column("factors", JB, server_default="{}", nullable=False),
        sa.Column("assessed_by", sa.String(255)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_ai_agent_ra_agent", "ai_agent_risk_assessments", ["agent_id"], schema="ccf"
    )

    op.create_table(
        "ai_agent_approvals",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _org_col(),
        _agent_fk(),
        sa.Column("decision", sa.String(16), nullable=False),
        sa.Column("reviewer", sa.String(255)),
        sa.Column("note", sa.Text),
        sa.Column("decided_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_ai_agent_appr_agent", "ai_agent_approvals", ["agent_id"], schema="ccf"
    )

    op.create_table(
        "ai_agent_monitoring_events",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _org_col(),
        _agent_fk(),
        sa.Column("event_type", sa.String(48), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False, server_default="info"),
        sa.Column("detail", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_ai_agent_mon_agent", "ai_agent_monitoring_events", ["agent_id"], schema="ccf"
    )

    op.create_table(
        "ai_agent_incidents",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _org_col(),
        _agent_fk(),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False, server_default="moderate"),
        sa.Column("status", sa.String(16), nullable=False, server_default="open"),
        sa.Column("detail", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_ai_agent_inc_agent", "ai_agent_incidents", ["agent_id"], schema="ccf"
    )

    op.create_table(
        "ai_agent_kill_switch_events",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _org_col(),
        _agent_fk(),
        sa.Column("action", sa.String(16), nullable=False, server_default="engage"),
        sa.Column("reason", sa.Text),
        sa.Column("actor", sa.String(255)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_ai_agent_ks_agent", "ai_agent_kill_switch_events", ["agent_id"], schema="ccf"
    )

    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
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
    op.drop_table("ai_agent_kill_switch_events", schema="ccf")
    op.drop_table("ai_agent_incidents", schema="ccf")
    op.drop_table("ai_agent_monitoring_events", schema="ccf")
    op.drop_table("ai_agent_approvals", schema="ccf")
    op.drop_table("ai_agent_risk_assessments", schema="ccf")
    op.drop_table("ai_agents", schema="ccf")
