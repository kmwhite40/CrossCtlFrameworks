"""Typed agentic GRC action layer.

Adds ``ai_action_definitions`` (global registry mirror) and the tenant-owned run
tables (runs, inputs, outputs, citations, reviews, evaluations, approved mutations,
guardrail violations). Org-scoped rows filter directly; per-run children filter via
the parent run.

Revision ID: 0032_ai_actions
Revises: 0031_authorization_packages
Create Date: 2026-07-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0032_ai_actions"
down_revision = "0031_authorization_packages"
branch_labels = None
depends_on = None

JB = postgresql.JSONB
_ORG = "organization_id = ccf.current_tenant()"
_RUN = (
    "run_id IN (SELECT id FROM ccf.ai_action_runs WHERE organization_id = ccf.current_tenant())"
)
_POLICIES = {
    "ai_action_runs": _ORG,
    "ai_approved_mutations": _ORG,
    "ai_guardrail_violations": _ORG,
    "ai_action_inputs": _RUN,
    "ai_action_outputs": _RUN,
    "ai_action_citations": _RUN,
    "ai_action_reviews": _RUN,
    "ai_action_evaluations": _RUN,
}


def _org_col() -> sa.Column:
    return sa.Column(
        "organization_id", sa.Integer, sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE")
    )


def _run_fk() -> sa.Column:
    return sa.Column(
        "run_id", sa.BigInteger,
        sa.ForeignKey("ccf.ai_action_runs.id", ondelete="CASCADE"), nullable=False,
    )


def upgrade() -> None:
    op.create_table(
        "ai_action_definitions",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("action_key", sa.String(64), nullable=False, unique=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("input_entity_types", JB, server_default="[]", nullable=False),
        sa.Column("requires_approval", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("citation_required", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("allowed_mutation", sa.String(64)),
        sa.Column("output_kind", sa.String(32), nullable=False, server_default="text"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )

    op.create_table(
        "ai_action_runs",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _org_col(),
        sa.Column("action_key", sa.String(64), nullable=False),
        sa.Column("entity_type", sa.String(48)),
        sa.Column("entity_id", sa.String(128)),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending_review"),
        sa.Column("provider", sa.String(24), nullable=False, server_default="stub"),
        sa.Column("prompt_version", sa.String(24), nullable=False, server_default="v1"),
        sa.Column("input_hash", sa.String(64)),
        sa.Column("output_hash", sa.String(64)),
        sa.Column("actor", sa.String(255)),
        sa.Column("reviewer", sa.String(255)),
        sa.Column("disposition", sa.String(24)),
        sa.Column("mutation_applied", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("summary", JB, server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("decided_at", sa.DateTime(timezone=True)),
        schema="ccf",
    )
    op.create_index("ix_ccf_ai_runs_org", "ai_action_runs", ["organization_id"], schema="ccf")
    op.create_index("ix_ccf_ai_runs_action", "ai_action_runs", ["action_key"], schema="ccf")

    op.create_table(
        "ai_action_inputs",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _run_fk(),
        sa.Column("entity_type", sa.String(48)),
        sa.Column("entity_id", sa.String(128)),
        sa.Column("payload", JB, server_default="{}", nullable=False),
        sa.Column("hash", sa.String(64)),
        schema="ccf",
    )
    op.create_index("ix_ccf_ai_inputs_run", "ai_action_inputs", ["run_id"], schema="ccf")

    op.create_table(
        "ai_action_outputs",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _run_fk(),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("uncited", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("payload", JB, server_default="{}", nullable=False),
        sa.Column("hash", sa.String(64)),
        schema="ccf",
    )
    op.create_index("ix_ccf_ai_outputs_run", "ai_action_outputs", ["run_id"], schema="ccf")

    op.create_table(
        "ai_action_citations",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _run_fk(),
        sa.Column("source_type", sa.String(48), nullable=False),
        sa.Column("source_id", sa.String(128)),
        sa.Column("label", sa.String(512)),
        sa.Column("note", sa.Text),
        schema="ccf",
    )
    op.create_index("ix_ccf_ai_citations_run", "ai_action_citations", ["run_id"], schema="ccf")

    op.create_table(
        "ai_action_reviews",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _run_fk(),
        sa.Column("reviewer", sa.String(255)),
        sa.Column("decision", sa.String(16), nullable=False),
        sa.Column("note", sa.Text),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index("ix_ccf_ai_reviews_run", "ai_action_reviews", ["run_id"], schema="ccf")

    op.create_table(
        "ai_action_evaluations",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _run_fk(),
        sa.Column("metric", sa.String(48), nullable=False),
        sa.Column("value", sa.String(128)),
        sa.Column("note", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index("ix_ccf_ai_evals_run", "ai_action_evaluations", ["run_id"], schema="ccf")

    op.create_table(
        "ai_approved_mutations",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _org_col(),
        _run_fk(),
        sa.Column("mutation_type", sa.String(64), nullable=False),
        sa.Column("target_type", sa.String(48)),
        sa.Column("target_id", sa.String(128)),
        sa.Column("approved_by", sa.String(255)),
        sa.Column("payload", JB, server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_ai_mutations_org", "ai_approved_mutations", ["organization_id"], schema="ccf"
    )

    op.create_table(
        "ai_guardrail_violations",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _org_col(),
        sa.Column("run_id", sa.BigInteger),
        sa.Column("kind", sa.String(48), nullable=False),
        sa.Column("detail", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_ai_violations_org", "ai_guardrail_violations", ["organization_id"], schema="ccf"
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
    op.drop_table("ai_guardrail_violations", schema="ccf")
    op.drop_table("ai_approved_mutations", schema="ccf")
    op.drop_table("ai_action_evaluations", schema="ccf")
    op.drop_table("ai_action_reviews", schema="ccf")
    op.drop_table("ai_action_citations", schema="ccf")
    op.drop_table("ai_action_outputs", schema="ccf")
    op.drop_table("ai_action_inputs", schema="ccf")
    op.drop_table("ai_action_runs", schema="ccf")
    op.drop_table("ai_action_definitions", schema="ccf")
