"""Remediation plans -- the record that a write to an environment was considered.

Every connector before this reads. A plan exists so that a write cannot happen
without one: it is built and persisted first, carries the reversal data
captured at planning time, and records each transition and per-step outcome.

``steps`` is stored rather than recomputed at apply time, deliberately. The plan
that was approved must be the plan that is applied; re-planning would silently
approve a different change.

``result_id`` is ON DELETE SET NULL: retention prunes per-resource detail, and
the record of what was *done about* an observation must outlive the
observation.

Tenancy: ``remediation_plans`` carries ``organization_id`` and gets the direct
``organization_id = ccf.current_tenant()`` policy, so it joins
``EXPECTED_TENANT_ISOLATION_TABLES`` (count 133 -> 134) and is NOT added to
``GLOBAL_TABLES``.

Revision ID: 0072_remediation_plans
Revises: 0071_pack_sources
Create Date: 2026-09-15
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0072_remediation_plans"
down_revision = "0071_pack_sources"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"
_PREDICATE = "(ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant())"


def upgrade() -> None:
    op.create_table(
        "remediation_plans",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "system_id",
            sa.Integer(),
            sa.ForeignKey("ccf.systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("check_key", sa.String(length=128), nullable=False),
        sa.Column("provider_key", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False, server_default="draft"),
        sa.Column(
            "steps",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "outcomes",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("resource_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("refusal_reason", sa.Text(), nullable=True),
        sa.Column("requested_by", sa.String(length=255), nullable=True),
        sa.Column("approved_by", sa.String(length=255), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reversed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "result_id",
            sa.BigInteger(),
            sa.ForeignKey("ccf.control_test_results.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('draft', 'pending_approval', 'approved', 'applied', "
            "'failed', 'reversed', 'refused', 'rejected')",
            name="ck_remediation_plan_status",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_ccf_remediation_plans_org", "remediation_plans", ["organization_id"], schema=_SCHEMA
    )
    op.create_index(
        "ix_ccf_remediation_plans_system", "remediation_plans", ["system_id"], schema=_SCHEMA
    )
    op.create_index(
        "ix_ccf_remediation_plans_check", "remediation_plans", ["check_key"], schema=_SCHEMA
    )
    op.create_index(
        "ix_ccf_remediation_plans_status", "remediation_plans", ["status"], schema=_SCHEMA
    )

    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    op.execute("ALTER TABLE ccf.remediation_plans ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE ccf.remediation_plans FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON ccf.remediation_plans "
        f"FOR ALL USING {_PREDICATE} WITH CHECK {_PREDICATE}"
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON ccf.remediation_plans")
    op.drop_table("remediation_plans", schema=_SCHEMA)
