"""Flaw-remediation policy and patch campaigns.

SI-2 requires flaws remediated within an organization-defined period. That
parameter previously existed only as free text in an SSP template, so nothing
compared it to what happened. ``remediation_policies`` gives it a structured
home, defaulting to FedRAMP's timeframes so a deployment that never sets one is
still measured against the numbers an assessor expects.

``patch_campaigns`` and ``patch_waves`` organize the work: ordered batches with
a window, smallest first, so the blast radius of a bad patch is bounded by the
wave. A wave RECORDS completion; it does not cause it -- Concord has no
endpoint-management provider, so a wave carries an evidence reference or points
at an enforcement plan when a deployment supplies one.

``patch_waves.poam_ids`` is stored rather than re-derived at completion time:
the batch someone scheduled is the batch they completed, and re-deriving would
silently change what was claimed.

Tenancy: ``remediation_policies`` and ``patch_campaigns`` carry
``organization_id`` and get the direct ``current_tenant()`` policy.
``patch_waves`` carries none -- it is policied through its parent campaign, the
same parent-chain shape ``control_test_resource_results`` uses. All three join
``EXPECTED_TENANT_ISOLATION_TABLES`` (count 134 -> 137); none is added to
``GLOBAL_TABLES``.

Revision ID: 0076_flaw_remediation
Revises: 0075_remediation_plans
Create Date: 2026-09-15
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0076_flaw_remediation"
down_revision = "0075_remediation_plans"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"
_PREDICATE = "(ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant())"
#: Waves inherit their tenant from the campaign.
_WAVE_PREDICATE = (
    "(ccf.current_tenant() IS NULL OR EXISTS ("
    "SELECT 1 FROM ccf.patch_campaigns c "
    "WHERE c.id = patch_waves.campaign_id "
    "AND (c.organization_id = ccf.current_tenant())))"
)


def upgrade() -> None:
    op.create_table(
        "remediation_policies",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("critical_days", sa.Integer(), nullable=False, server_default="30"),
        sa.Column("high_days", sa.Integer(), nullable=False, server_default="30"),
        sa.Column("moderate_days", sa.Integer(), nullable=False, server_default="90"),
        sa.Column("low_days", sa.Integer(), nullable=False, server_default="180"),
        sa.Column("source", sa.String(length=128), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.UniqueConstraint("organization_id", name="uq_remediation_policy_org"),
        sa.CheckConstraint(
            "critical_days > 0 AND high_days > 0 AND moderate_days > 0 AND low_days > 0",
            name="ck_remediation_policy_positive",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_ccf_remediation_policies_org", "remediation_policies", ["organization_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "patch_campaigns",
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
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="planned"),
        sa.Column("window_start", sa.Date(), nullable=False),
        sa.Column("window_end", sa.Date(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('planned', 'in_progress', 'completed', 'cancelled')",
            name="ck_patch_campaign_status",
        ),
        sa.CheckConstraint("window_end >= window_start", name="ck_patch_campaign_window"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_ccf_patch_campaigns_org", "patch_campaigns", ["organization_id"], schema=_SCHEMA
    )
    op.create_index(
        "ix_ccf_patch_campaigns_system", "patch_campaigns", ["system_id"], schema=_SCHEMA
    )
    op.create_index(
        "ix_ccf_patch_campaigns_status", "patch_campaigns", ["status"], schema=_SCHEMA
    )

    op.create_table(
        "patch_waves",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "campaign_id",
            sa.BigInteger(),
            sa.ForeignKey("ccf.patch_campaigns.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="pending"),
        sa.Column(
            "poam_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("window_start", sa.Date(), nullable=True),
        sa.Column("window_end", sa.Date(), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_by", sa.String(length=255), nullable=True),
        sa.Column("evidence_ref", sa.String(length=512), nullable=True),
        sa.Column(
            "remediation_plan_id",
            sa.BigInteger(),
            sa.ForeignKey("ccf.remediation_plans.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.UniqueConstraint("campaign_id", "sequence", name="uq_patch_wave_sequence"),
        sa.CheckConstraint(
            "status IN ('pending', 'completed', 'skipped')", name="ck_patch_wave_status"
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_ccf_patch_waves_campaign", "patch_waves", ["campaign_id"], schema=_SCHEMA
    )
    op.create_index("ix_ccf_patch_waves_status", "patch_waves", ["status"], schema=_SCHEMA)

    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    for table in ("remediation_policies", "patch_campaigns"):
        op.execute(f"ALTER TABLE ccf.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE ccf.{table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON ccf.{table} "
            f"FOR ALL USING {_PREDICATE} WITH CHECK {_PREDICATE}"
        )
    op.execute("ALTER TABLE ccf.patch_waves ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE ccf.patch_waves FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON ccf.patch_waves "
        f"FOR ALL USING {_WAVE_PREDICATE} WITH CHECK {_WAVE_PREDICATE}"
    )


def downgrade() -> None:
    for table in ("patch_waves", "patch_campaigns", "remediation_policies"):
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON ccf.{table}")
    op.drop_table("patch_waves", schema=_SCHEMA)
    op.drop_table("patch_campaigns", schema=_SCHEMA)
    op.drop_table("remediation_policies", schema=_SCHEMA)
