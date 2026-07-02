"""FedRAMP 20x layer — Key Security Indicators (KSIs), CSO profile, KSI state,
validation history, assessor review, exceptions, authorized-dependency tracking,
and readiness snapshots. Additive and backward-compatible; kept logically separate
from the traditional FedRAMP Rev. 5 baseline/scoring tables.

Revision ID: 0019_fedramp_20x
Revises: 0018_ssp_enterprise
Create Date: 2026-07-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0019_fedramp_20x"
down_revision = "0018_ssp_enterprise"
branch_labels = None
depends_on = None

_now = sa.func.now()


def upgrade() -> None:
    # KSI reference catalog (org-agnostic, like scoring_controls).
    op.create_table(
        "ksis",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("identifier", sa.String(32), nullable=False),
        sa.Column("category", sa.String(8), nullable=False),
        sa.Column("category_name", sa.String(128)),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("expected_outcome", sa.Text),
        sa.Column("validation_method", sa.String(32)),
        sa.Column("validation_frequency", sa.String(32)),
        sa.Column("automation_level", sa.String(32)),
        sa.Column("evidence_required", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("nist_refs", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("cmmc_refs", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("provider_services", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("rule", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("sort_order", sa.Integer, nullable=False, server_default="0"),
        sa.Column("source", sa.String(255)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=_now, nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=_now, nullable=False),
        sa.UniqueConstraint("identifier", name="uq_ksi_identifier"),
        schema="ccf",
    )
    op.create_index("ix_ccf_ksis_identifier", "ksis", ["identifier"], schema="ccf")
    op.create_index("ix_ccf_ksis_category", "ksis", ["category"], schema="ccf")

    # Cloud Service Offering profile (one per system).
    op.create_table(
        "fedramp20x_profiles",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "system_id",
            sa.Integer,
            sa.ForeignKey("ccf.systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("service_name", sa.String(255)),
        sa.Column("service_description", sa.Text),
        sa.Column("deployment_model", sa.String(32)),
        sa.Column("cloud_environment", sa.String(48)),
        sa.Column("boundary_description", sa.Text),
        sa.Column("data_types", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("federal_data", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("cui_support", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("external_services", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("customer_responsibilities", sa.Text),
        sa.Column("provider_responsibilities", sa.Text),
        sa.Column("shared_responsibilities", sa.Text),
        sa.Column("cryptographic_boundary", sa.Text),
        sa.Column("logging_boundary", sa.Text),
        sa.Column("incident_response_boundary", sa.Text),
        sa.Column("backup_recovery_boundary", sa.Text),
        sa.Column("administrative_access_boundary", sa.Text),
        sa.Column("readiness_status", sa.String(32), nullable=False, server_default="not_started"),
        sa.Column("metadata_json", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=_now, nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=_now, nullable=False),
        sa.UniqueConstraint("system_id", name="uq_fedramp20x_profile_system"),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_fedramp20x_profiles_system", "fedramp20x_profiles", ["system_id"], schema="ccf"
    )

    # Per-system KSI state.
    op.create_table(
        "ksi_states",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "system_id",
            sa.Integer,
            sa.ForeignKey("ccf.systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "ksi_id",
            sa.Integer,
            sa.ForeignKey("ccf.ksis.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(32), nullable=False, server_default="not_tested"),
        sa.Column("assessor_status", sa.String(32), nullable=False, server_default="not_reviewed"),
        sa.Column("owner_user_id", sa.Integer, sa.ForeignKey("ccf.users.id", ondelete="SET NULL")),
        sa.Column(
            "reviewer_user_id", sa.Integer, sa.ForeignKey("ccf.users.id", ondelete="SET NULL")
        ),
        sa.Column("last_validated_at", sa.DateTime(timezone=True)),
        sa.Column("next_validation_due", sa.Date),
        sa.Column("notes", sa.Text),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=_now, nullable=False),
        sa.UniqueConstraint("system_id", "ksi_id", name="uq_ksi_state_system_ksi"),
        schema="ccf",
    )
    op.create_index("ix_ccf_ksi_states_system", "ksi_states", ["system_id"], schema="ccf")
    op.create_index("ix_ccf_ksi_states_ksi", "ksi_states", ["ksi_id"], schema="ccf")

    # Append-only KSI validation history.
    op.create_table(
        "ksi_validation_results",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "system_id",
            sa.Integer,
            sa.ForeignKey("ccf.systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "ksi_id",
            sa.Integer,
            sa.ForeignKey("ccf.ksis.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("ksi_identifier", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("confidence", sa.String(16)),
        sa.Column("source", sa.String(64)),
        sa.Column("evidence_refs", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("failure_reason", sa.Text),
        sa.Column("remediation_hint", sa.Text),
        sa.Column(
            "assessor_review_required", sa.Boolean, nullable=False, server_default=sa.false()
        ),
        sa.Column("validated_at", sa.DateTime(timezone=True), server_default=_now, nullable=False),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_ksi_val_system", "ksi_validation_results", ["system_id"], schema="ccf"
    )
    op.create_index("ix_ccf_ksi_val_ksi", "ksi_validation_results", ["ksi_id"], schema="ccf")
    op.create_index(
        "ix_ccf_ksi_val_ident", "ksi_validation_results", ["ksi_identifier"], schema="ccf"
    )
    op.create_index(
        "ix_ccf_ksi_val_at", "ksi_validation_results", ["validated_at"], schema="ccf"
    )

    # Assessor (3PAO) reviews.
    op.create_table(
        "ksi_assessor_reviews",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "system_id",
            sa.Integer,
            sa.ForeignKey("ccf.systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "ksi_id",
            sa.Integer,
            sa.ForeignKey("ccf.ksis.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("assessor", sa.String(255)),
        sa.Column("status", sa.String(32), nullable=False, server_default="not_reviewed"),
        sa.Column("notes", sa.Text),
        sa.Column("evidence_accepted", sa.Boolean),
        sa.Column("retest_requested", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("finding", sa.Text),
        sa.Column("management_response", sa.Text),
        sa.Column("closure_evidence", sa.Text),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), server_default=_now, nullable=False),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_ksi_reviews_system", "ksi_assessor_reviews", ["system_id"], schema="ccf"
    )
    op.create_index("ix_ccf_ksi_reviews_ksi", "ksi_assessor_reviews", ["ksi_id"], schema="ccf")

    # KSI exceptions / deviations.
    op.create_table(
        "ksi_exceptions",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "system_id",
            sa.Integer,
            sa.ForeignKey("ccf.systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "ksi_id",
            sa.Integer,
            sa.ForeignKey("ccf.ksis.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("rationale", sa.Text, nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="open"),
        sa.Column("risk_id", sa.BigInteger, sa.ForeignKey("ccf.risks.id", ondelete="SET NULL")),
        sa.Column("expires_on", sa.Date),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=_now, nullable=False),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_ksi_exceptions_system", "ksi_exceptions", ["system_id"], schema="ccf"
    )
    op.create_index("ix_ccf_ksi_exceptions_ksi", "ksi_exceptions", ["ksi_id"], schema="ccf")

    # FedRAMP-authorized dependency tracking.
    op.create_table(
        "fedramp_dependencies",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "system_id",
            sa.Integer,
            sa.ForeignKey("ccf.systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("provider", sa.String(255)),
        sa.Column("service_type", sa.String(16)),
        sa.Column("fedramp_status", sa.String(32), nullable=False, server_default="unknown"),
        sa.Column("marketplace_url", sa.String(1024)),
        sa.Column("authorization_level", sa.String(32)),
        sa.Column("impact_level", sa.String(16)),
        sa.Column("boundary_role", sa.String(255)),
        sa.Column("inherited_controls", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("shared_responsibilities", sa.Text),
        sa.Column("dependency_risk", sa.String(16)),
        sa.Column("evidence", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=_now, nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=_now, nullable=False),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_fedramp_deps_system", "fedramp_dependencies", ["system_id"], schema="ccf"
    )

    # Readiness snapshots (separate from traditional FedRAMP scoring).
    op.create_table(
        "fedramp20x_readiness_snapshots",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "system_id",
            sa.Integer,
            sa.ForeignKey("ccf.systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("readiness_pct", sa.Integer, nullable=False, server_default="0"),
        sa.Column("status", sa.String(32), nullable=False, server_default="not_started"),
        sa.Column("ksi_pass_rate", sa.Integer),
        sa.Column("automation_coverage", sa.Integer),
        sa.Column("evidence_completeness", sa.Integer),
        sa.Column("conmon_coverage", sa.Integer),
        sa.Column("assessor_completion", sa.Integer),
        sa.Column("dependency_readiness", sa.Integer),
        sa.Column("open_exceptions", sa.Integer, nullable=False, server_default="0"),
        sa.Column("high_risk_findings", sa.Integer, nullable=False, server_default="0"),
        sa.Column("expired_validations", sa.Integer, nullable=False, server_default="0"),
        sa.Column("manual_review_burden", sa.Integer, nullable=False, server_default="0"),
        sa.Column("payload", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=_now, nullable=False),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_fedramp20x_snap_system",
        "fedramp20x_readiness_snapshots",
        ["system_id"],
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_fedramp20x_snap_at",
        "fedramp20x_readiness_snapshots",
        ["created_at"],
        schema="ccf",
    )


def downgrade() -> None:
    op.drop_table("fedramp20x_readiness_snapshots", schema="ccf")
    op.drop_table("fedramp_dependencies", schema="ccf")
    op.drop_table("ksi_exceptions", schema="ccf")
    op.drop_table("ksi_assessor_reviews", schema="ccf")
    op.drop_table("ksi_validation_results", schema="ccf")
    op.drop_table("ksi_states", schema="ccf")
    op.drop_table("fedramp20x_profiles", schema="ccf")
    op.drop_table("ksis", schema="ccf")
