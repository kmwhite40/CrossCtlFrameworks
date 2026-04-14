"""Baseline schema — creates ccf/ccf_raw/ccf_audit schemas, extensions, and all tables.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-04-14
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS ccf")
    op.execute("CREATE SCHEMA IF NOT EXISTS ccf_raw")
    op.execute("CREATE SCHEMA IF NOT EXISTS ccf_audit")
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    # --- Enums -------------------------------------------------------------
    fips199 = postgresql.ENUM("low", "moderate", "high",
                              name="fips199_level", schema="ccf",
                              create_type=True)
    baseline = postgresql.ENUM("low", "moderate", "high",
                               name="fedramp_baseline", schema="ccf",
                               create_type=True)
    ato_status = postgresql.ENUM("none", "in_progress", "authorized", "expired",
                                 name="ato_status", schema="ccf",
                                 create_type=True)
    impl_status = postgresql.ENUM(
        "not_implemented", "planned", "partial",
        "implemented", "inherited", "not_applicable",
        name="impl_status", schema="ccf", create_type=True,
    )
    impl_resp = postgresql.ENUM(
        "customer", "provider", "shared", "inherited",
        name="impl_responsibility", schema="ccf", create_type=True,
    )
    evidence_kind = postgresql.ENUM(
        "document", "screenshot", "config_export", "attestation",
        "scan_result", "ticket", "link", "other",
        name="evidence_kind", schema="ccf", create_type=True,
    )
    assessment_kind = postgresql.ENUM(
        "self", "internal", "3pao", "ig", "audit",
        name="assessment_kind", schema="ccf", create_type=True,
    )
    finding_status = postgresql.ENUM(
        "satisfied", "other_than_satisfied", "not_applicable",
        name="finding_status", schema="ccf", create_type=True,
    )
    severity = postgresql.ENUM(
        "low", "moderate", "high", "critical",
        name="severity", schema="ccf", create_type=True,
    )
    poam_status = postgresql.ENUM(
        "open", "in_progress", "completed", "risk_accepted", "closed",
        name="poam_status", schema="ccf", create_type=True,
    )
    risk_level = postgresql.ENUM(
        "low", "moderate", "high",
        name="risk_level", schema="ccf", create_type=True,
    )
    risk_treatment = postgresql.ENUM(
        "mitigate", "transfer", "accept", "avoid",
        name="risk_treatment", schema="ccf", create_type=True,
    )
    risk_status = postgresql.ENUM(
        "open", "mitigated", "accepted", "closed",
        name="risk_status", schema="ccf", create_type=True,
    )
    user_role = postgresql.ENUM(
        "admin", "control_owner", "assessor", "viewer",
        name="user_role", schema="ccf", create_type=True,
    )

    # Enum types are created lazily by SQLAlchemy on first column use
    # (create_type=True on the initial ENUM() constructor, False on reuse).
    # --- Reference tables --------------------------------------------------
    op.create_table(
        "ingestion_runs",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("source_file", sa.String(512), nullable=False),
        sa.Column("sha256", sa.String(64)),
        sa.Column("started_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("status", sa.String(32), server_default="running", nullable=False),
        sa.Column("stats", postgresql.JSONB, server_default="{}", nullable=False),
        schema="ccf",
    )
    op.create_table(
        "frameworks",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("code", sa.String(64), nullable=False, unique=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("family", sa.String(64)),
        sa.Column("description", sa.Text),
        schema="ccf",
    )
    op.create_table(
        "control_families",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("code", sa.String(16), nullable=False, unique=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("category", sa.String(64)),
        schema="ccf",
    )
    op.create_table(
        "controls",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("identifier", sa.String(128), nullable=False, unique=True),
        sa.Column("sequence_control", sa.String(64)),
        sa.Column("sort_as", sa.String(64)),
        sa.Column("family_id", sa.Integer,
                  sa.ForeignKey("ccf.control_families.id", ondelete="SET NULL")),
        sa.Column("control_number", sa.String(64)),
        sa.Column("control_name", sa.String(512)),
        sa.Column("description", sa.Text),
        sa.Column("discussion", sa.Text),
        sa.Column("related_controls", sa.Text),
        sa.Column("assessment_objective", sa.Text),
        sa.Column("examine", sa.Text),
        sa.Column("interview", sa.Text),
        sa.Column("test", sa.Text),
        sa.Column("ap_acronym", sa.String(64)),
        sa.Column("assurance_control", sa.String(16)),
        sa.Column("implemented_by", sa.String(64)),
        sa.Column("owner", sa.String(64)),
        sa.Column("overall_control_type", sa.String(64)),
        sa.Column("opd", sa.Boolean),
        sa.Column("fisma_low", sa.Boolean),
        sa.Column("fisma_mod", sa.Boolean),
        sa.Column("fisma_high", sa.Boolean),
        sa.Column("audit_payload", postgresql.JSONB, server_default="{}", nullable=False),
        sa.Column("search_vector", postgresql.TSVECTOR),
        sa.Column("source_row", sa.Integer),
        sa.Column("loaded_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        schema="ccf",
    )
    op.create_index("idx_controls_sequence", "controls", ["sequence_control"], schema="ccf")
    op.create_index("idx_controls_search_vector", "controls", ["search_vector"],
                    postgresql_using="gin", schema="ccf")
    op.create_index("idx_controls_audit_payload_gin", "controls", ["audit_payload"],
                    postgresql_using="gin", schema="ccf")

    op.create_table(
        "framework_mappings",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("control_id", sa.BigInteger,
                  sa.ForeignKey("ccf.controls.id", ondelete="CASCADE"), nullable=False),
        sa.Column("framework_id", sa.Integer,
                  sa.ForeignKey("ccf.frameworks.id", ondelete="SET NULL")),
        sa.Column("column_key", sa.String(255), nullable=False),
        sa.Column("value", sa.Text, nullable=False),
        sa.UniqueConstraint("control_id", "column_key", name="uq_mapping_control_column"),
        schema="ccf",
    )
    op.create_index("ix_ccf_framework_mappings_control_id", "framework_mappings",
                    ["control_id"], schema="ccf")
    op.create_index("ix_ccf_framework_mappings_framework_id", "framework_mappings",
                    ["framework_id"], schema="ccf")
    op.create_index("ix_ccf_framework_mappings_column_key", "framework_mappings",
                    ["column_key"], schema="ccf")
    op.execute(
        "CREATE INDEX idx_mapping_value_trgm ON ccf.framework_mappings "
        "USING GIN (value gin_trgm_ops)"
    )

    op.create_table(
        "worksheets",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("slug", sa.String(255), nullable=False, unique=True),
        sa.Column("headers", sa.JSON, server_default="[]", nullable=False),
        sa.Column("row_count", sa.Integer, server_default="0", nullable=False),
        sa.Column("loaded_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        schema="ccf",
    )
    op.create_table(
        "worksheet_rows",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("worksheet_id", sa.Integer,
                  sa.ForeignKey("ccf.worksheets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("row_index", sa.Integer, nullable=False),
        sa.Column("payload", postgresql.JSONB, nullable=False),
        schema="ccf",
    )
    op.create_index("idx_worksheet_rows_payload_gin", "worksheet_rows", ["payload"],
                    postgresql_using="gin", schema="ccf")
    op.create_index("ix_ccf_worksheet_rows_worksheet_id", "worksheet_rows",
                    ["worksheet_id"], schema="ccf")

    # --- Operational tables -----------------------------------------------
    op.create_table(
        "organizations",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("description", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        schema="ccf",
    )
    op.create_table(
        "users",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("organization_id", sa.Integer,
                  sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("full_name", sa.String(255)),
        sa.Column("role", user_role, server_default="viewer", nullable=False),
        sa.Column("active", sa.Boolean, server_default=sa.text("true"), nullable=False),
        schema="ccf",
    )
    op.create_index("ix_ccf_users_org", "users", ["organization_id"], schema="ccf")

    op.create_table(
        "systems",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("organization_id", sa.Integer,
                  sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("fips199_confidentiality", fips199),
        sa.Column("fips199_integrity", fips199),
        sa.Column("fips199_availability", fips199),
        sa.Column("baseline", baseline),
        sa.Column("ato_status", ato_status, server_default="none"),
        sa.Column("ato_expires_on", sa.Date),
        sa.UniqueConstraint("organization_id", "name", name="uq_system_org_name"),
        schema="ccf",
    )

    op.create_table(
        "control_implementations",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("system_id", sa.Integer,
                  sa.ForeignKey("ccf.systems.id", ondelete="CASCADE"), nullable=False),
        sa.Column("control_id", sa.BigInteger,
                  sa.ForeignKey("ccf.controls.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("status", impl_status, server_default="not_implemented", nullable=False),
        sa.Column("responsibility", impl_resp),
        sa.Column("owner_user_id", sa.Integer,
                  sa.ForeignKey("ccf.users.id", ondelete="SET NULL")),
        sa.Column("narrative", sa.Text),
        sa.Column("conmon_frequency", sa.String(32)),
        sa.Column("last_assessed_on", sa.Date),
        sa.Column("next_assessment_due", sa.Date),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("system_id", "control_id", name="uq_impl_system_control"),
        schema="ccf",
    )

    op.create_table(
        "evidence",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("implementation_id", sa.BigInteger,
                  sa.ForeignKey("ccf.control_implementations.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("kind", evidence_kind, nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("uri", sa.String(1024)),
        sa.Column("collected_on", sa.Date),
        sa.Column("expires_on", sa.Date),
        sa.Column("hash_sha256", sa.String(64)),
        sa.Column("metadata_json", postgresql.JSONB, server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        schema="ccf",
    )

    op.create_table(
        "assessments",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("system_id", sa.Integer,
                  sa.ForeignKey("ccf.systems.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("kind", assessment_kind, nullable=False),
        sa.Column("started_on", sa.Date),
        sa.Column("finished_on", sa.Date),
        sa.Column("assessor", sa.String(255)),
        sa.Column("summary", sa.Text),
        schema="ccf",
    )
    op.create_table(
        "assessment_results",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("assessment_id", sa.Integer,
                  sa.ForeignKey("ccf.assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("implementation_id", sa.BigInteger,
                  sa.ForeignKey("ccf.control_implementations.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("finding", finding_status, nullable=False),
        sa.Column("rationale", sa.Text),
        sa.Column("observed_on", sa.Date),
        schema="ccf",
    )

    op.create_table(
        "poams",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("system_id", sa.Integer,
                  sa.ForeignKey("ccf.systems.id", ondelete="CASCADE"), nullable=False),
        sa.Column("control_id", sa.BigInteger,
                  sa.ForeignKey("ccf.controls.id", ondelete="SET NULL")),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("weakness", sa.Text),
        sa.Column("severity", severity, server_default="moderate", nullable=False),
        sa.Column("status", poam_status, server_default="open", nullable=False),
        sa.Column("identified_on", sa.Date),
        sa.Column("due_on", sa.Date),
        sa.Column("closed_on", sa.Date),
        sa.Column("owner_user_id", sa.Integer,
                  sa.ForeignKey("ccf.users.id", ondelete="SET NULL")),
        schema="ccf",
    )

    op.create_table(
        "risks",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("system_id", sa.Integer,
                  sa.ForeignKey("ccf.systems.id", ondelete="CASCADE")),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("likelihood", risk_level),
        sa.Column("impact", risk_level),
        sa.Column("treatment", risk_treatment),
        sa.Column("status", risk_status, server_default="open", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        schema="ccf",
    )

    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("actor", sa.String(255)),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("entity_type", sa.String(64), nullable=False),
        sa.Column("entity_id", sa.String(64)),
        sa.Column("diff", postgresql.JSONB, server_default="{}", nullable=False),
        schema="ccf",
    )
    op.create_index("ix_ccf_audit_log_at", "audit_log", ["at"], schema="ccf")


def downgrade() -> None:
    for t in (
        "audit_log", "risks", "poams", "assessment_results", "assessments",
        "evidence", "control_implementations", "systems", "users", "organizations",
        "worksheet_rows", "worksheets",
        "framework_mappings", "controls", "control_families", "frameworks",
        "ingestion_runs",
    ):
        op.drop_table(t, schema="ccf")
    for enum_name in (
        "user_role", "risk_status", "risk_treatment", "risk_level",
        "poam_status", "severity", "finding_status", "assessment_kind",
        "evidence_kind", "impl_responsibility", "impl_status",
        "ato_status", "fedramp_baseline", "fips199_level",
    ):
        op.execute(f"DROP TYPE IF EXISTS ccf.{enum_name}")
    op.execute("DROP SCHEMA IF EXISTS ccf_audit CASCADE")
    op.execute("DROP SCHEMA IF EXISTS ccf_raw CASCADE")
    op.execute("DROP SCHEMA IF EXISTS ccf CASCADE")
