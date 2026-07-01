"""Enterprise governance layer — tasks, notifications, events/webhooks, policies,
vendors, artifacts, monitoring runs; evidence->artifact link; risk scoring.

Revision ID: 0013_enterprise_governance
Revises: 0012_odp_and_templates
Create Date: 2026-07-01
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0013_enterprise_governance"
down_revision = "0012_odp_and_templates"
branch_labels = None
depends_on = None

FK = sa.ForeignKey


def _org_col() -> sa.Column:
    return sa.Column(
        "organization_id",
        sa.Integer,
        sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
    )


def upgrade() -> None:
    op.create_table(
        "tasks",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _org_col(),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("kind", sa.String(32), nullable=False, server_default="general"),
        sa.Column("status", sa.String(16), nullable=False, server_default="open"),
        sa.Column("priority", sa.String(16), nullable=False, server_default="medium"),
        sa.Column(
            "assignee_user_id", sa.Integer, sa.ForeignKey("ccf.users.id", ondelete="SET NULL")
        ),
        sa.Column("system_id", sa.Integer, sa.ForeignKey("ccf.systems.id", ondelete="CASCADE")),
        sa.Column("entity_type", sa.String(32)),
        sa.Column("entity_id", sa.String(64)),
        sa.Column("source", sa.String(16), nullable=False, server_default="manual"),
        sa.Column("dedupe_key", sa.String(160)),
        sa.Column("due_on", sa.Date),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("closed_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("dedupe_key", name="uq_tasks_dedupe"),
        schema="ccf",
    )
    op.create_index("ix_ccf_tasks_org", "tasks", ["organization_id"], schema="ccf")
    op.create_index("ix_ccf_tasks_status", "tasks", ["status"], schema="ccf")
    op.create_index("ix_ccf_tasks_assignee", "tasks", ["assignee_user_id"], schema="ccf")
    op.create_index("ix_ccf_tasks_system", "tasks", ["system_id"], schema="ccf")
    op.create_index("ix_tasks_entity", "tasks", ["entity_type", "entity_id"], schema="ccf")

    op.create_table(
        "notifications",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _org_col(),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("ccf.users.id", ondelete="CASCADE")),
        sa.Column("severity", sa.String(16), nullable=False, server_default="info"),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("body", sa.Text),
        sa.Column("entity_type", sa.String(32)),
        sa.Column("entity_id", sa.String(64)),
        sa.Column("dedupe_key", sa.String(200)),
        sa.Column("read_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("dedupe_key", name="uq_notifications_dedupe"),
        schema="ccf",
    )
    op.create_index("ix_ccf_notifications_org", "notifications", ["organization_id"], schema="ccf")
    op.create_index("ix_ccf_notifications_user", "notifications", ["user_id"], schema="ccf")
    op.create_index("ix_ccf_notifications_created", "notifications", ["created_at"], schema="ccf")

    op.create_table(
        "events",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _org_col(),
        sa.Column("actor", sa.String(255)),
        sa.Column("verb", sa.String(48), nullable=False),
        sa.Column("entity_type", sa.String(32), nullable=False),
        sa.Column("entity_id", sa.String(64)),
        sa.Column("summary", sa.String(512), nullable=False),
        sa.Column("payload", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        schema="ccf",
    )
    op.create_index("ix_ccf_events_org", "events", ["organization_id"], schema="ccf")
    op.create_index("ix_ccf_events_created", "events", ["created_at"], schema="ccf")
    op.create_index("ix_events_entity", "events", ["entity_type", "entity_id"], schema="ccf")

    op.create_table(
        "webhooks",
        sa.Column("id", sa.Integer, primary_key=True),
        _org_col(),
        sa.Column("url", sa.String(1024), nullable=False),
        sa.Column("secret", sa.String(128)),
        sa.Column("events", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        schema="ccf",
    )
    op.create_index("ix_ccf_webhooks_org", "webhooks", ["organization_id"], schema="ccf")

    op.create_table(
        "artifacts",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _org_col(),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("filename", sa.String(512), nullable=False),
        sa.Column("media_type", sa.String(255)),
        sa.Column("size_bytes", sa.BigInteger),
        sa.Column("storage", sa.String(16), nullable=False, server_default="inline"),
        sa.Column("content", sa.LargeBinary),
        sa.Column("uri", sa.String(1024)),
        sa.Column("uploaded_by", sa.String(255)),
        sa.Column("metadata_json", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("organization_id", "sha256", name="uq_artifact_org_sha"),
        schema="ccf",
    )
    op.create_index("ix_ccf_artifacts_org", "artifacts", ["organization_id"], schema="ccf")
    op.create_index("ix_ccf_artifacts_sha", "artifacts", ["sha256"], schema="ccf")

    op.add_column(
        "evidence",
        sa.Column(
            "artifact_id", sa.BigInteger, sa.ForeignKey("ccf.artifacts.id", ondelete="SET NULL")
        ),
        schema="ccf",
    )

    op.create_table(
        "policies",
        sa.Column("id", sa.Integer, primary_key=True),
        _org_col(),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("category", sa.String(64)),
        sa.Column("owner_user_id", sa.Integer, sa.ForeignKey("ccf.users.id", ondelete="SET NULL")),
        sa.Column("status", sa.String(16), nullable=False, server_default="draft"),
        sa.Column("review_frequency", sa.String(32)),
        sa.Column("next_review_on", sa.Date),
        sa.Column("linked_controls", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        schema="ccf",
    )
    op.create_index("ix_ccf_policies_org", "policies", ["organization_id"], schema="ccf")

    op.create_table(
        "policy_versions",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "policy_id",
            sa.Integer,
            sa.ForeignKey("ccf.policies.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version", sa.String(32), nullable=False),
        sa.Column("body", sa.Text),
        sa.Column("uri", sa.String(1024)),
        sa.Column("effective_on", sa.Date),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("policy_id", "version", name="uq_policy_version"),
        schema="ccf",
    )
    op.create_index("ix_ccf_policy_versions_policy", "policy_versions", ["policy_id"], schema="ccf")

    op.create_table(
        "policy_attestations",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "policy_version_id",
            sa.BigInteger,
            sa.ForeignKey("ccf.policy_versions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("ccf.users.id", ondelete="SET NULL")),
        sa.Column("attestor", sa.String(255)),
        sa.Column("note", sa.Text),
        sa.Column(
            "attested_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_policy_attest_version", "policy_attestations", ["policy_version_id"], schema="ccf"
    )

    op.create_table(
        "vendors",
        sa.Column("id", sa.Integer, primary_key=True),
        _org_col(),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("service_type", sa.String(128)),
        sa.Column("criticality", sa.String(16), nullable=False, server_default="medium"),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("risk_rating", sa.String(16)),
        sa.Column("contact_email", sa.String(255)),
        sa.Column("authorization", sa.String(128)),
        sa.Column("review_frequency", sa.String(32)),
        sa.Column("last_reviewed_on", sa.Date),
        sa.Column("next_review_on", sa.Date),
        sa.Column("linked_controls", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        schema="ccf",
    )
    op.create_index("ix_ccf_vendors_org", "vendors", ["organization_id"], schema="ccf")

    op.create_table(
        "monitoring_runs",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _org_col(),
        sa.Column(
            "started_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("controls_checked", sa.Integer, nullable=False, server_default="0"),
        sa.Column("findings", sa.Integer, nullable=False, server_default="0"),
        sa.Column("tasks_created", sa.Integer, nullable=False, server_default="0"),
        sa.Column("notifications_created", sa.Integer, nullable=False, server_default="0"),
        sa.Column("summary", postgresql.JSONB, nullable=False, server_default="{}"),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_monitoring_runs_org", "monitoring_runs", ["organization_id"], schema="ccf"
    )

    op.add_column("risks", sa.Column("inherent_score", sa.Integer), schema="ccf")
    op.add_column("risks", sa.Column("residual_score", sa.Integer), schema="ccf")


def downgrade() -> None:
    op.drop_column("risks", "residual_score", schema="ccf")
    op.drop_column("risks", "inherent_score", schema="ccf")
    op.drop_table("monitoring_runs", schema="ccf")
    op.drop_table("vendors", schema="ccf")
    op.drop_table("policy_attestations", schema="ccf")
    op.drop_table("policy_versions", schema="ccf")
    op.drop_table("policies", schema="ccf")
    op.drop_column("evidence", "artifact_id", schema="ccf")
    op.drop_table("artifacts", schema="ccf")
    op.drop_table("webhooks", schema="ccf")
    op.drop_table("events", schema="ccf")
    op.drop_table("notifications", schema="ccf")
    op.drop_table("tasks", schema="ccf")
