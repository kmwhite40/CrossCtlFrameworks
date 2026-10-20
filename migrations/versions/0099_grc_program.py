"""GRC program build-out: posture history, risk scale, appetite and KRIs,
organization structure, governance bodies, objectives, obligations,
compensating controls, audit workpapers, third-party contracts and due
diligence, projects, and the CISA KEV catalog.

Revision ID: 0099_grc_program
Revises: 0098_assurance_edge_source
Create Date: 2026-10-20

Every new table except ``kev_entries`` is tenant data: it carries its own
``organization_id`` and gets the same forced ``tenant_isolation`` policy as
the rest of the schema (0096's shape). ``kev_entries`` is CISA's catalog,
identical for every tenant, and is on the global allowlist.

Risks gain ``likelihood_score``/``impact_score`` on 1-5. Existing rows are
backfilled low=1, moderate=3, high=5 -- the values ``compute_scores`` already
used -- so no inherent or residual score changes. Systems gain a nullable
``business_unit_id``.

Downgrade drops everything this adds. It is lossy for the data entered in
these tables, and that is the only way back to 0098's schema.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0099_grc_program"
down_revision = "0098_assurance_edge_source"
branch_labels = None
depends_on = None

_PREDICATE = "(ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant())"

#: Tenant tables in creation order (mirrors ccf.models_program.TENANT_TABLES,
#: restated because a migration must not import application code).
_TENANT_TABLES = (
    "posture_snapshots",
    "risk_appetites",
    "key_risk_indicators",
    "kri_readings",
    "business_units",
    "teams",
    "team_members",
    "committees",
    "committee_members",
    "committee_meetings",
    "strategic_objectives",
    "objective_links",
    "compliance_obligations",
    "compensating_controls",
    "audit_workpapers",
    "vendor_contracts",
    "contract_obligations",
    "due_diligence_items",
    "vendor_findings",
    "projects",
    "project_links",
)


def upgrade() -> None:
    op.create_table(
        "posture_snapshots",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("taken_on", sa.Date(), nullable=False),
        sa.Column(
            "taken_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("metrics", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["ccf.organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "taken_on", name="uq_posture_snapshot_day"),
        schema="ccf",
    )

    op.create_table(
        "risk_appetites",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=True),
        sa.Column("statement", sa.Text(), nullable=False),
        sa.Column("max_residual_score", sa.Integer(), nullable=False),
        sa.Column("owner_user_id", sa.Integer(), nullable=True),
        sa.Column("approved_by", sa.String(length=255), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("review_on", sa.Date(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["ccf.organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["owner_user_id"], ["ccf.users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        schema="ccf",
    )

    op.create_table(
        "key_risk_indicators",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("metric_key", sa.String(length=64), nullable=True),
        sa.Column("unit", sa.String(length=32), nullable=True),
        sa.Column("direction", sa.String(length=16), nullable=False),
        sa.Column("warn_threshold", sa.Float(), nullable=True),
        sa.Column("critical_threshold", sa.Float(), nullable=True),
        sa.Column("owner_user_id", sa.Integer(), nullable=True),
        sa.Column("risk_id", sa.Integer(), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["ccf.organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["owner_user_id"], ["ccf.users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["risk_id"], ["ccf.risks.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        schema="ccf",
    )

    op.create_table(
        "kri_readings",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("kri_id", sa.Integer(), nullable=False),
        sa.Column("value", sa.Float(), nullable=False),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("recorded_by", sa.String(length=255), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["kri_id"], ["ccf.key_risk_indicators.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["ccf.organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        schema="ccf",
    )

    op.create_table(
        "business_units",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("parent_id", sa.Integer(), nullable=True),
        sa.Column("owner_user_id", sa.Integer(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["ccf.organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["owner_user_id"], ["ccf.users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["parent_id"], ["ccf.business_units.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "name", name="uq_business_unit_name"),
        schema="ccf",
    )

    op.create_table(
        "teams",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("business_unit_id", sa.Integer(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["business_unit_id"], ["ccf.business_units.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["ccf.organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "name", name="uq_team_name"),
        schema="ccf",
    )

    op.create_table(
        "team_members",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("team_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["ccf.organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["team_id"], ["ccf.teams.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["ccf.users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("team_id", "user_id", name="uq_team_member"),
        schema="ccf",
    )

    op.create_table(
        "committees",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("charter", sa.Text(), nullable=True),
        sa.Column("cadence", sa.String(length=32), nullable=True),
        sa.Column("chair_user_id", sa.Integer(), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["chair_user_id"], ["ccf.users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["organization_id"], ["ccf.organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "name", name="uq_committee_name"),
        schema="ccf",
    )

    op.create_table(
        "committee_members",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("committee_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.ForeignKeyConstraint(["committee_id"], ["ccf.committees.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["ccf.organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["ccf.users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("committee_id", "user_id", name="uq_committee_member"),
        schema="ccf",
    )

    op.create_table(
        "committee_meetings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("committee_id", sa.Integer(), nullable=False),
        sa.Column("held_on", sa.Date(), nullable=False),
        sa.Column("attendee_user_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("minutes", sa.Text(), nullable=True),
        sa.Column("decisions", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("recorded_by", sa.String(length=255), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["committee_id"], ["ccf.committees.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["ccf.organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        schema="ccf",
    )

    op.create_table(
        "strategic_objectives",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("measure", sa.Text(), nullable=True),
        sa.Column("owner_user_id", sa.Integer(), nullable=True),
        sa.Column("target_on", sa.Date(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["ccf.organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["owner_user_id"], ["ccf.users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        schema="ccf",
    )

    op.create_table(
        "objective_links",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("objective_id", sa.Integer(), nullable=False),
        sa.Column("entity_type", sa.String(length=32), nullable=False),
        sa.Column("entity_id", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(
            ["objective_id"], ["ccf.strategic_objectives.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["ccf.organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("objective_id", "entity_type", "entity_id", name="uq_objective_link"),
        schema="ccf",
    )

    op.create_table(
        "compliance_obligations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("citation", sa.String(length=255), nullable=True),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("owner_user_id", sa.Integer(), nullable=True),
        sa.Column("frequency", sa.String(length=32), nullable=True),
        sa.Column("due_on", sa.Date(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("control_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["ccf.organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["owner_user_id"], ["ccf.users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        schema="ccf",
    )

    op.create_table(
        "compensating_controls",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("system_id", sa.Integer(), nullable=False),
        sa.Column("control_identifier", sa.String(length=64), nullable=False),
        sa.Column("measure", sa.Text(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("proposed_by", sa.String(length=255), nullable=True),
        sa.Column("decided_by", sa.String(length=255), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_on", sa.Date(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["ccf.organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["system_id"], ["ccf.systems.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        schema="ccf",
    )

    op.create_table(
        "audit_workpapers",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("engagement_id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("control_id", sa.String(length=64), nullable=True),
        sa.Column("procedure", sa.Text(), nullable=True),
        sa.Column("sample_size", sa.Integer(), nullable=True),
        sa.Column("exceptions_found", sa.Integer(), nullable=True),
        sa.Column("conclusion", sa.String(length=16), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("prepared_by", sa.String(length=255), nullable=True),
        sa.Column("reviewed_by", sa.String(length=255), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("evidence_refs", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["engagement_id"], ["ccf.audit_engagements.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["ccf.organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        schema="ccf",
    )

    op.create_table(
        "vendor_contracts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("vendor_id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("contract_ref", sa.String(length=128), nullable=True),
        sa.Column("start_on", sa.Date(), nullable=True),
        sa.Column("end_on", sa.Date(), nullable=True),
        sa.Column("renewal_on", sa.Date(), nullable=True),
        sa.Column("annual_value", sa.Float(), nullable=True),
        sa.Column("owner_user_id", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["ccf.organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["owner_user_id"], ["ccf.users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["vendor_id"], ["ccf.vendors.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        schema="ccf",
    )

    op.create_table(
        "contract_obligations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("contract_id", sa.Integer(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("frequency", sa.String(length=32), nullable=True),
        sa.Column("due_on", sa.Date(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("control_id", sa.String(length=64), nullable=True),
        sa.Column("evidence_ref", sa.String(length=512), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["contract_id"], ["ccf.vendor_contracts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["ccf.organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        schema="ccf",
    )

    op.create_table(
        "due_diligence_items",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("vendor_id", sa.Integer(), nullable=False),
        sa.Column("item", sa.String(length=255), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=True),
        sa.Column("required", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("evidence_ref", sa.String(length=512), nullable=True),
        sa.Column("due_on", sa.Date(), nullable=True),
        sa.Column("reviewed_by", sa.String(length=255), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["ccf.organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["vendor_id"], ["ccf.vendors.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        schema="ccf",
    )

    op.create_table(
        "vendor_findings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("vendor_id", sa.Integer(), nullable=False),
        sa.Column("questionnaire_id", sa.Integer(), nullable=True),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("due_on", sa.Date(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["organization_id"], ["ccf.organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["questionnaire_id"], ["ccf.vendor_questionnaires.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["vendor_id"], ["ccf.vendors.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        schema="ccf",
    )

    op.create_table(
        "projects",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("owner_user_id", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("start_on", sa.Date(), nullable=True),
        sa.Column("target_on", sa.Date(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["ccf.organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["owner_user_id"], ["ccf.users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        schema="ccf",
    )

    op.create_table(
        "project_links",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("entity_type", sa.String(length=32), nullable=False),
        sa.Column("entity_id", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["ccf.organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["ccf.projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "entity_type", "entity_id", name="uq_project_link"),
        schema="ccf",
    )

    op.create_table(
        "kev_entries",
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("vendor", sa.String(length=255), nullable=True),
        sa.Column("product", sa.String(length=255), nullable=True),
        sa.Column("name", sa.String(length=512), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("date_added", sa.Date(), nullable=True),
        sa.Column("due_date", sa.Date(), nullable=True),
        sa.Column("known_ransomware", sa.String(length=16), nullable=True),
        sa.Column("catalog_version", sa.String(length=32), nullable=True),
        sa.Column(
            "synced_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.PrimaryKeyConstraint("cve_id"),
        schema="ccf",
    )

    op.create_index(
        op.f("ix_ccf_posture_snapshots_organization_id"),
        "posture_snapshots",
        ["organization_id"],
        unique=False,
        schema="ccf",
    )
    op.create_index(
        op.f("ix_ccf_posture_snapshots_taken_on"),
        "posture_snapshots",
        ["taken_on"],
        unique=False,
        schema="ccf",
    )
    op.create_index(
        op.f("ix_ccf_audit_workpapers_engagement_id"),
        "audit_workpapers",
        ["engagement_id"],
        unique=False,
        schema="ccf",
    )
    op.create_index(
        op.f("ix_ccf_audit_workpapers_organization_id"),
        "audit_workpapers",
        ["organization_id"],
        unique=False,
        schema="ccf",
    )
    op.create_index(
        op.f("ix_ccf_business_units_organization_id"),
        "business_units",
        ["organization_id"],
        unique=False,
        schema="ccf",
    )
    op.create_index(
        op.f("ix_ccf_committees_organization_id"),
        "committees",
        ["organization_id"],
        unique=False,
        schema="ccf",
    )
    op.create_index(
        op.f("ix_ccf_compliance_obligations_organization_id"),
        "compliance_obligations",
        ["organization_id"],
        unique=False,
        schema="ccf",
    )
    op.create_index(
        op.f("ix_ccf_due_diligence_items_organization_id"),
        "due_diligence_items",
        ["organization_id"],
        unique=False,
        schema="ccf",
    )
    op.create_index(
        op.f("ix_ccf_due_diligence_items_vendor_id"),
        "due_diligence_items",
        ["vendor_id"],
        unique=False,
        schema="ccf",
    )
    op.create_index(
        op.f("ix_ccf_projects_organization_id"),
        "projects",
        ["organization_id"],
        unique=False,
        schema="ccf",
    )
    op.create_index(
        op.f("ix_ccf_risk_appetites_organization_id"),
        "risk_appetites",
        ["organization_id"],
        unique=False,
        schema="ccf",
    )
    op.create_index(
        op.f("ix_ccf_strategic_objectives_organization_id"),
        "strategic_objectives",
        ["organization_id"],
        unique=False,
        schema="ccf",
    )
    op.create_index(
        op.f("ix_ccf_vendor_contracts_organization_id"),
        "vendor_contracts",
        ["organization_id"],
        unique=False,
        schema="ccf",
    )
    op.create_index(
        op.f("ix_ccf_vendor_contracts_vendor_id"),
        "vendor_contracts",
        ["vendor_id"],
        unique=False,
        schema="ccf",
    )
    op.create_index(
        op.f("ix_ccf_committee_meetings_committee_id"),
        "committee_meetings",
        ["committee_id"],
        unique=False,
        schema="ccf",
    )
    op.create_index(
        op.f("ix_ccf_committee_meetings_organization_id"),
        "committee_meetings",
        ["organization_id"],
        unique=False,
        schema="ccf",
    )
    op.create_index(
        op.f("ix_ccf_committee_members_committee_id"),
        "committee_members",
        ["committee_id"],
        unique=False,
        schema="ccf",
    )
    op.create_index(
        op.f("ix_ccf_committee_members_organization_id"),
        "committee_members",
        ["organization_id"],
        unique=False,
        schema="ccf",
    )
    op.create_index(
        op.f("ix_ccf_contract_obligations_contract_id"),
        "contract_obligations",
        ["contract_id"],
        unique=False,
        schema="ccf",
    )
    op.create_index(
        op.f("ix_ccf_contract_obligations_organization_id"),
        "contract_obligations",
        ["organization_id"],
        unique=False,
        schema="ccf",
    )
    op.create_index(
        op.f("ix_ccf_objective_links_objective_id"),
        "objective_links",
        ["objective_id"],
        unique=False,
        schema="ccf",
    )
    op.create_index(
        op.f("ix_ccf_objective_links_organization_id"),
        "objective_links",
        ["organization_id"],
        unique=False,
        schema="ccf",
    )
    op.create_index(
        op.f("ix_ccf_project_links_organization_id"),
        "project_links",
        ["organization_id"],
        unique=False,
        schema="ccf",
    )
    op.create_index(
        op.f("ix_ccf_project_links_project_id"),
        "project_links",
        ["project_id"],
        unique=False,
        schema="ccf",
    )
    op.create_index(
        op.f("ix_ccf_teams_organization_id"),
        "teams",
        ["organization_id"],
        unique=False,
        schema="ccf",
    )
    op.create_index(
        op.f("ix_ccf_vendor_findings_organization_id"),
        "vendor_findings",
        ["organization_id"],
        unique=False,
        schema="ccf",
    )
    op.create_index(
        op.f("ix_ccf_vendor_findings_vendor_id"),
        "vendor_findings",
        ["vendor_id"],
        unique=False,
        schema="ccf",
    )
    op.create_index(
        op.f("ix_ccf_compensating_controls_organization_id"),
        "compensating_controls",
        ["organization_id"],
        unique=False,
        schema="ccf",
    )
    op.create_index(
        op.f("ix_ccf_compensating_controls_system_id"),
        "compensating_controls",
        ["system_id"],
        unique=False,
        schema="ccf",
    )
    op.create_index(
        op.f("ix_ccf_team_members_organization_id"),
        "team_members",
        ["organization_id"],
        unique=False,
        schema="ccf",
    )
    op.create_index(
        op.f("ix_ccf_team_members_team_id"), "team_members", ["team_id"], unique=False, schema="ccf"
    )
    op.create_index(
        op.f("ix_ccf_key_risk_indicators_organization_id"),
        "key_risk_indicators",
        ["organization_id"],
        unique=False,
        schema="ccf",
    )
    op.create_index(
        op.f("ix_ccf_kri_readings_kri_id"), "kri_readings", ["kri_id"], unique=False, schema="ccf"
    )
    op.create_index(
        op.f("ix_ccf_kri_readings_organization_id"),
        "kri_readings",
        ["organization_id"],
        unique=False,
        schema="ccf",
    )

    # One default (category-less) appetite per organization: NULLs must not
    # count as distinct, or every save would add another default.
    op.execute(
        "CREATE UNIQUE INDEX uq_risk_appetite_category ON ccf.risk_appetites "
        "(organization_id, category) NULLS NOT DISTINCT"
    )

    op.add_column("risks", sa.Column("likelihood_score", sa.Integer(), nullable=True), schema="ccf")
    op.add_column("risks", sa.Column("impact_score", sa.Integer(), nullable=True), schema="ccf")
    op.execute(
        "UPDATE ccf.risks SET "
        "likelihood_score = CASE likelihood::text WHEN 'low' THEN 1 WHEN 'moderate' THEN 3 "
        "WHEN 'high' THEN 5 END, "
        "impact_score = CASE impact::text WHEN 'low' THEN 1 WHEN 'moderate' THEN 3 "
        "WHEN 'high' THEN 5 END"
    )
    op.create_check_constraint(
        "ck_risk_likelihood_score",
        "risks",
        "likelihood_score IS NULL OR likelihood_score BETWEEN 1 AND 5",
        schema="ccf",
    )
    op.create_check_constraint(
        "ck_risk_impact_score",
        "risks",
        "impact_score IS NULL OR impact_score BETWEEN 1 AND 5",
        schema="ccf",
    )
    op.add_column(
        "systems",
        sa.Column(
            "business_unit_id",
            sa.Integer(),
            sa.ForeignKey("ccf.business_units.id", ondelete="SET NULL"),
            nullable=True,
        ),
        schema="ccf",
    )

    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    for table in _TENANT_TABLES:
        op.execute(f"ALTER TABLE ccf.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE ccf.{table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON ccf.{table} "
            f"FOR ALL USING {_PREDICATE} WITH CHECK {_PREDICATE}"
        )


def downgrade() -> None:
    for table in _TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON ccf.{table}")
    op.drop_column("systems", "business_unit_id", schema="ccf")
    op.drop_constraint("ck_risk_impact_score", "risks", schema="ccf")
    op.drop_constraint("ck_risk_likelihood_score", "risks", schema="ccf")
    op.drop_column("risks", "impact_score", schema="ccf")
    op.drop_column("risks", "likelihood_score", schema="ccf")
    op.drop_table("kev_entries", schema="ccf")
    for table in reversed(_TENANT_TABLES):
        op.drop_table(table, schema="ccf")
