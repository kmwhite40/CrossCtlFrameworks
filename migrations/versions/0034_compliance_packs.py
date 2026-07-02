"""Compliance pack runtime.

Adds ``compliance_packs`` + version history + install runs + materialized
controls/mappings/evidence-requirements/rules + test results. Org-scoped rows
filter directly; per-pack children filter via the parent pack.

Revision ID: 0034_compliance_packs
Revises: 0033_ai_agents
Create Date: 2026-07-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0034_compliance_packs"
down_revision = "0033_ai_agents"
branch_labels = None
depends_on = None

JB = postgresql.JSONB
_ORG = "organization_id = ccf.current_tenant()"
_PACK = (
    "pack_id IN (SELECT id FROM ccf.compliance_packs WHERE organization_id = ccf.current_tenant())"
)
_POLICIES = {
    "compliance_packs": _ORG,
    "pack_install_runs": _ORG,
    "compliance_pack_versions": _PACK,
    "pack_controls": _PACK,
    "pack_mappings": _PACK,
    "pack_evidence_requirements": _PACK,
    "pack_rules": _PACK,
    "pack_test_results": _PACK,
}


def _pack_fk() -> sa.Column:
    return sa.Column(
        "pack_id", sa.Integer,
        sa.ForeignKey("ccf.compliance_packs.id", ondelete="CASCADE"), nullable=False,
    )


def upgrade() -> None:
    op.create_table(
        "compliance_packs",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "organization_id", sa.Integer,
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
        ),
        sa.Column("pack_key", sa.String(64), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("version", sa.String(24), nullable=False),
        sa.Column("schema_version", sa.String(8), nullable=False, server_default="1"),
        sa.Column("source", sa.String(255)),
        sa.Column("manifest_sha", sa.String(64)),
        sa.Column("status", sa.String(16), nullable=False, server_default="installed"),
        sa.Column("manifest", JB, server_default="{}", nullable=False),
        sa.Column("installed_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("organization_id", "pack_key", name="uq_compliance_pack"),
        schema="ccf",
    )
    op.create_index("ix_ccf_packs_org", "compliance_packs", ["organization_id"], schema="ccf")
    op.create_index("ix_ccf_packs_key", "compliance_packs", ["pack_key"], schema="ccf")

    op.create_table(
        "compliance_pack_versions",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _pack_fk(),
        sa.Column("version", sa.String(24), nullable=False),
        sa.Column("manifest_sha", sa.String(64)),
        sa.Column("installed_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_pack_versions_pack", "compliance_pack_versions", ["pack_id"], schema="ccf"
    )

    op.create_table(
        "pack_install_runs",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "organization_id", sa.Integer,
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
        ),
        sa.Column("pack_key", sa.String(64), nullable=False),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="ok"),
        sa.Column("summary", JB, server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_pack_install_org", "pack_install_runs", ["organization_id"], schema="ccf"
    )

    op.create_table(
        "pack_controls",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _pack_fk(),
        sa.Column("control_id", sa.String(64), nullable=False),
        sa.Column("title", sa.String(512)),
        sa.Column("family", sa.String(64)),
        schema="ccf",
    )
    op.create_index("ix_ccf_pack_controls_pack", "pack_controls", ["pack_id"], schema="ccf")
    op.create_index("ix_ccf_pack_controls_cid", "pack_controls", ["control_id"], schema="ccf")

    op.create_table(
        "pack_mappings",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _pack_fk(),
        sa.Column("control_id", sa.String(64), nullable=False),
        sa.Column("framework", sa.String(64), nullable=False),
        sa.Column("reference", sa.String(255)),
        schema="ccf",
    )
    op.create_index("ix_ccf_pack_mappings_pack", "pack_mappings", ["pack_id"], schema="ccf")

    op.create_table(
        "pack_evidence_requirements",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _pack_fk(),
        sa.Column("control_id", sa.String(64), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_pack_evreq_pack", "pack_evidence_requirements", ["pack_id"], schema="ccf"
    )

    op.create_table(
        "pack_rules",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _pack_fk(),
        sa.Column("rule_key", sa.String(64), nullable=False),
        sa.Column("kind", sa.String(48)),
        sa.Column("definition", JB, server_default="{}", nullable=False),
        schema="ccf",
    )
    op.create_index("ix_ccf_pack_rules_pack", "pack_rules", ["pack_id"], schema="ccf")

    op.create_table(
        "pack_test_results",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _pack_fk(),
        sa.Column("test_key", sa.String(64), nullable=False),
        sa.Column("status", sa.String(8), nullable=False),
        sa.Column("detail", sa.Text),
        sa.Column("run_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index("ix_ccf_pack_tests_pack", "pack_test_results", ["pack_id"], schema="ccf")

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
    op.drop_table("pack_test_results", schema="ccf")
    op.drop_table("pack_rules", schema="ccf")
    op.drop_table("pack_evidence_requirements", schema="ccf")
    op.drop_table("pack_mappings", schema="ccf")
    op.drop_table("pack_controls", schema="ccf")
    op.drop_table("pack_install_runs", schema="ccf")
    op.drop_table("compliance_pack_versions", schema="ccf")
    op.drop_table("compliance_packs", schema="ccf")
