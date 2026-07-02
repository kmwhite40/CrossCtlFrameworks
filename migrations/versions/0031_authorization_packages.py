"""Authorization package provenance, diff, and replay.

Adds ``authorization_packages`` + facts/artifacts + diffs + replay runs + delta
memos. Tenant-isolated: org-scoped rows directly; facts/artifacts via parent
package.

Revision ID: 0031_authorization_packages
Revises: 0030_evidence_confidence
Create Date: 2026-07-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0031_authorization_packages"
down_revision = "0030_evidence_confidence"
branch_labels = None
depends_on = None

JB = postgresql.JSONB
_ORG = "organization_id = ccf.current_tenant()"
_PKG = (
    "package_id IN (SELECT id FROM ccf.authorization_packages "
    "WHERE organization_id = ccf.current_tenant())"
)
_POLICIES = {
    "authorization_packages": _ORG,
    "authorization_package_facts": _PKG,
    "authorization_package_artifacts": _PKG,
    "authorization_package_diffs": _ORG,
    "authorization_package_replay_runs": _ORG,
    "authorization_delta_memos": _ORG,
}


def _org_col() -> sa.Column:
    return sa.Column(
        "organization_id", sa.Integer, sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE")
    )


def _pkg_fk() -> sa.Column:
    return sa.Column(
        "package_id", sa.Integer,
        sa.ForeignKey("ccf.authorization_packages.id", ondelete="CASCADE"), nullable=False,
    )


def upgrade() -> None:
    op.create_table(
        "authorization_packages",
        sa.Column("id", sa.Integer, primary_key=True),
        _org_col(),
        sa.Column("system_id", sa.Integer, sa.ForeignKey("ccf.systems.id", ondelete="CASCADE")),
        sa.Column("kind", sa.String(24), nullable=False, server_default="fedramp20x"),
        sa.Column("label", sa.String(255), nullable=False),
        sa.Column("readiness_pct", sa.Float),
        sa.Column("fact_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_by", sa.String(255)),
        sa.Column("summary", JB, server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_auth_packages_org", "authorization_packages", ["organization_id"], schema="ccf"
    )

    op.create_table(
        "authorization_package_facts",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _pkg_fk(),
        sa.Column("fact_type", sa.String(24), nullable=False),
        sa.Column("fact_key", sa.String(255), nullable=False),
        sa.Column("value", sa.Text),
        sa.Column("digest", sa.String(64)),
        sa.Column("metadata", JB, server_default="{}", nullable=False),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_auth_facts_pkg", "authorization_package_facts", ["package_id"], schema="ccf"
    )

    op.create_table(
        "authorization_package_artifacts",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _pkg_fk(),
        sa.Column("artifact_kind", sa.String(24), nullable=False),
        sa.Column("sha256", sa.String(64)),
        sa.Column("media_type", sa.String(128)),
        sa.Column("size_bytes", sa.Integer, nullable=False, server_default="0"),
        sa.Column("storage_ref", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_auth_artifacts_pkg", "authorization_package_artifacts", ["package_id"], schema="ccf"
    )

    op.create_table(
        "authorization_package_diffs",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _org_col(),
        sa.Column("from_package_id", sa.BigInteger),
        sa.Column("to_package_id", sa.BigInteger),
        sa.Column("summary", JB, server_default="{}", nullable=False),
        sa.Column("changes", JB, server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_auth_diffs_org", "authorization_package_diffs", ["organization_id"], schema="ccf"
    )

    op.create_table(
        "authorization_package_replay_runs",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _org_col(),
        _pkg_fk(),
        sa.Column("status", sa.String(16), nullable=False, server_default="reproducible"),
        sa.Column("drift", JB, server_default="{}", nullable=False),
        sa.Column("ran_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_auth_replay_org", "authorization_package_replay_runs",
        ["organization_id"], schema="ccf",
    )

    op.create_table(
        "authorization_delta_memos",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _org_col(),
        sa.Column("system_id", sa.Integer, sa.ForeignKey("ccf.systems.id", ondelete="CASCADE")),
        sa.Column("from_package_id", sa.BigInteger),
        sa.Column("to_package_id", sa.BigInteger),
        sa.Column("since", sa.Date),
        sa.Column("body", sa.Text, nullable=False),
        sa.Column("summary", JB, server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_auth_memos_org", "authorization_delta_memos", ["organization_id"], schema="ccf"
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
    op.drop_table("authorization_delta_memos", schema="ccf")
    op.drop_table("authorization_package_replay_runs", schema="ccf")
    op.drop_table("authorization_package_diffs", schema="ccf")
    op.drop_table("authorization_package_artifacts", schema="ccf")
    op.drop_table("authorization_package_facts", schema="ccf")
    op.drop_table("authorization_packages", schema="ccf")
