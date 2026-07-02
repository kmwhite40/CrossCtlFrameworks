"""Evidence confidence scoring + reproducibility.

Adds ``evidence_objects.source_type`` and the confidence/reproducibility tables
(``evidence_confidence_scores``, ``evidence_reproducibility_checks``,
``evidence_source_trust_policies``, ``evidence_replay_runs``), all tenant-isolated
by ``organization_id`` under the standard RLS policy.

Revision ID: 0030_evidence_confidence
Revises: 0029_assurance_graph
Create Date: 2026-07-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0030_evidence_confidence"
down_revision = "0029_assurance_graph"
branch_labels = None
depends_on = None

JB = postgresql.JSONB
_ORG = "organization_id = ccf.current_tenant()"
_POLICIES = {
    "evidence_confidence_scores": _ORG,
    "evidence_reproducibility_checks": _ORG,
    "evidence_source_trust_policies": _ORG,
    "evidence_replay_runs": _ORG,
}


def _org_col() -> sa.Column:
    return sa.Column(
        "organization_id", sa.Integer, sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE")
    )


def _obj_fk() -> sa.Column:
    return sa.Column(
        "evidence_object_id", sa.Integer,
        sa.ForeignKey("ccf.evidence_objects.id", ondelete="CASCADE"), nullable=False,
    )


def upgrade() -> None:
    op.add_column(
        "evidence_objects",
        sa.Column("source_type", sa.String(32), nullable=False, server_default="manual_upload"),
        schema="ccf",
    )

    op.create_table(
        "evidence_confidence_scores",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _org_col(),
        _obj_fk(),
        sa.Column("version_id", sa.BigInteger),
        sa.Column("score", sa.Float, nullable=False, server_default="0"),
        sa.Column("band", sa.String(16), nullable=False, server_default="low"),
        sa.Column("source_type", sa.String(32), nullable=False, server_default="manual_upload"),
        sa.Column("reproducible", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("factors", JB, server_default="{}", nullable=False),
        sa.Column("computed_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("evidence_object_id", name="uq_evidence_confidence_object"),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_evidence_conf_org", "evidence_confidence_scores", ["organization_id"], schema="ccf"
    )
    op.create_index(
        "ix_ccf_evidence_conf_obj", "evidence_confidence_scores",
        ["evidence_object_id"], schema="ccf",
    )

    op.create_table(
        "evidence_reproducibility_checks",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _org_col(),
        _obj_fk(),
        sa.Column("reproducible", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("method", sa.String(24), nullable=False, server_default="none"),
        sa.Column("detail", sa.Text),
        sa.Column("checked_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_evidence_repro_obj", "evidence_reproducibility_checks",
        ["evidence_object_id"], schema="ccf",
    )

    op.create_table(
        "evidence_source_trust_policies",
        sa.Column("id", sa.Integer, primary_key=True),
        _org_col(),
        sa.Column("source_type", sa.String(32), nullable=False),
        sa.Column("base_trust", sa.Float, nullable=False, server_default="0.5"),
        sa.Column("max_age_days", sa.Integer),
        sa.Column("require_review", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("organization_id", "source_type", name="uq_evidence_trust_policy"),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_evidence_trust_org", "evidence_source_trust_policies",
        ["organization_id"], schema="ccf",
    )

    op.create_table(
        "evidence_replay_runs",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _org_col(),
        _obj_fk(),
        sa.Column("status", sa.String(16), nullable=False, server_default="error"),
        sa.Column("detail", JB, server_default="{}", nullable=False),
        sa.Column("ran_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_evidence_replay_obj", "evidence_replay_runs",
        ["evidence_object_id"], schema="ccf",
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
    op.drop_table("evidence_replay_runs", schema="ccf")
    op.drop_table("evidence_source_trust_policies", schema="ccf")
    op.drop_table("evidence_reproducibility_checks", schema="ccf")
    op.drop_table("evidence_confidence_scores", schema="ccf")
    op.drop_column("evidence_objects", "source_type", schema="ccf")
