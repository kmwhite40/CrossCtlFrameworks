"""Concord-on-Concord self-assurance run record.

Adds ``self_assurance_runs`` (tenant-isolated) — a point-in-time record of a
Concord self-assessment. Everything else reuses existing tables.

Revision ID: 0035_self_assurance
Revises: 0034_compliance_packs
Create Date: 2026-07-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0035_self_assurance"
down_revision = "0034_compliance_packs"
branch_labels = None
depends_on = None

_ORG = "organization_id = ccf.current_tenant()"


def upgrade() -> None:
    op.create_table(
        "self_assurance_runs",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "organization_id", sa.Integer,
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
        ),
        sa.Column("system_id", sa.Integer, sa.ForeignKey("ccf.systems.id", ondelete="CASCADE")),
        sa.Column("readiness_pct", sa.Float, nullable=False, server_default="0"),
        sa.Column("checks_total", sa.Integer, nullable=False, server_default="0"),
        sa.Column("checks_passed", sa.Integer, nullable=False, server_default="0"),
        sa.Column("summary", postgresql.JSONB, server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_self_assurance_org", "self_assurance_runs", ["organization_id"], schema="ccf"
    )
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ccf.self_assurance_runs TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    expr = f"(ccf.current_tenant() IS NULL OR {_ORG})"
    op.execute("ALTER TABLE ccf.self_assurance_runs ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE ccf.self_assurance_runs FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation ON ccf.self_assurance_runs "
        f"FOR ALL USING {expr} WITH CHECK {expr}"
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON ccf.self_assurance_runs")
    op.drop_table("self_assurance_runs", schema="ccf")
