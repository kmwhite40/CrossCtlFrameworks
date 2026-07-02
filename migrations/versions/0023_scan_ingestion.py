"""Vulnerability-scan ingestion → auto-POA&M reconciliation.

Adds the ``scanner`` + ``finding_uid`` reconciliation fields to POA&Ms (so a
re-ingested scan updates/reopens/auto-closes rather than duplicating), and a
``scan_ingestions`` provenance table (tenant-isolated under the same RLS policy
as the rest of the operational layer).

Revision ID: 0023_scan_ingestion
Revises: 0022_rls_coverage_and_fk_indexes
Create Date: 2026-07-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0023_scan_ingestion"
down_revision = "0022_rls_coverage_and_fk_indexes"
branch_labels = None
depends_on = None

_RLS = "(ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant())"


def upgrade() -> None:
    op.add_column("poams", sa.Column("scanner", sa.String(32)), schema="ccf")
    op.add_column("poams", sa.Column("finding_uid", sa.String(64)), schema="ccf")
    op.create_index(
        "ix_ccf_poams_finding_uid", "poams", ["finding_uid"], schema="ccf"
    )
    # Fast reconciliation lookup: all scanner POA&Ms for a system+scanner.
    op.create_index(
        "ix_ccf_poams_system_scanner", "poams", ["system_id", "scanner"], schema="ccf"
    )

    op.create_table(
        "scan_ingestions",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer,
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
        ),
        sa.Column(
            "system_id",
            sa.Integer,
            sa.ForeignKey("ccf.systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("scanner", sa.String(32), nullable=False),
        sa.Column("filename", sa.String(512)),
        sa.Column("findings_total", sa.Integer, nullable=False, server_default="0"),
        sa.Column("poams_created", sa.Integer, nullable=False, server_default="0"),
        sa.Column("poams_updated", sa.Integer, nullable=False, server_default="0"),
        sa.Column("poams_reopened", sa.Integer, nullable=False, server_default="0"),
        sa.Column("poams_closed", sa.Integer, nullable=False, server_default="0"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("summary", postgresql.JSONB, server_default="{}", nullable=False),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_scan_ingestions_org", "scan_ingestions", ["organization_id"], schema="ccf"
    )
    op.create_index(
        "ix_ccf_scan_ingestions_system", "scan_ingestions", ["system_id"], schema="ccf"
    )

    # Keep the application role's grants current, then bring the new table under
    # the same tenant-isolation policy the rest of the operational layer uses.
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ccf.scan_ingestions TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    op.execute("ALTER TABLE ccf.scan_ingestions ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE ccf.scan_ingestions FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation ON ccf.scan_ingestions "
        f"FOR ALL USING {_RLS} WITH CHECK {_RLS}"
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON ccf.scan_ingestions")
    op.drop_table("scan_ingestions", schema="ccf")
    op.drop_index("ix_ccf_poams_system_scanner", "poams", schema="ccf")
    op.drop_index("ix_ccf_poams_finding_uid", "poams", schema="ccf")
    op.drop_column("poams", "finding_uid", schema="ccf")
    op.drop_column("poams", "scanner", schema="ccf")
