"""catalog integrity reports

Advisory OSCAL catalog reconciliation runs (controls/mappings vs. pinned
NIST 800-53r5 catalog). Global catalog data, not tenant-scoped: no RLS
policy, consistent with other non-tenant reference tables (e.g.
``catalog_sources``).

Revision ID: 0051_catalog_integrity_reports
Revises: 0050_evidence_object_impl_fk
Create Date: 2026-07-27
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0051_catalog_integrity_reports"
down_revision = "0050_evidence_object_impl_fk"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "catalog_integrity_reports",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("run_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("oscal_version", sa.String(32)),
        sa.Column("oscal_sha256", sa.String(64)),
        sa.Column("controls_checked", sa.Integer, server_default="0"),
        sa.Column("not_evaluated", sa.Integer, server_default="0"),
        sa.Column("findings_total", sa.Integer, server_default="0"),
        sa.Column("findings_by_severity", postgresql.JSONB, server_default="{}"),
        sa.Column("findings", postgresql.JSONB, server_default="[]"),
        sa.Column("crosswalk", postgresql.JSONB, server_default="{}"),
        sa.Column("summary", postgresql.JSONB, server_default="{}"),
        schema="ccf",
    )


def downgrade() -> None:
    op.drop_table("catalog_integrity_reports", schema="ccf")
