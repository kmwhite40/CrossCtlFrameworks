"""Row-level security for the FedRAMP 20x system-owned tables.

Extends the tenant-isolation backstop from 0010 to the 20x layer. Every 20x table
keyed by ``system_id`` is filtered by ``ccf.current_tenant()``; the ``ksis``
reference catalog stays open (org-agnostic, like ``controls``/``scoring_controls``).
Unset tenant GUC = bypass, so CLI/ETL/migrations/global principals are unaffected.

Revision ID: 0020_fedramp_20x_rls
Revises: 0019_fedramp_20x
Create Date: 2026-07-02
"""

from __future__ import annotations

from alembic import op

revision = "0020_fedramp_20x_rls"
down_revision = "0019_fedramp_20x"
branch_labels = None
depends_on = None

_SYS = "system_id IN (SELECT id FROM ccf.systems WHERE organization_id = ccf.current_tenant())"

# All 20x tables are system-scoped; the ``ksis`` catalog is reference data (no RLS).
TENANT_TABLES = (
    "fedramp20x_profiles",
    "ksi_states",
    "ksi_validation_results",
    "ksi_assessor_reviews",
    "ksi_exceptions",
    "fedramp_dependencies",
    "fedramp20x_readiness_snapshots",
)


def upgrade() -> None:
    # Ensure the application role can reach the new tables (0010 set default
    # privileges, but grant explicitly so this migration is self-contained).
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    for table in TENANT_TABLES:
        expr = f"(ccf.current_tenant() IS NULL OR {_SYS})"
        op.execute(f"ALTER TABLE ccf.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE ccf.{table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON ccf.{table} "
            f"FOR ALL USING {expr} WITH CHECK {expr}"
        )


def downgrade() -> None:
    for table in TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON ccf.{table}")
        op.execute(f"ALTER TABLE ccf.{table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE ccf.{table} DISABLE ROW LEVEL SECURITY")
