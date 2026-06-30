"""Database-enforced tenant isolation via PostgreSQL row-level security.

Adds a defense-in-depth backstop beneath the application-layer org scoping: every
tenant-owned table is filtered by ``ccf.current_tenant()`` (read from the
``ccf.tenant_id`` session GUC the app sets per request). When the GUC is unset the
policies treat it as *bypass* (full access) so CLI/ETL, migrations, and
unscoped/global principals keep working unchanged. ``FORCE ROW LEVEL SECURITY``
makes the policies apply to the table-owning ``ccf`` role too.
"""

from __future__ import annotations

from alembic import op

revision = "0010_row_level_security"
down_revision = "0009_assessment_results"
branch_labels = None
depends_on = None

# table -> predicate selecting rows that belong to the current tenant.
_SYS = "system_id IN (SELECT id FROM ccf.systems WHERE organization_id = ccf.current_tenant())"
TENANT_POLICIES: dict[str, str] = {
    "users": "organization_id = ccf.current_tenant()",
    "systems": "organization_id = ccf.current_tenant()",
    "ssp_projects": "organization_id = ccf.current_tenant()",
    "control_implementations": _SYS,
    "assessments": _SYS,
    "poams": _SYS,
    "risks": _SYS,
    "scoring_statuses": _SYS,
    "evidence": (
        "implementation_id IN (SELECT ci.id FROM ccf.control_implementations ci "
        "JOIN ccf.systems s ON s.id = ci.system_id "
        "WHERE s.organization_id = ccf.current_tenant())"
    ),
    "assessment_results": (
        "assessment_id IN (SELECT a.id FROM ccf.assessments a "
        "JOIN ccf.systems s ON s.id = a.system_id "
        "WHERE s.organization_id = ccf.current_tenant())"
    ),
    "assessment_control_results": (
        "assessment_id IN (SELECT a.id FROM ccf.assessments a "
        "JOIN ccf.systems s ON s.id = a.system_id "
        "WHERE s.organization_id = ccf.current_tenant())"
    ),
    "ssp_control_entries": (
        "project_id IN (SELECT id FROM ccf.ssp_projects "
        "WHERE organization_id = ccf.current_tenant())"
    ),
}


def upgrade() -> None:
    # Non-superuser application role that RLS policies actually apply to. The app
    # connects as the bootstrap superuser and `SET ROLE ccf_app` per scoped
    # request, so no second login/password is introduced.
    op.execute(
        "DO $$ BEGIN "
        "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "CREATE ROLE ccf_app NOLOGIN; END IF; END $$"
    )
    op.execute("GRANT ccf_app TO CURRENT_USER")
    for schema in ("ccf", "ccf_audit"):
        op.execute(f"GRANT USAGE ON SCHEMA {schema} TO ccf_app")
        op.execute(
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {schema} TO ccf_app"
        )
        op.execute(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {schema} TO ccf_app")
        op.execute(
            f"ALTER DEFAULT PRIVILEGES IN SCHEMA {schema} "
            "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ccf_app"
        )
        op.execute(
            f"ALTER DEFAULT PRIVILEGES IN SCHEMA {schema} "
            "GRANT USAGE, SELECT ON SEQUENCES TO ccf_app"
        )

    op.execute(
        "CREATE OR REPLACE FUNCTION ccf.current_tenant() RETURNS integer "
        "LANGUAGE sql STABLE AS $$ "
        "SELECT NULLIF(current_setting('ccf.tenant_id', true), '')::integer $$"
    )
    for table, predicate in TENANT_POLICIES.items():
        expr = f"(ccf.current_tenant() IS NULL OR {predicate})"
        op.execute(f"ALTER TABLE ccf.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE ccf.{table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON ccf.{table} "
            f"FOR ALL USING {expr} WITH CHECK {expr}"
        )


def downgrade() -> None:
    for table in TENANT_POLICIES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON ccf.{table}")
        op.execute(f"ALTER TABLE ccf.{table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE ccf.{table} DISABLE ROW LEVEL SECURITY")
    op.execute("DROP FUNCTION IF EXISTS ccf.current_tenant()")
    # Revoke this database's grants/default-privileges from ccf_app. The role is
    # cluster-global and may still be in use by another database (e.g. the test
    # DB on the same server), so we drop the per-database grants but leave the
    # (login-less, harmless) role in place rather than fail on a cross-DB dependency.
    op.execute(
        "DO $$ BEGIN "
        "IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "DROP OWNED BY ccf_app; END IF; END $$"
    )
