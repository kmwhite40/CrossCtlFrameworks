"""Close two production-readiness gaps left by earlier migrations.

1. **RLS coverage** — 0010/0020 established the tenant-isolation backstop but only
   covered ~26 tables. Every remaining tenant-owned table (org-scoped operational
   data, the enterprise-governance layer, and the GRC-OS layer) is brought under
   the same ``ccf.current_tenant()`` policy here, using the identical
   "unset GUC = bypass" semantics so CLI/ETL/migrations/global principals are
   unaffected. Tables scoped by ``organization_id`` filter directly; tables scoped
   by ``system_id`` / a parent FK filter via the parent's organization.

2. **Missing FK indexes** — several hot foreign-key / cascade columns declared
   ``index=True`` on the ORM were never given a single-column index by 0001, so
   joins and cascade-deletes sequentially scanned. They are added here
   (``IF NOT EXISTS`` — safe to re-run and idempotent against partially-indexed DBs).

Revision ID: 0022_rls_coverage_and_fk_indexes
Revises: 0021_grc_os
Create Date: 2026-07-02
"""

from __future__ import annotations

from alembic import op

revision = "0022_rls_coverage_and_fk_indexes"
down_revision = "0021_grc_os"
branch_labels = None
depends_on = None

_ORG = "organization_id = ccf.current_tenant()"
_SYS = "system_id IN (SELECT id FROM ccf.systems WHERE organization_id = ccf.current_tenant())"
_ENGAGEMENT = (
    "engagement_id IN (SELECT id FROM ccf.audit_engagements "
    "WHERE organization_id = ccf.current_tenant())"
)
_POLICY = "policy_id IN (SELECT id FROM ccf.policies WHERE organization_id = ccf.current_tenant())"
_POLICY_VERSION = (
    "policy_version_id IN (SELECT pv.id FROM ccf.policy_versions pv "
    "JOIN ccf.policies p ON p.id = pv.policy_id "
    "WHERE p.organization_id = ccf.current_tenant())"
)
_CONTROL_TEST = (
    "control_test_id IN (SELECT id FROM ccf.control_tests "
    "WHERE organization_id = ccf.current_tenant())"
)

# table -> predicate selecting rows that belong to the current tenant.
TENANT_POLICIES: dict[str, str] = {
    # organization_id directly on the row
    "tasks": _ORG,
    "notifications": _ORG,
    "events": _ORG,
    "artifacts": _ORG,
    "policies": _ORG,
    "vendors": _ORG,
    "approvals": _ORG,
    "capture_snapshots": _ORG,
    "monitoring_runs": _ORG,
    "connector_configs": _ORG,
    "webhooks": _ORG,
    "control_tests": _ORG,
    "trust_profiles": _ORG,
    "trust_access_requests": _ORG,
    "regulatory_updates": _ORG,
    "audit_engagements": _ORG,
    # scoped via a parent relationship
    "system_profiles": _SYS,
    "audit_requests": _ENGAGEMENT,
    "audit_findings": _ENGAGEMENT,
    "policy_versions": _POLICY,
    "policy_attestations": _POLICY_VERSION,
    "control_test_results": _CONTROL_TEST,
}

# (table, column, index_name) — single-column FK/scan indexes 0001 omitted.
FK_INDEXES: list[tuple[str, str, str]] = [
    ("control_implementations", "control_id", "ix_ccf_control_implementations_control_id"),
    ("evidence", "implementation_id", "ix_ccf_evidence_implementation_id"),
    ("assessment_results", "assessment_id", "ix_ccf_assessment_results_assessment_id"),
    ("assessment_results", "implementation_id", "ix_ccf_assessment_results_implementation_id"),
    ("assessments", "system_id", "ix_ccf_assessments_system_id"),
    ("poams", "system_id", "ix_ccf_poams_system_id"),
    ("audit_engagements", "organization_id", "ix_ccf_audit_engagements_organization_id"),
    ("connector_configs", "organization_id", "ix_ccf_connector_configs_organization_id"),
    ("control_tests", "organization_id", "ix_ccf_control_tests_organization_id"),
    ("regulatory_updates", "organization_id", "ix_ccf_regulatory_updates_organization_id"),
    ("trust_access_requests", "organization_id", "ix_ccf_trust_access_requests_organization_id"),
]


def upgrade() -> None:
    # Keep the application role's grants current for these tables (0010 set default
    # privileges, but grant explicitly so this migration is self-contained).
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    for table, predicate in TENANT_POLICIES.items():
        expr = f"(ccf.current_tenant() IS NULL OR {predicate})"
        op.execute(f"ALTER TABLE ccf.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE ccf.{table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON ccf.{table} "
            f"FOR ALL USING {expr} WITH CHECK {expr}"
        )

    for table, column, name in FK_INDEXES:
        op.execute(f"CREATE INDEX IF NOT EXISTS {name} ON ccf.{table} ({column})")


def downgrade() -> None:
    for _, _, name in FK_INDEXES:
        op.execute(f"DROP INDEX IF EXISTS ccf.{name}")
    for table in TENANT_POLICIES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON ccf.{table}")
        op.execute(f"ALTER TABLE ccf.{table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE ccf.{table} DISABLE ROW LEVEL SECURITY")
