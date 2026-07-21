"""Close two tenant-isolation gaps: ``poam_milestones`` and ``organizations``.

Both tables carry no ``tenant_isolation`` RLS policy today: ``poam_milestones``
(a tenant child of ``poams``, which is itself scoped via its owning ``systems``
row) is cross-tenant readable/writable at the DB layer, and ``organizations``
(the tenant root) lets any scoped tenant enumerate every organization in the
system. This migration adds the missing policies, following the 0032 pattern
(ENABLE + FORCE ROW LEVEL SECURITY, then a ``tenant_isolation`` policy wrapped
in the ``ccf.current_tenant() IS NULL OR ...`` bypass used for
unscoped/global/CLI sessions).

``poam_milestones`` has no direct tenant column, so its predicate walks the
parent chain: ``poam_id -> poams.system_id -> systems.organization_id``.

``organizations`` is scoped directly on its own primary key: a tenant may only
see its own row. This is safe for existing unauthenticated/global flows
because every such flow runs with the session tenant GUC unset (``NULL`` —
see ``ccf.db.session_scope`` for CLI/ETL and ``ccf.api.deps.get_session`` for
global/anonymous principals), and ``NULL`` is exactly what the bypass clause
allows through unfiltered. Only requests bound to a specific tenant (which
already app-layer-filter ``Organization.id == org`` wherever they touch this
table) are newly enforced at the DB layer too.

Revision ID: 0039_poam_milestones_org_rls
Revises: 0038_poam_source_ref
Create Date: 2026-07-21
"""

from __future__ import annotations

from alembic import op

revision = "0039_poam_milestones_org_rls"
down_revision = "0038_poam_source_ref"
branch_labels = None
depends_on = None

_POLICIES = {
    "poam_milestones": (
        "poam_id IN (SELECT p.id FROM ccf.poams p JOIN ccf.systems s ON s.id = p.system_id "
        "WHERE s.organization_id = ccf.current_tenant())"
    ),
    "organizations": "id = ccf.current_tenant()",
}


def upgrade() -> None:
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
        op.execute(f"ALTER TABLE ccf.{table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE ccf.{table} DISABLE ROW LEVEL SECURITY")
