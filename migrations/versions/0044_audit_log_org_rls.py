"""Per-tenant audit-log isolation (DATA-06).

Adds ``organization_id`` to ``ccf.audit_log`` — nullable, since system/global
events (CLI/ETL, unauthenticated mutations, migrations) have no resolvable
tenant and must stay visible to every scoped tenant as well as the unscoped
bypass. This is a SCOPING column only: it is deliberately excluded from the
``row_hash``/``prev_hash`` chain payload computed in ``ccf.api.audit``, so
existing chains and ``/api/audit/verify`` are unaffected by this migration or
by the middleware change that populates it going forward.

RLS follows the 0032/0039 pattern (ENABLE + FORCE ROW LEVEL SECURITY, then a
``tenant_isolation`` policy), but with a three-way predicate instead of the
usual two-way one: a scoped tenant sees its own org's rows *and* NULL-org
(system) rows, while the unscoped/global bypass (``current_tenant() IS NULL``)
sees everything, same as elsewhere.

Revision ID: 0044_audit_log_org_rls
Revises: 0043_connector_credentials
Create Date: 2026-07-21
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0044_audit_log_org_rls"
down_revision = "0043_connector_credentials"
branch_labels = None
depends_on = None

_TABLE = "audit_log"
_PREDICATE = (
    "(ccf.current_tenant() IS NULL OR organization_id IS NULL "
    "OR organization_id = ccf.current_tenant())"
)


def upgrade() -> None:
    op.add_column(_TABLE, sa.Column("organization_id", sa.Integer), schema="ccf")
    op.create_index(
        "ix_ccf_audit_log_organization_id", _TABLE, ["organization_id"], schema="ccf"
    )
    op.execute(f"ALTER TABLE ccf.{_TABLE} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE ccf.{_TABLE} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation ON ccf.{_TABLE} "
        f"FOR ALL USING {_PREDICATE} WITH CHECK {_PREDICATE}"
    )


def downgrade() -> None:
    op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON ccf.{_TABLE}")
    op.execute(f"ALTER TABLE ccf.{_TABLE} NO FORCE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE ccf.{_TABLE} DISABLE ROW LEVEL SECURITY")
    op.drop_index("ix_ccf_audit_log_organization_id", table_name=_TABLE, schema="ccf")
    op.drop_column(_TABLE, "organization_id", schema="ccf")
