"""Tenant-scope ``framework_controls`` (DATA-03).

``ccf.framework_controls`` carries no ``organization_id`` and no RLS today,
yet it is a tenant-facing upload target
(``POST /api/framework-controls/{code}[/csv]`` ->
``ccf.api.routes.automation._upsert_controls``). Its old unique key —
global ``(framework_code, identifier)`` — means one tenant's upload
silently overwrites another tenant's rows for the same framework code, and
every tenant can read every other tenant's uploaded controls.

This migration adds ``organization_id`` (nullable — NULL marks a
globally-shared/seeded reference row, visible to every tenant; non-NULL
marks a tenant-uploaded row, visible only to that tenant), replaces the
global unique constraint with ``(organization_id, framework_code,
identifier)``, and adds the ``tenant_isolation`` RLS policy. The predicate
follows the ``audit_log``/0044 three-way shape (own org, or NULL/global,
or unscoped bypass) rather than the plain two-way ownership check most
tables use, since NULL-org rows must stay visible to every scoped tenant.

Every existing row predates per-tenant uploads (there was no
``organization_id`` column for the app to have written), so they are
backfilled to NULL (global) rather than guessed into an org — this is the
same "unknown owner -> unscoped/global" convention used for
``audit_log`` system events in 0044. The dedupe step is a defensive no-op
given the old constraint already enforced global uniqueness on
``(framework_code, identifier)`` (so no two rows can collide on the new,
strictly-more-specific key), but it's included for the same safety reason
0040 includes one: it makes this migration correct even if that invariant
is ever violated out from under it.

Revision ID: 0046_framework_controls_org_rls
Revises: 0045_soft_delete_systems_orgs
Create Date: 2026-07-21
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0046_framework_controls_org_rls"
down_revision = "0045_soft_delete_systems_orgs"
branch_labels = None
depends_on = None

_TABLE = "framework_controls"
_OLD_CONSTRAINT = "uq_framework_control"
_NEW_CONSTRAINT = "uq_framework_control"  # same name, new column set
_PREDICATE = (
    "(ccf.current_tenant() IS NULL OR organization_id IS NULL "
    "OR organization_id = ccf.current_tenant())"
)


def _dedupe(columns: list[str], where: str | None) -> None:
    partition = ", ".join(columns)
    select_sql = (
        f"SELECT id, ROW_NUMBER() OVER (PARTITION BY {partition} ORDER BY id) AS rn "
        f"FROM ccf.{_TABLE}"
    )
    if where:
        select_sql += f" WHERE {where}"
    op.execute(
        f"DELETE FROM ccf.{_TABLE} t "
        f"USING ({select_sql}) ranked "
        f"WHERE t.id = ranked.id AND ranked.rn > 1"
    )


def upgrade() -> None:
    op.add_column(
        _TABLE,
        sa.Column(
            "organization_id",
            sa.Integer,
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
        ),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_framework_controls_organization_id", _TABLE, ["organization_id"], schema="ccf"
    )

    # Defensive dedupe (see module docstring): collapses any rows the new,
    # strictly-more-specific unique constraint would reject, keeping the
    # lowest id. All existing rows are NULL-org at this point, so this only
    # ever fires if the pre-existing global uniqueness was somehow already
    # violated.
    _dedupe(["organization_id", "framework_code", "identifier"], "organization_id IS NULL")

    op.drop_constraint(_OLD_CONSTRAINT, _TABLE, schema="ccf", type_="unique")
    op.create_unique_constraint(
        _NEW_CONSTRAINT, _TABLE, ["organization_id", "framework_code", "identifier"], schema="ccf"
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

    op.drop_constraint(_NEW_CONSTRAINT, _TABLE, schema="ccf", type_="unique")
    # Going back to a global (framework_code, identifier) unique constraint
    # can now collide across orgs (that's the whole point of this migration),
    # so dedupe on the OLD key shape first, keeping the lowest id.
    _dedupe(["framework_code", "identifier"], None)
    op.create_unique_constraint(
        _OLD_CONSTRAINT, _TABLE, ["framework_code", "identifier"], schema="ccf"
    )

    op.drop_index(
        "ix_ccf_framework_controls_organization_id", table_name=_TABLE, schema="ccf"
    )
    op.drop_column(_TABLE, "organization_id", schema="ccf")
