"""Soft-delete for systems + organizations (DATA-04).

Deleting a System or Organization today issues a hard ``DELETE``, which
``CASCADE``s away every dependent authorization record — POA&Ms, assessments,
evidence, control implementations, risks, scoring statuses — irreversibly.
Adds a nullable ``deleted_at`` timestamp to both tables so the delete routes
can mark a row gone (hiding it from inventory/list/get queries and from
``org_systems_subq`` tenant scoping) without ever triggering the cascade.

This is deliberately minimal: it does not change any FK's ``ondelete``
behavior (a hard-delete path, gated behind an explicit guard, remains
available for operators who really want to purge a row with no dependents).
Converting every cascade FK to ``RESTRICT`` is a larger follow-up, not needed
to stop the accidental-cascade footgun this migration closes.

Revision ID: 0045_soft_delete_systems_orgs
Revises: 0044_audit_log_org_rls
Create Date: 2026-07-21
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0045_soft_delete_systems_orgs"
down_revision = "0044_audit_log_org_rls"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "systems", sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True), schema="ccf"
    )
    op.add_column(
        "organizations",
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        schema="ccf",
    )
    # Partial indexes: fast "active rows" scans without bloating the index
    # with the (rarely queried) soft-deleted rows.
    op.execute(
        "CREATE INDEX ix_ccf_systems_active ON ccf.systems (id) WHERE deleted_at IS NULL"
    )
    op.execute(
        "CREATE INDEX ix_ccf_organizations_active ON ccf.organizations (id) "
        "WHERE deleted_at IS NULL"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ccf.ix_ccf_organizations_active")
    op.execute("DROP INDEX IF EXISTS ccf.ix_ccf_systems_active")
    op.drop_column("organizations", "deleted_at", schema="ccf")
    op.drop_column("systems", "deleted_at", schema="ccf")
