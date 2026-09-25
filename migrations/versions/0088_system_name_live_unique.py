"""A deleted system stops holding its name.

``uq_system_org_name`` was UNIQUE (organization_id, name) with no regard for
``deleted_at``, so deleting a system reserved its name in that organization
permanently: re-creating "Nexus" after deleting "Nexus" was impossible, and
the intake form answered the attempt with a 500. Ten systems across six
organizations were holding names this way when this was written.

Replaced with a partial unique index over live rows only. Soft-deleted rows
are then unconstrained, which is what makes the name reusable, and two deleted
systems may share a name -- correct, since neither is reachable.

Safe to apply: no organization has two live systems sharing a name (checked
against the data, not assumed), because the constraint being replaced
prevented exactly that.

Revision ID: 0088_system_name_live_unique
Revises: 0087_external_issue_links
Create Date: 2026-09-25
"""

from __future__ import annotations

from alembic import op

revision = "0088_system_name_live_unique"
down_revision = "0087_external_issue_links"
branch_labels = None
depends_on = None

_INDEX = "uq_system_org_name_live"


def upgrade() -> None:
    op.drop_constraint("uq_system_org_name", "systems", schema="ccf", type_="unique")
    op.execute(
        f"CREATE UNIQUE INDEX {_INDEX} ON ccf.systems (organization_id, name) "
        "WHERE deleted_at IS NULL"
    )


def downgrade() -> None:
    # Reversing this can fail, and should: if a name was reused after its
    # holder was deleted, restoring the blanket constraint would have to
    # choose which of the two rows to discard. Failing loudly is better than a
    # migration that silently drops a system.
    op.execute(f"DROP INDEX IF EXISTS ccf.{_INDEX}")
    op.create_unique_constraint(
        "uq_system_org_name", "systems", ["organization_id", "name"], schema="ccf"
    )
