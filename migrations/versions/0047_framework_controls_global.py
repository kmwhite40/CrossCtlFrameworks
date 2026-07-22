"""Restore global uniqueness for NULL-org ``framework_controls`` rows.

0046 replaced the old global unique constraint on ``(framework_code,
identifier)`` with ``(organization_id, framework_code, identifier)`` so that
tenant-uploaded rows (non-NULL ``organization_id``) can coexist per-org.
Postgres unique constraints/indexes default to ``NULLS DISTINCT``, meaning
each NULL is treated as its own, distinct value — so that new constraint no
longer prevents two *global* rows (``organization_id IS NULL``) from
colliding on the same ``(framework_code, identifier)``, which the old
constraint did prevent.

This migration adds a partial unique index scoped to ``organization_id IS
NULL`` to restore that invariant for global/seeded reference rows, without
constraining per-org uploaded rows (which 0046's constraint already keeps
unique per org).

Revision ID: 0047_framework_controls_global
Revises: 0046_framework_controls_org_rls
Create Date: 2026-07-21
"""

from __future__ import annotations

from alembic import op

revision = "0047_framework_controls_global"
down_revision = "0046_framework_controls_org_rls"
branch_labels = None
depends_on = None

_TABLE = "framework_controls"
_INDEX = "uq_framework_controls_global"


def _dedupe_global() -> None:
    """Defensive no-op given 0046 already enforced this (see its docstring's
    dedupe rationale) — collapses any NULL-org duplicates the new partial
    index would otherwise reject, keeping the lowest id.
    """
    op.execute(
        f"DELETE FROM ccf.{_TABLE} t "
        f"USING ("
        f"  SELECT id, ROW_NUMBER() OVER ("
        f"    PARTITION BY framework_code, identifier ORDER BY id"
        f"  ) AS rn "
        f"  FROM ccf.{_TABLE} WHERE organization_id IS NULL"
        f") ranked "
        f"WHERE t.id = ranked.id AND ranked.rn > 1"
    )


def upgrade() -> None:
    _dedupe_global()
    op.execute(
        f"CREATE UNIQUE INDEX {_INDEX} ON ccf.{_TABLE} (framework_code, identifier) "
        f"WHERE organization_id IS NULL"
    )


def downgrade() -> None:
    op.execute(f"DROP INDEX IF EXISTS ccf.{_INDEX}")
