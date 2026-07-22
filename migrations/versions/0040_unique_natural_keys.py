"""Unique constraints on natural keys that currently allow duplicates.

Closes the DATA-08 / DATA-10 findings from the integrity validator
(``docs/superpowers/assessments/integrity_checks.py``): ``vendors``,
``policies``, ``fedramp_dependencies``, ``pack_mappings``, and ``people`` each
have a natural key that the ORM/API treat as identifying (repeated
create/reconcile flows look records up by it) but that the schema never
enforced, so retries or races can accumulate duplicate rows.

``organization_id`` is nullable on ``vendors``/``policies``/``people``, and
Postgres treats each NULL as distinct for uniqueness purposes — a
``UNIQUE (organization_id, name)`` constraint does *not* reject two
organization-less rows with the same name. The dedupe below mirrors that
exactly: it only collapses rows that the new constraint would actually
reject (non-NULL key columns), so it never deletes data the constraint
wouldn't have blocked in the first place. ``fedramp_dependencies.system_id``
and all of ``pack_mappings``' key columns are NOT NULL, so those two dedupes
run unconditionally.

Each dedupe keeps the lowest ``id`` per natural key and deletes the rest,
via a ``ROW_NUMBER() OVER (PARTITION BY ...)`` self-join — safe to re-run
(a second pass finds no ``rn > 1`` rows once the first pass has run).

Revision ID: 0040_unique_natural_keys
Revises: 0039_poam_milestones_org_rls
Create Date: 2026-07-21
"""

from __future__ import annotations

from alembic import op

revision = "0040_unique_natural_keys"
down_revision = "0039_poam_milestones_org_rls"
branch_labels = None
depends_on = None

# table -> (constraint name, key columns, extra dedupe WHERE clause or None)
_NATURAL_KEYS: list[tuple[str, str, list[str], str | None]] = [
    (
        "vendors",
        "uq_vendor_org_name",
        ["organization_id", "name"],
        "organization_id IS NOT NULL",
    ),
    (
        "policies",
        "uq_policy_org_name",
        ["organization_id", "name"],
        "organization_id IS NOT NULL",
    ),
    (
        "fedramp_dependencies",
        "uq_fedramp_dep_system_name",
        ["system_id", "name"],
        None,
    ),
    (
        "pack_mappings",
        "uq_pack_mapping_pack_control_framework",
        ["pack_id", "control_id", "framework"],
        None,
    ),
    (
        "people",
        "uq_person_org_email",
        ["organization_id", "email"],
        "organization_id IS NOT NULL AND email IS NOT NULL",
    ),
]


def _dedupe(table: str, columns: list[str], where: str | None) -> None:
    partition = ", ".join(columns)
    select_sql = (
        f"SELECT id, ROW_NUMBER() OVER (PARTITION BY {partition} ORDER BY id) AS rn "
        f"FROM ccf.{table}"
    )
    if where:
        select_sql += f" WHERE {where}"
    op.execute(
        f"DELETE FROM ccf.{table} t "
        f"USING ({select_sql}) ranked "
        f"WHERE t.id = ranked.id AND ranked.rn > 1"
    )


def upgrade() -> None:
    for table, constraint, columns, where in _NATURAL_KEYS:
        _dedupe(table, columns, where)
        op.create_unique_constraint(constraint, table, columns, schema="ccf")


def downgrade() -> None:
    for table, constraint, _columns, _where in _NATURAL_KEYS:
        op.drop_constraint(constraint, table, schema="ccf", type_="unique")
