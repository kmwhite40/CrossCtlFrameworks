"""Let a CR26 deliverable be keyed within (system_id, kind), not just filed once.

``cr26_documents`` has held one row per ``(system_id, kind)`` since 0079, and
that is correct for the six deliverables shipped so far (``cpo``, ``sdr``,
``ocr``, and the periodic-snapshot ``vdr``/``avi``/``ver_history``): each is
either current-state or a snapshot that is meant to be overwritten.

Two deliverables still to be built are not that shape. The Incident Report's
``providerTrackingId`` "must be consistent across IIR, OIR, and FIR reports"
-- one incident produces three reports over its lifecycle (Initial, Ongoing,
Final), and a system has many incidents concurrently. One row per
``(system_id, "incident")`` would mean filing a Final report for incident A
and then an Initial for incident B **overwrites the filed federal incident
report for A** -- a compliance record destroyed by an unrelated filing.
Significant Change Notifications have the same per-instance shape. This
migration makes the store *able* to hold such documents; it does not build
either deliverable -- that is separate work, gated on this.

``document_key`` is nullable. A NULL key is what every one of the six shipped
deliverables continues to use, and the migration does not backfill a value
for any existing row -- their identity stays exactly ``(system_id, kind)``.

**The trap, and the reason this migration exists in this shape.** Postgres
treats NULLs as *distinct* from one another in an ordinary unique constraint.
Measured on this server before writing this migration::

    create temp table t (a int, b text, k text, unique (a,b,k));
    insert into t values (1,'sdr',null);
    insert into t values (1,'sdr',null);   -- BOTH ACCEPTED

A plain ``UNIQUE (system_id, kind, document_key)`` would therefore silently
allow a second ``sdr`` row (or ``cpo``, or any of the other five) for the same
system, because both rows' ``document_key`` is NULL and NULL <> NULL under the
default rule. That destroys the one-row-per-system invariant every shipped
deliverable's seeder and every read helper (``ocr._current``, ``sdr._current``,
``cpo._current``, ``ver._current``, the ``GET`` route) depends on, and no
existing test would catch it -- they all insert against a fresh system, never
two rows with the same NULL key.

The fix, also measured on this server::

    create temp table t2 (a int, b text, k text, unique nulls not distinct (a,b,k));
    insert into t2 values (1,'sdr',null);
    insert into t2 values (1,'sdr',null);  -- second insert: UniqueViolation

``NULLS NOT DISTINCT`` is PostgreSQL 15+ syntax. CI pins
``pgvector/pgvector:pg16`` and this database reports 16.14, so 15+ is a safe
floor here; on an older server the ``CREATE ... NULLS NOT DISTINCT`` DDL is a
syntax error, so the migration fails loudly at apply time rather than
silently creating the broken (NULLS DISTINCT) constraint above. In
SQLAlchemy 2.0.51 (confirmed installed) this is
``postgresql_nulls_not_distinct=True`` on ``UniqueConstraint`` /
``op.create_unique_constraint`` -- verified directly against this database
(a scratch table, both statements above) before relying on it here, rather
than assumed from the changelog. Had it been unsupported, the fallback is
raw ``op.execute("... UNIQUE NULLS NOT DISTINCT (...)")`` DDL.

Tenancy: this adds a COLUMN to the existing ``ccf.cr26_documents`` table, not
a new table, so it does not touch
``tests/test_rls_coverage.py``'s ``EXPECTED_TENANT_ISOLATION_TABLES`` count
(138) -- ``cr26_documents`` was already in it as of 0079.

**Downgrade** refuses loudly rather than silently discarding data: if any row
carries a non-NULL ``document_key`` when downgrading, that row's identity
depends on the very column being dropped -- for a filed incident report or
SCN, dropping it and reinstating the old two-column constraint would either
collapse two distinct filed documents onto one row (an overwrite indistin-
guishable from data loss) or fail outright once two such rows share a
``(system_id, kind)``. Silently deleting a filed federal report is not an
option, so ``downgrade()`` counts keyed rows first and raises rather than
proceeding if any exist. A downgrade is only ever a no-op in practice on this
branch, because nothing yet writes a non-NULL key; the guard exists for the
first migration downgrade *after* the incident/SCN deliverable ships.

Revision ID: 0081_cr26_document_key
Revises: 0080_poam_acceptance_rationale
Create Date: 2026-09-19
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0081_cr26_document_key"
down_revision = "0080_poam_acceptance_rationale"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"
_TABLE = "cr26_documents"
_OLD_CONSTRAINT = "uq_cr26_document_system_kind"
_NEW_CONSTRAINT = "uq_cr26_document_system_kind_key"


def upgrade() -> None:
    op.add_column(
        _TABLE,
        sa.Column("document_key", sa.String(length=128), nullable=True),
        schema=_SCHEMA,
    )
    op.drop_constraint(_OLD_CONSTRAINT, _TABLE, schema=_SCHEMA, type_="unique")
    op.create_unique_constraint(
        _NEW_CONSTRAINT,
        _TABLE,
        ["system_id", "kind", "document_key"],
        schema=_SCHEMA,
        postgresql_nulls_not_distinct=True,
    )


def downgrade() -> None:
    bind = op.get_bind()
    keyed = bind.execute(
        sa.text(f"SELECT count(*) FROM {_SCHEMA}.{_TABLE} WHERE document_key IS NOT NULL")
    ).scalar_one()
    if keyed:
        raise RuntimeError(
            f"cannot downgrade 0081_cr26_document_key: {keyed} row(s) in "
            f"{_SCHEMA}.{_TABLE} carry a non-NULL document_key. Dropping the "
            "column would discard the identity that keeps those documents "
            "distinct from others of the same (system_id, kind) -- e.g. a "
            "filed federal incident report or significant change "
            "notification -- which this migration refuses to do silently. "
            "Resolve or export those rows by hand before downgrading."
        )
    op.drop_constraint(_NEW_CONSTRAINT, _TABLE, schema=_SCHEMA, type_="unique")
    op.drop_column(_TABLE, "document_key", schema=_SCHEMA)
    op.create_unique_constraint(
        _OLD_CONSTRAINT, _TABLE, ["system_id", "kind"], schema=_SCHEMA
    )
