"""Close two production-readiness gaps in the prep tables (0052).

**Missing blanket GRANT.** Ten prior feature migrations (e.g. 0037) re-issue
``GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO
ccf_app`` after adding new tables, because a deployment that migrates as a
role other than ``ccf_app`` itself needs it re-issued: 0010's ``ALTER DEFAULT
PRIVILEGES`` only covers objects created by the *same* migrating role. 0052
added seven ``prep_*`` tables without re-issuing that grant. It has worked so
far only because this app's own Docker/CI setup happens to migrate as the
same role application requests run as -- a deployment that migrates as a
different role would get ``permission denied for table ccf.prep_units`` for
every scoped tenant the moment it tried to use the pipeline. Fixed here,
rather than by editing 0052 directly, because 0052 has already shipped in
this branch's own history and other environments may already have run it —
editing a migration that has already been applied elsewhere is exactly the
kind of drift Alembic's linear revision chain exists to prevent.

**Missing GIN index on ``prep_classifications.control_identifiers``.** The
tagged-boost half of hybrid retrieval (``ccf.prep.retriever._tagged_ids``)
queries this column with jsonb ``@>`` containment on every single retrieval
call. Without an index, that is a sequential scan of the whole table every
time. A plain (default ``jsonb_ops``) GIN index, matching the existing
pattern for JSONB columns elsewhere in this schema (e.g.
``idx_controls_audit_payload_gin`` in the 0001 baseline), supports ``@>``
directly.

Revision ID: 0054_prep_grants_gin
Revises: 0053_ccf_app_search_path
Create Date: 2026-08-10
"""

from __future__ import annotations

from alembic import op

revision = "0054_prep_grants_gin"
down_revision = "0053_ccf_app_search_path"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"
_INDEX = "ix_prep_classifications_control_identifiers_gin"


def upgrade() -> None:
    # Matches 0037's exact block (and every other migration that re-issues
    # this grant): a no-op if ccf_app doesn't exist in this environment (e.g.
    # a dev DB that never split roles), and otherwise ensures every table in
    # the schema -- prep_* included -- is usable by the scoped application
    # role regardless of which role actually ran the migrations.
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    op.create_index(
        _INDEX,
        "prep_classifications",
        ["control_identifiers"],
        postgresql_using="gin",
        schema=_SCHEMA,
    )


def downgrade() -> None:
    op.drop_index(_INDEX, table_name="prep_classifications", schema=_SCHEMA)
    # The GRANT is intentionally not reversed: every prior migration that
    # re-issues it does the same (see 0037's own downgrade), since revoking a
    # blanket grant on downgrade could strand other, unrelated tables that
    # still need it and whose own migrations already ran.
