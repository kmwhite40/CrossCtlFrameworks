"""CR26 Certification Class and Path on a system.

Two nullable columns, independent of ``baseline`` and of each other. FedRAMP
states a Certification Class is not a one-for-one replacement for an impact
level, and the published adequacy ranges overlap, so nothing derives one from
the other. Null means "not CR26-certified" -- correct for every existing row
and for the whole Rev5 lane, which is why neither column is backfilled.

Revision ID: 0078_cr26_certification
Revises: 0077_cci_source_spine
Create Date: 2026-09-16
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0078_cr26_certification"
down_revision = "0077_cci_source_spine"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"
_CLASS = sa.Enum("A", "B", "C", "D", name="certification_class", schema=_SCHEMA)
_PATH = sa.Enum("program", "agency", name="certification_path", schema=_SCHEMA)


def upgrade() -> None:
    bind = op.get_bind()
    _CLASS.create(bind, checkfirst=True)
    _PATH.create(bind, checkfirst=True)
    op.add_column(
        "systems",
        sa.Column("certification_class", _CLASS, nullable=True),
        schema=_SCHEMA,
    )
    op.add_column(
        "systems",
        sa.Column("certification_path", _PATH, nullable=True),
        schema=_SCHEMA,
    )
    # Standard since 0054: grant only if the role exists, so a developer
    # database without ccf_app migrates cleanly.
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    # No RLS change: systems is an existing tenant table and already carries its
    # own direct-shape policy. No new table, so no isolation count moves.


def downgrade() -> None:
    op.drop_column("systems", "certification_path", schema=_SCHEMA)
    op.drop_column("systems", "certification_class", schema=_SCHEMA)
    bind = op.get_bind()
    _PATH.drop(bind, checkfirst=True)
    _CLASS.drop(bind, checkfirst=True)
