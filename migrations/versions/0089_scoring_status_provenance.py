"""Where a SPRS implementation state came from.

``scoring_statuses`` recorded provenance only as free text in ``notes``
(``"derived: platform:m365_gcc_high"``), and nothing cleared it when a person
changed the state afterwards. On the tenant this was found in, three rows read
as platform-derived while holding ``implemented`` -- a state the derivation
cannot produce -- so a human's claim was attributed to Microsoft's placemat.

``source`` makes the distinction structural: ``derived`` for a state the
profile derivation computed, ``assessed`` for one a person or a piece of
evidence set. ``derived_from`` keeps the derivation's own label
(``platform:m365_gcc_high``, ``vendor:Acme``, ``profile:not_applicable``) so a
reader can see which rule credited the control.

Backfill reads the existing notes, with one correction: a derived note is only
believed when the state is one the derivation can actually produce
(``not_applicable``, ``inherited``, ``partial``, ``not_implemented`` -- see
``ccf.governance.automation._COVERAGE_TO_STATE``). ``implemented`` or
``planned`` under a derived note is proof a person overrode it, so those rows
backfill as ``assessed`` with no ``derived_from``: we cannot recover who set
them, but we can stop crediting the platform for them. Their note is a false
statement about where the state came from, so it is cleared -- but only where
it is *exactly* the derivation's own prose and nothing else, because a note a
person added to is theirs and no migration gets to delete it.

Revision ID: 0089_scoring_status_provenance
Revises: 0088_system_name_live_unique
Create Date: 2026-09-25
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0089_scoring_status_provenance"
down_revision = "0088_system_name_live_unique"
branch_labels = None
depends_on = None

#: States ``derive_system`` is able to write. A ``derived:`` note on any other
#: state is stale provenance, not a derivation.
_DERIVABLE = ("not_applicable", "inherited", "partial", "not_implemented")


def upgrade() -> None:
    op.add_column(
        "scoring_statuses",
        sa.Column("source", sa.String(16), nullable=False, server_default="assessed"),
        schema="ccf",
    )
    op.add_column(
        "scoring_statuses",
        sa.Column("derived_from", sa.String(64), nullable=True),
        schema="ccf",
    )
    states = ", ".join(f"'{s}'" for s in _DERIVABLE)
    op.execute(
        f"""
        UPDATE ccf.scoring_statuses
           SET source = 'derived',
               derived_from = left(trim(substring(notes from 10)), 64)
         WHERE notes LIKE 'derived: %'
           AND state IN ({states})
        """
    )
    # A `derived:` note on a state the derivation cannot produce says something
    # untrue about who decided it. Clear it only where the note is nothing but
    # that label -- a single line the derivation wrote and nobody edited.
    op.execute(
        """
        UPDATE ccf.scoring_statuses
           SET notes = NULL
         WHERE source = 'assessed'
           AND notes ~ '^derived: [^[:space:]]+$'
        """
    )
    op.create_index(
        "ix_scoring_statuses_source", "scoring_statuses", ["source"], schema="ccf"
    )


def downgrade() -> None:
    op.drop_index("ix_scoring_statuses_source", table_name="scoring_statuses", schema="ccf")
    op.drop_column("scoring_statuses", "derived_from", schema="ccf")
    op.drop_column("scoring_statuses", "source", schema="ccf")
