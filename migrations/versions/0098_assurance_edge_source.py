"""Assurance edges name their source; the invented confidence is dropped.

Spec: docs/superpowers/specs/2026-10-15-compliance-graph-design.md §1.

Every edge the builder writes now carries ``source``: a table, a dataset at a
version, or a check source. ``confidence`` held fixed guesses (0.6 for
"connector feeds every system", 0.7 for agent links) that measured nothing.
Rows written before this migration have no provenance; they are labelled
``unsourced:pre-0098`` rather than given one, and the next rebuild replaces
them.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0098_assurance_edge_source"
down_revision = "0097_orgless_digest_alerts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "assurance_edges", sa.Column("source", sa.String(96), nullable=True), schema="ccf"
    )
    op.execute(
        "UPDATE ccf.assurance_edges SET source = 'unsourced:pre-0098' WHERE source IS NULL"
    )
    op.alter_column("assurance_edges", "source", nullable=False, schema="ccf")
    op.drop_column("assurance_edges", "confidence", schema="ccf")


def downgrade() -> None:
    op.add_column(
        "assurance_edges",
        sa.Column("confidence", sa.Float, nullable=False, server_default="1.0"),
        schema="ccf",
    )
    op.drop_column("assurance_edges", "source", schema="ccf")
