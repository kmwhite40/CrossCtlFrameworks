"""Record where a promoted POA&M acceptance rationale came from.

Revision ID: 0117_poam_rationale_provenance
Revises: 0116_outbox_trigger_nullable
Create Date: 2026-11-09

The CR26 re-seed copies a rationale a person typed into the stored AVI into a
blank ``poams.acceptance_rationale`` (spec 9.1). Now that the event bus
re-seeds automatically, the POA&M must not read as if someone typed it there:
``acceptance_rationale_provenance`` names the document it came from, who last
saved that document and when, and who ran the promotion. NULL for a rationale
written on the POA&M itself. Existing rows (including 0080's backfill) stay
NULL: their source was not recorded and is not guessed.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0117_poam_rationale_provenance"
down_revision = "0116_outbox_trigger_nullable"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "poams",
        sa.Column("acceptance_rationale_provenance", JSONB(), nullable=True),
        schema="ccf",
    )


def downgrade() -> None:
    op.drop_column("poams", "acceptance_rationale_provenance", schema="ccf")
