"""Record who wrote each acceptance rationale in an AVI.

Revision ID: 0118_cr26_rationale_authors
Revises: 0117_poam_rationale_provenance
Create Date: 2026-11-09

``cr26_documents.updated_by`` names whoever last saved the whole document, so a
POA&M whose rationale the re-seed promotes from the AVI was attributed to the
last editor of any entry. ``rationale_authors`` maps each entry's
``providerTrackingId`` to ``{"by", "at"}`` of the person who wrote or last
changed that rationale, kept beside the document (which must stay
schema-valid). Existing rows start empty: who wrote their rationales was never
recorded and is not guessed.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0118_cr26_rationale_authors"
down_revision = "0117_poam_rationale_provenance"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "cr26_documents",
        sa.Column("rationale_authors", JSONB(), nullable=False, server_default="{}"),
        schema="ccf",
    )


def downgrade() -> None:
    op.drop_column("cr26_documents", "rationale_authors", schema="ccf")
