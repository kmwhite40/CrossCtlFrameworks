"""Due-diligence items record who received them.

Revision ID: 0102_dd_received_by
Revises: 0101_parent_org_invariants
Create Date: 2026-10-20

Receiving an item (recording the vendor's document and where it is) and
accepting it are separate duties: the reviewer must not be the person who
received it. ``received_by`` is what the review compares against. Existing
received items have no recorded receiver and stay NULL; accepting or
rejecting one is refused until its receipt is recorded again, so the two
people can be compared -- the safe direction.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0102_dd_received_by"
down_revision = "0101_parent_org_invariants"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "due_diligence_items",
        sa.Column("received_by", sa.String(255), nullable=True),
        schema="ccf",
    )


def downgrade() -> None:
    op.drop_column("due_diligence_items", "received_by", schema="ccf")
