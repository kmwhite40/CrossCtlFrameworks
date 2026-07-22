"""Bridge control-linked evidence to the evidence repository (DATA-09).

The legacy control-linked ``evidence`` table (FK to ``control_implementations``)
and the versioned ``evidence_objects``/``evidence_versions`` repository
(confidence, review, retention) were two disconnected stores:
``evidence_objects.control_id`` is a free-text tag (e.g. ``"AC-2"``), not a
foreign key, so "evidence supporting control X" could not be joined to that
evidence's confidence/review state.

``evidence_objects`` is where repository rows are actually created (see
``ccf.evidence.service.create_object``); ``evidence`` rows are created
independently and never reference a repository object. So the bridge goes on
the repository side: a nullable ``implementation_id`` FK on
``evidence_objects`` -> ``control_implementations.id``. Nullable because most
existing/new evidence objects are not (yet) tied to a specific control
implementation, and because backfilling from the free-text ``control_id`` tag
would fabricate a linkage that was never actually asserted.

Revision ID: 0050_evidence_object_impl_fk
Revises: 0049_portal_grant_ref_fks
Create Date: 2026-07-22
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0050_evidence_object_impl_fk"
down_revision = "0049_portal_grant_ref_fks"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "evidence_objects",
        sa.Column(
            "implementation_id",
            sa.BigInteger(),
            sa.ForeignKey("ccf.control_implementations.id", ondelete="SET NULL"),
            nullable=True,
        ),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_evidence_objects_implementation_id",
        "evidence_objects",
        ["implementation_id"],
        schema="ccf",
    )


def downgrade() -> None:
    op.drop_index(
        "ix_ccf_evidence_objects_implementation_id",
        table_name="evidence_objects",
        schema="ccf",
    )
    op.drop_column("evidence_objects", "implementation_id", schema="ccf")
