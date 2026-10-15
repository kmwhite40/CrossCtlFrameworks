"""Retire KSIs instead of deleting them; keep FedRAMP's per-class statements.

Revision ID: 0093_ksi_retirement
Revises: 0092_evidenced_controls
Create Date: 2026-10-14

The KSI catalog moves from Concord's 51 phase-one indicators to the 46 that
FedRAMP publishes in the Consolidated Rules for 2026 (``FedRAMP/rules``). No
phase-one identifier survives, and every per-system table -- states,
validation history, assessor reviews, exceptions -- references ``ccf.ksis``
with ``ON DELETE CASCADE``. Deleting a superseded indicator would silently
delete a customer's history with it.

``retired_at`` lets ``seed_ksis`` retire what the dataset no longer defines,
the way the workbook ETL retires controls. Readers filter on it through
``ccf.fedramp20x.catalog.current_ksis`` / ``current_ksi_ids``.

No backfill and no retirement here. Seeding is an operator step
(``ccf fedramp20x seed-ksi``), so retiring in the migration would leave a
deployment with zero current KSIs until someone seeded. The cut-over is the
seed: the 2026 rows arrive and the phase-one rows retire in one transaction.

``statement_by_class`` holds FedRAMP's ``varies_by_class`` statements verbatim
(class key -> statement). Five 2026 indicators state a requirement per class
rather than once; Concord does not record a system's class, so nothing chooses
between them yet.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0093_ksi_retirement"
down_revision = "0092_evidenced_controls"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "ksis",
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        schema="ccf",
    )
    op.add_column(
        "ksis",
        sa.Column(
            "statement_by_class",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        schema="ccf",
    )
    op.create_index("ix_ccf_ksis_retired_at", "ksis", ["retired_at"], schema="ccf")


def downgrade() -> None:
    op.drop_index("ix_ccf_ksis_retired_at", table_name="ksis", schema="ccf")
    op.drop_column("ksis", "statement_by_class", schema="ccf")
    op.drop_column("ksis", "retired_at", schema="ccf")
