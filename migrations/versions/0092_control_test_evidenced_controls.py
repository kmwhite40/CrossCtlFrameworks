"""Record every control a generated test evidences, not only the first.

Revision ID: 0092_evidenced_controls
Revises: 0091_connector_readiness
Create Date: 2026-09-29

A ``PostureCheck`` declares ``control_ids`` -- "what it evidences", a tuple. A
scan recorded only ``control_ids[0]`` on the ``ControlTest``, so every other
control the check bears on was invisible to the rollups. The MFA check declares
``IA-2`` and ``IA-2(1)``; ``IA-2(1)`` never failed, never passed, and appeared
as unaddressed, which is the coverage the platform actually had understated in
the direction that looks better.

``control_id`` stays and stays primary -- it is what an authored (human) test
has, what the POA&M and waiver paths key on, and what a passing verdict credits.
The new column is additive: the full declared tuple, written on every scan.

No backfill. A null means "this row predates the column", which is exactly
right: nothing here can reconstruct what a check declared at the time a
historical row was written, and writing ``[control_id]`` into old rows would
manufacture a record that the check declared exactly one control. Readers treat
null as ``[control_id]`` (see ``ccf.posture.evidence.evidenced_controls``), and
the next scan fills it in.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0092_evidenced_controls"
down_revision = "0091_connector_readiness"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "control_tests",
        sa.Column("control_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        schema="ccf",
    )


def downgrade() -> None:
    op.drop_column("control_tests", "control_ids", schema="ccf")
