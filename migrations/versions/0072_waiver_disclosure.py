"""Disclose active waivers in the 20x readiness snapshot.

A waiver suppresses a failing control test's consequence (notification,
remediation task, POA&M) while leaving the recorded finding untouched. Before
this migration nothing in the readiness/package surface reported that a
waiver was in force: an ISSO could waive a control before its first failure
and the finding would never generate a POA&M, and no artifact an assessor
reads would disclose the acceptance either. ``fedramp20x_readiness_snapshots``
already carries ``open_exceptions`` as a detractor for ``KSIException`` --
this adds a parallel, distinct ``active_waivers`` column for the same
disclosure role. It is deliberately not merged with ``open_exceptions``: an
exception is a disclosure that suppresses nothing, a waiver suppresses, and
counting them as one quantity would misstate both.

``server_default='0'`` backfills existing rows (historical snapshots, taken
before waivers existed, correctly show zero) without requiring a data
migration.

Revision ID: 0071_waiver_disclosure
Revises: 0071_waivers
Create Date: 2026-09-16
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0072_waiver_disclosure"
down_revision = "0071_waivers"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"


def upgrade() -> None:
    op.add_column(
        "fedramp20x_readiness_snapshots",
        sa.Column("active_waivers", sa.Integer(), nullable=False, server_default="0"),
        schema=_SCHEMA,
    )


def downgrade() -> None:
    op.drop_column("fedramp20x_readiness_snapshots", "active_waivers", schema=_SCHEMA)
