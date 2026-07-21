"""Stable POA&M back-reference for non-scanner sources.

Adds a generic ``source_ref`` column to ``poams`` — a stable back-reference to
the originating record (e.g. ``assessment:{assessment_control_result_id}``)
that idempotency for any source can key on, mirroring how ``finding_uid``
already keys scanner reconciliation. No RLS change needed: this is a plain
column add to an existing tenant-isolated table.

Revision ID: 0038_poam_source_ref
Revises: 0037_ai_provider_configs
Create Date: 2026-07-21
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0038_poam_source_ref"
down_revision = "0037_ai_provider_configs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("poams", sa.Column("source_ref", sa.String(128)), schema="ccf")
    op.create_index("ix_ccf_poams_source_ref", "poams", ["source_ref"], schema="ccf")


def downgrade() -> None:
    op.drop_index("ix_ccf_poams_source_ref", "poams", schema="ccf")
    op.drop_column("poams", "source_ref", schema="ccf")
