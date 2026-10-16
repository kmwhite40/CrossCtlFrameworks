"""Automated methods for a KSI: posture checks that evidence it, never decide it.

Revision ID: 0094_ksi_methods
Revises: 0093_ksi_retirement
Create Date: 2026-10-15

FRC-CSX-VVK asks a 20x provider for "automated methods to persistently verify
and validate" each KSI (at least 1 for Class B, 2 for C, 4 for D). Most 2026
KSIs state that an effectiveness review is *persistently* performed, which no
configuration check can prove -- but a check can contradict one. So a KSI
carries a curated list of Concord platform posture checks
(``rules_data/ksi_rules.json``), each with the rationale for why its failure
contradicts the indicator's statement. A failing method raises the KSI to
``warn``; a passing one is recorded as evidence; neither produces ``pass``.

``methods`` is ``[{"check": <posture check key>, "rationale": <text>}]``.
Additive, no backfill: the next ``ccf fedramp20x seed-ksi`` fills it.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0094_ksi_methods"
down_revision = "0093_ksi_retirement"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "ksis",
        sa.Column(
            "methods",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        schema="ccf",
    )


def downgrade() -> None:
    op.drop_column("ksis", "methods", schema="ccf")
