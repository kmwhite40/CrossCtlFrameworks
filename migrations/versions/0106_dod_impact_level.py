"""Systems declare their DoD Cloud Computing SRG impact level.

Revision ID: 0106_dod_impact_level
Revises: 0105_ports_and_crypto
Create Date: 2026-10-20

The IL5 checks (GovCloud partition, services in AWS's DoD SRG scope,
customer-managed keys) answer a question only for a system that is a DoD
system at a known level. Nothing recorded that, so this column does; NULL
means "not a DoD system / not declared", and those checks then report
not_applicable instead of judging against a level nobody chose.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0106_dod_impact_level"
down_revision = "0105_ports_and_crypto"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("systems", sa.Column("dod_impact_level", sa.String(4)), schema="ccf")
    op.create_check_constraint(
        "ck_systems_dod_impact_level",
        "systems",
        "dod_impact_level IS NULL OR dod_impact_level IN ('IL2', 'IL4', 'IL5', 'IL6')",
        schema="ccf",
    )


def downgrade() -> None:
    op.drop_constraint("ck_systems_dod_impact_level", "systems", schema="ccf")
    op.drop_column("systems", "dod_impact_level", schema="ccf")
