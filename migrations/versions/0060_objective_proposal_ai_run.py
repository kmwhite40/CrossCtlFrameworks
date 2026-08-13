"""Add the AI-provenance FK to assessment_objective_proposals.

An accepted objective verdict can become a finding in a Security Assessment
Report and auto-create a POA&M, but until now nothing recorded which model
produced it. ``ccf.ai_actions.provenance.record_ai_run`` (added alongside this
migration) writes the ``ai_action_runs`` row; this column is where the
objective proposal points at it. Nullable because recording is best-effort --
see that module's docstring for why a failed recording must not fail the
evaluation it documents -- and because historical rows predate this column
entirely.

Revision ID: 0056_objective_proposal_ai_run
Revises: 0055_assessment_engine
Create Date: 2026-08-11
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0056_objective_proposal_ai_run"
down_revision = "0055_assessment_engine"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"
_TABLE = "assessment_objective_proposals"
_INDEX = "ix_assessment_objective_proposals_ai_action_run_id"


def upgrade() -> None:
    op.add_column(
        _TABLE,
        sa.Column(
            "ai_action_run_id",
            sa.BigInteger(),
            sa.ForeignKey("ccf.ai_action_runs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        _INDEX,
        _TABLE,
        ["ai_action_run_id"],
        schema=_SCHEMA,
    )

    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app")


def downgrade() -> None:
    op.drop_index(_INDEX, table_name=_TABLE, schema=_SCHEMA)
    op.drop_column(_TABLE, "ai_action_run_id", schema=_SCHEMA)
