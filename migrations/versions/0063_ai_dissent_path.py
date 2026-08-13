"""AI dissent path: primary/challenger verdict columns on
assessment_objective_proposals, and a dissent_count rollup on
assessment_control_proposals.

A qualifying (satisfied-only) verdict can now be challenged by an
independent second model call, recorded through
ccf.ai_actions.provenance.record_ai_run under its own action_key. Four new
columns on assessment_objective_proposals hold: the primary call's original
verdict (``primary_verdict``, preserved because ``verdict`` itself is
deliberately overwritten to "insufficient_evidence" on a genuine
disagreement, so ccf.assessment.engine.rollup needs no change of its own);
the challenger's own verdict and rationale; and a link to the AiActionRun
that produced the challenge. All four are nullable and all NULL together for
an un-challenged objective (see ccf.assessment.engine.evaluate's module
docstring for the two distinct meanings a NULL can carry).
``primary_verdict`` is recorded rather than inferred from the fact of a
challenge: today's satisfied-only challenge policy would make that inference
sound, but the policy is expected to broaden, and the moment it does, every
previously contested row would become unreadable without this column.
assessment_control_proposals gains dissent_count, NOT NULL with a default of
0, so a reviewer sees how many of a control's objectives were contested
without a join.

Revision ID: 0063_ai_dissent_path
Revises: 0062_closure_reevaluation
Create Date: 2026-08-11
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0063_ai_dissent_path"
down_revision = "0062_closure_reevaluation"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"
_OBJECTIVES = "assessment_objective_proposals"
_CONTROLS = "assessment_control_proposals"
_INDEX = "ix_objective_proposal_challenger_ai_action_run_id"


def upgrade() -> None:
    op.add_column(_OBJECTIVES, sa.Column("primary_verdict", sa.String(32)), schema=_SCHEMA)
    op.add_column(_OBJECTIVES, sa.Column("challenger_verdict", sa.String(32)), schema=_SCHEMA)
    op.add_column(_OBJECTIVES, sa.Column("challenger_rationale", sa.Text()), schema=_SCHEMA)
    op.add_column(
        _OBJECTIVES,
        sa.Column(
            "challenger_ai_action_run_id",
            sa.BigInteger(),
            sa.ForeignKey(f"{_SCHEMA}.ai_action_runs.id", ondelete="SET NULL"),
        ),
        schema=_SCHEMA,
    )
    op.create_index(_INDEX, _OBJECTIVES, ["challenger_ai_action_run_id"], schema=_SCHEMA)

    op.add_column(
        _CONTROLS,
        sa.Column("dissent_count", sa.Integer(), nullable=False, server_default="0"),
        schema=_SCHEMA,
    )

    # Matches 0058's exact block -- the repo standard this migration must
    # carry that 0061 and 0062 both omitted (a bare, unguarded GRANT
    # statement in each): a no-op if ccf_app doesn't exist in this
    # environment (e.g. a dev DB that never split roles), and otherwise
    # ensures every table in the schema is usable by the scoped application
    # role regardless of which role actually ran the migrations.
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )


def downgrade() -> None:
    op.drop_column(_CONTROLS, "dissent_count", schema=_SCHEMA)
    op.drop_index(_INDEX, table_name=_OBJECTIVES, schema=_SCHEMA)
    op.drop_column(_OBJECTIVES, "challenger_ai_action_run_id", schema=_SCHEMA)
    op.drop_column(_OBJECTIVES, "challenger_rationale", schema=_SCHEMA)
    op.drop_column(_OBJECTIVES, "challenger_verdict", schema=_SCHEMA)
    op.drop_column(_OBJECTIVES, "primary_verdict", schema=_SCHEMA)
    # The GRANT is intentionally not reversed -- every prior migration that
    # re-issues it does the same (see 0037, 0058), since revoking a blanket
    # grant on downgrade could strand other, unrelated tables whose own
    # migrations already ran and still need it.
