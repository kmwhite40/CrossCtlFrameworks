"""Record WHICH model produced an AI action's output, not only which vendor.

``ai_action_runs.provider`` already existed and was wrong: it was set from
``settings.ai_provider`` before the call, while ``ai_actions/provider.generate``
ignored its argument and always returned the deterministic stub. So with
``CCF_AI_ENABLED=true`` every run recorded ``provider="anthropic"`` on output no
model had touched -- a false attribution in the one audit trail whose job is to
say what was machine-generated and by what.

``model`` is added because ``ai/gateway.StructuredResult``'s own docstring says
provenance needs both, and because "anthropic" does not identify an output the
way a model name and version do. Nullable: a stub run has no model, and writing
one would repeat the defect this migration accompanies.

Revision ID: 0086_ai_action_run_model
Revises: 0085_mfa_recovery_revocation
Create Date: 2026-09-24
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0086_ai_action_run_model"
down_revision = "0085_mfa_recovery_revocation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "ai_action_runs", sa.Column("model", sa.String(64)), schema="ccf"
    )
    # Existing rows claiming a vendor were produced by the stub -- that is the
    # defect, and every one of them predates any real call. Corrected rather
    # than left asserting something untrue.
    op.execute("UPDATE ccf.ai_action_runs SET provider = 'stub' WHERE provider <> 'stub'")


def downgrade() -> None:
    op.drop_column("ai_action_runs", "model", schema="ccf")
