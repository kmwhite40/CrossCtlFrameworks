"""Rejection columns and the calibration snapshot table.

``PROPOSAL_STATES`` has declared ``rejected`` since the assessment engine
migration, but nothing writes it: acceptance is fully modeled and rejection is
not, so today the system can only ever record an assessor agreeing with a
proposal. This adds the other half -- the four columns a rejection needs on
``assessment_control_proposals`` -- and ``calibration_snapshots``, a
point-in-time measurement of how often the engine's findings matched what
assessors ultimately decided.

Revision ID: 0057_reject_and_calibration
Revises: 0056_objective_proposal_ai_run
Create Date: 2026-08-11
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0057_reject_and_calibration"
down_revision = "0056_objective_proposal_ai_run"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"
_PROPOSALS = "assessment_control_proposals"
_SNAPSHOTS = "calibration_snapshots"
JB = postgresql.JSONB


def upgrade() -> None:
    op.add_column(
        _PROPOSALS, sa.Column("corrected_finding", sa.String(32)), schema=_SCHEMA
    )
    op.add_column(
        _PROPOSALS, sa.Column("rejected_by", sa.String(255)), schema=_SCHEMA
    )
    op.add_column(
        _PROPOSALS,
        sa.Column("rejected_at", sa.DateTime(timezone=True)),
        schema=_SCHEMA,
    )
    op.add_column(
        _PROPOSALS, sa.Column("rejection_note", sa.Text()), schema=_SCHEMA
    )

    op.create_table(
        _SNAPSHOTS,
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey(f"{_SCHEMA}.organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("config_fingerprint", sa.String(64), nullable=False),
        sa.Column("metrics", JB, nullable=False, server_default=sa.text("'{}'")),
        sa.Column(
            "computed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_calibration_snapshots_organization_id",
        _SNAPSHOTS,
        ["organization_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_calibration_snapshots_config_fingerprint",
        _SNAPSHOTS,
        ["config_fingerprint"],
        schema=_SCHEMA,
    )

    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app")


def downgrade() -> None:
    op.drop_table(_SNAPSHOTS, schema=_SCHEMA)
    op.drop_column(_PROPOSALS, "rejection_note", schema=_SCHEMA)
    op.drop_column(_PROPOSALS, "rejected_at", schema=_SCHEMA)
    op.drop_column(_PROPOSALS, "rejected_by", schema=_SCHEMA)
    op.drop_column(_PROPOSALS, "corrected_finding", schema=_SCHEMA)
