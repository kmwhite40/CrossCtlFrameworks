"""Concord's own pipeline stage on a system.

One nullable column, independent of ``baseline``, ``certification_class`` and
``certification_path``. It records where CONCORD understands a system to be --
an operator's note to themselves -- and is NOT a status FedRAMP conferred and
NOT what the FedRAMP Marketplace says: FedRAMP has published no status
enumeration, and the five-per-regime lists these members borrow their words
from appear only in RFC-0020, a proposal. See
``docs/superpowers/specs/2026-09-21-pipeline-stage-design.md``.

The regime is part of each value rather than living in a second column, so the
impossible pair "Rev5 + Persistent Validation" is unrepresentable -- no check
constraint to write and no second column to disagree with.

Null means "nobody has said", which is correct for every existing row: no
platform signal can establish a stage, so nothing is backfilled.

Revision ID: 0082_pipeline_stage
Revises: 0081_cr26_document_key
Create Date: 2026-09-21
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0082_pipeline_stage"
down_revision = "0081_cr26_document_key"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"
# Spelled out here independently of ``ccf.constants.PIPELINE_STAGES`` -- a
# migration must not shift under a later edit to application code. Nothing
# else cross-checks the two, which is why
# tests/test_pipeline_stage_columns.py INSERTs every member.
_STAGE = sa.Enum(
    "rev5:preparation",
    "rev5:agency-authorization-in-process",
    "rev5:assessment-by-fedramp",
    "rev5:continuous-monitoring",
    "rev5:remediation",
    "20x:preparation",
    "20x:prioritized",
    "20x:assessment-by-fedramp",
    "20x:persistent-validation",
    "20x:remediation",
    name="pipeline_stage",
    schema=_SCHEMA,
)


def upgrade() -> None:
    bind = op.get_bind()
    _STAGE.create(bind, checkfirst=True)
    op.add_column(
        "systems",
        sa.Column("pipeline_stage", _STAGE, nullable=True),
        schema=_SCHEMA,
    )
    # Standard since 0054: grant only if the role exists, so a developer
    # database without ccf_app migrates cleanly.
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    # No RLS change: systems is an existing tenant table and already carries its
    # own direct-shape policy. No new table, so no isolation count moves.


def downgrade() -> None:
    op.drop_column("systems", "pipeline_stage", schema=_SCHEMA)
    bind = op.get_bind()
    _STAGE.drop(bind, checkfirst=True)
