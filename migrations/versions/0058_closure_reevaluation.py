"""Closure-triggered re-evaluation: source_poam_id, and the constraint swap
that lets a re-evaluation proposal coexist with the first-pass row it
re-evaluates.

An accepted other_than_satisfied finding now creates a POA&M (the
"bridge" -- see ccf.assessment.engine.service); closing that POA&M must be
able to enqueue a *second*, distinct AssessmentControlProposal for the same
(assessment_id, control_identifier) the first-pass proposal already
occupies. The flat uq_control_proposal_assessment_control constraint that
pair carried since migration 0055 would reject that second row outright, so
it is replaced here by two partial unique indexes: first-pass idempotency
now applies only to source_poam_id-NULL rows, and a second index caps
re-evaluation at one proposal per POA&M.

``downgrade()`` deletes every row carrying a non-NULL source_poam_id before
restoring the flat uq_control_proposal_assessment_control constraint. That
constraint cannot represent the two-rows-per-control state this migration
exists to allow, so a downgrade that left re-evaluation rows in place would
fail outright with a unique-violation the moment a re-evaluation row shared
its (assessment_id, control_identifier) with the first-pass row it
re-evaluates -- exactly the state the test suite's own mid-session
``alembic downgrade base`` resets (see e.g. ``tests/test_ingest.py``'s
``apply_migrations`` fixture) run into in practice, not just in theory.
Deleting the re-evaluation rows is the correct reversal, not a workaround:
they are records of a capability (closure-triggered re-evaluation) that does
not exist below this revision, so a schema that no longer supports them
should not carry them either. First-pass proposals -- the only kind that
existed before 0058 -- are left untouched.

Revision ID: 0058_closure_reevaluation
Revises: 0057_reject_and_calibration
Create Date: 2026-08-11
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0058_closure_reevaluation"
down_revision = "0057_reject_and_calibration"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"
_PROPOSALS = "assessment_control_proposals"


def upgrade() -> None:
    op.add_column(
        _PROPOSALS,
        sa.Column(
            "source_poam_id",
            sa.BigInteger(),
            sa.ForeignKey(f"{_SCHEMA}.poams.id", ondelete="SET NULL"),
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_control_proposal_source_poam_id",
        _PROPOSALS,
        ["source_poam_id"],
        schema=_SCHEMA,
    )

    op.drop_constraint(
        "uq_control_proposal_assessment_control", _PROPOSALS, schema=_SCHEMA, type_="unique"
    )
    op.create_index(
        "uq_control_proposal_first_pass",
        _PROPOSALS,
        ["assessment_id", "control_identifier"],
        unique=True,
        schema=_SCHEMA,
        postgresql_where=sa.text("source_poam_id IS NULL"),
    )
    op.create_index(
        "uq_control_proposal_source_poam",
        _PROPOSALS,
        ["source_poam_id"],
        unique=True,
        schema=_SCHEMA,
        postgresql_where=sa.text("source_poam_id IS NOT NULL"),
    )

    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app")


def downgrade() -> None:
    # Re-evaluation rows have no representation in the pre-0058 schema (a flat
    # unique constraint on (assessment_id, control_identifier) cannot hold both
    # a first-pass row and a re-evaluation row for the same pair) -- delete them
    # before the constraint that would otherwise reject their coexistence with
    # the first-pass row is restored.
    op.execute(f"DELETE FROM {_SCHEMA}.{_PROPOSALS} WHERE source_poam_id IS NOT NULL")
    op.drop_index("uq_control_proposal_source_poam", table_name=_PROPOSALS, schema=_SCHEMA)
    op.drop_index("uq_control_proposal_first_pass", table_name=_PROPOSALS, schema=_SCHEMA)
    op.create_unique_constraint(
        "uq_control_proposal_assessment_control",
        _PROPOSALS,
        ["assessment_id", "control_identifier"],
        schema=_SCHEMA,
    )
    op.drop_index("ix_control_proposal_source_poam_id", table_name=_PROPOSALS, schema=_SCHEMA)
    op.drop_column(_PROPOSALS, "source_poam_id", schema=_SCHEMA)
