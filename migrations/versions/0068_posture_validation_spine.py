"""Posture validation spine -- per-resource findings under a control test.

Concord could already define a repeatable control test, run it on a schedule,
record an append-only result, alert, open a POA&M, and resolve on recovery.
What it could not do is say *which* resources failed: status plus a free-text
detail for the whole test, with no resource identity and no
expected-versus-observed.

This adds control_test_resource_results, plus resource counts and the
evaluated expectation on the result, plus provenance and a capability link on
the test.

Vocabulary: control_test_results.status and control_tests.last_status widen
from varchar(8) to varchar(32) so the single vocabulary is
ccf.fedramp20x.VALIDATION_STATUSES -- whose longest member,
'manual_review_required', is 22 characters. ksi_validation_results.status was
already varchar(32) with that vocabulary, so this consolidates two
vocabularies rather than adding a third. Backward-compatible: pass/warn/fail
remain valid.

Tenancy: control_test_resource_results deliberately carries no
organization_id. control_test_results has none either and is policied through
control_tests; poam_milestones chains through poams -> systems. This table
follows that parent-chain shape one hop further. It is therefore NOT added to
GLOBAL_TABLES -- having a policy is what keeps it out of that guard's
unpolicied-table query -- but IS added to EXPECTED_TENANT_ISOLATION_TABLES.

Revision ID: 0068_posture_validation_spine
Revises: 0067_capability_ontology
Create Date: 2026-09-14
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0068_posture_validation_spine"
down_revision = "0067_capability_ontology"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"

# Two hops: resource result -> result -> test (which carries organization_id).
_PREDICATE = (
    "(ccf.current_tenant() IS NULL OR result_id IN ("
    " SELECT r.id FROM ccf.control_test_results r"
    " JOIN ccf.control_tests t ON t.id = r.control_test_id"
    " WHERE t.organization_id = ccf.current_tenant()))"
)


def upgrade() -> None:
    # --- one verdict vocabulary -------------------------------------------
    op.alter_column(
        "control_test_results",
        "status",
        type_=sa.String(32),
        existing_type=sa.String(8),
        existing_nullable=False,
        schema=_SCHEMA,
    )
    op.alter_column(
        "control_tests",
        "last_status",
        type_=sa.String(32),
        existing_type=sa.String(8),
        existing_nullable=True,
        schema=_SCHEMA,
    )

    # --- provenance + capability link on the test -------------------------
    op.add_column(
        "control_tests",
        sa.Column("source", sa.String(16), nullable=False, server_default="authored"),
        schema=_SCHEMA,
    )
    op.add_column(
        "control_tests", sa.Column("check_key", sa.String(128)), schema=_SCHEMA
    )
    op.add_column(
        "control_tests",
        sa.Column(
            "capability_id",
            sa.BigInteger,
            sa.ForeignKey("ccf.capabilities.id", ondelete="SET NULL"),
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_ccf_control_tests_check_key", "control_tests", ["check_key"], schema=_SCHEMA
    )
    op.create_index(
        "ix_ccf_control_tests_capability",
        "control_tests",
        ["capability_id"],
        schema=_SCHEMA,
    )
    # Nulls are distinct in Postgres unique indexes, so authored tests
    # (check_key NULL) are deliberately unconstrained while a generated
    # (system_id, check_key) pair can exist only once -- which is what makes
    # re-scanning idempotent.
    op.create_unique_constraint(
        "uq_control_test_system_check",
        "control_tests",
        ["system_id", "check_key"],
        schema=_SCHEMA,
    )

    # --- resource counts + evaluated expectation on the result ------------
    op.add_column(
        "control_test_results",
        sa.Column("evaluated", sa.Integer, nullable=False, server_default="0"),
        schema=_SCHEMA,
    )
    op.add_column(
        "control_test_results",
        sa.Column("failing", sa.Integer, nullable=False, server_default="0"),
        schema=_SCHEMA,
    )
    op.add_column("control_test_results", sa.Column("expected", sa.Text), schema=_SCHEMA)

    # --- the per-resource findings ----------------------------------------
    op.create_table(
        "control_test_resource_results",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "result_id",
            sa.BigInteger,
            sa.ForeignKey("ccf.control_test_results.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("resource_id", sa.String(512), nullable=False),
        sa.Column("resource_type", sa.String(64), nullable=False),
        sa.Column("verdict", sa.String(32), nullable=False),
        sa.Column("observed", sa.Text),
        sa.Column("detail", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_ctrr_result", "control_test_resource_results", ["result_id"], schema=_SCHEMA
    )
    # "every failing resource in this org" is a core query, not a scan.
    op.create_index(
        "ix_ctrr_verdict", "control_test_resource_results", ["verdict"], schema=_SCHEMA
    )
    op.create_index(
        "ix_ctrr_type_verdict",
        "control_test_resource_results",
        ["resource_type", "verdict"],
        schema=_SCHEMA,
    )

    # Standard grant guard: no-op where the ccf_app role was never created.
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )

    op.execute("ALTER TABLE ccf.control_test_resource_results ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE ccf.control_test_resource_results FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON ccf.control_test_resource_results "
        f"FOR ALL USING {_PREDICATE} WITH CHECK {_PREDICATE}"
    )


def downgrade() -> None:
    op.drop_table("control_test_resource_results", schema=_SCHEMA)
    for col in ("expected", "failing", "evaluated"):
        op.drop_column("control_test_results", col, schema=_SCHEMA)
    op.drop_constraint(
        "uq_control_test_system_check", "control_tests", schema=_SCHEMA, type_="unique"
    )
    op.drop_index("ix_ccf_control_tests_capability", "control_tests", schema=_SCHEMA)
    op.drop_index("ix_ccf_control_tests_check_key", "control_tests", schema=_SCHEMA)
    for col in ("capability_id", "check_key", "source"):
        op.drop_column("control_tests", col, schema=_SCHEMA)
    # Statuses are left widened: a value written under 0068 (e.g.
    # 'manual_review_required') would not fit varchar(8), so narrowing would
    # fail on real data.
