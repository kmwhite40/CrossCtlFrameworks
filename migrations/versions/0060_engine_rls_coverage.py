"""RLS coverage for the eleven engine tables slices 1-6 built without it.

110 of the 135 tables in the ccf schema carry a tenant_isolation policy.
prep_runs, prep_lines, prep_screens, prep_units, prep_classifications,
prep_embeddings, prep_jobs, assessment_jobs, calibration_snapshots,
assessment_control_proposals, and assessment_objective_proposals do not --
every one of them tenant data with no database backstop, sitting directly
beside tables (assessment_control_results, poams, evidence) that have one.
All eleven carry organization_id directly (verified against
information_schema.columns), so none needs the parent-join derivation poams
(system_id -> systems.organization_id) or assessment_control_results
(assessment_id -> assessments -> systems) use -- the policy is the simplest
form in the codebase, identical predicate and policy name to the other 110
(see e.g. migrations 0020, 0022): `current_tenant() IS NULL OR
organization_id = current_tenant()`. `current_tenant() IS NULL` means
*unrestricted* -- CLI/ETL/migrations/global principals stay unaffected, the
same semantics every existing RLS-backed table already uses.

FORCE is required, not optional: the owning role (`ccf`) bypasses its own
policy without it, which would produce a policy that exists, reports as
enabled, and is bypassed on exactly the connections the application uses --
checked live, not assumed: all 135 ccf tables are owned by role `ccf`, and
all 110 pre-existing RLS tables already carry FORCE.

See docs/superpowers/specs/2026-08-12-rls-coverage-design.md for the full
reasoning, including why the eleven tables' worker/CLI code paths are left
deliberately unscoped by session_scope() rather than fixed here (Task 2 of
the implementation plan audits and documents that as a named exception, not
a gap this migration needs to close).

Revision ID: 0060_engine_rls_coverage
Revises: 0059_ai_dissent_path
Create Date: 2026-08-12
"""

from __future__ import annotations

from alembic import op

revision = "0060_engine_rls_coverage"
down_revision = "0059_ai_dissent_path"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"

#: Every table verified live to carry organization_id directly and no
#: tenant_isolation policy as of this writing (see the design doc's "The
#: policy" section). Order is alphabetical within the prep chain then the
#: assessment-engine chain, matching models_prep.py / models_assessment_engine.py.
TENANT_TABLES: tuple[str, ...] = (
    "prep_runs",
    "prep_lines",
    "prep_screens",
    "prep_units",
    "prep_classifications",
    "prep_embeddings",
    "prep_jobs",
    "assessment_control_proposals",
    "assessment_objective_proposals",
    "assessment_jobs",
    "calibration_snapshots",
)

_PREDICATE = "(ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant())"


def upgrade() -> None:
    # Matches 0054's exact block (the repo standard 0057 and 0058 both
    # omitted): a no-op if ccf_app doesn't exist in this environment (e.g. a
    # dev DB that never split roles), and otherwise ensures every table in
    # the schema is usable by the scoped application role regardless of
    # which role actually ran the migrations.
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE ccf.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE ccf.{table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON ccf.{table} "
            f"FOR ALL USING {_PREDICATE} WITH CHECK {_PREDICATE}"
        )


def downgrade() -> None:
    for table in TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON ccf.{table}")
        op.execute(f"ALTER TABLE ccf.{table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE ccf.{table} DISABLE ROW LEVEL SECURITY")
    # The GRANT is intentionally not reversed -- every prior migration that
    # re-issues it does the same (see 0037, 0054), since revoking a blanket
    # grant on downgrade could strand other, unrelated tables whose own
    # migrations already ran and still need it.
