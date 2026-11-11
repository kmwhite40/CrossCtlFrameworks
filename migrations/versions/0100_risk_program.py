"""Risk program: enterprise risks get an owner, assessments and treatment plans.

Revision ID: 0100_risk_program
Revises: 0099_grc_program
Create Date: 2026-10-20

Before this, ``risks`` was scoped only through ``system_id`` (RLS and every
query), so a risk with no system -- an enterprise risk -- belonged to no
tenant: invisible to its organization and unreachable by any scoped query.

- ``risks.organization_id``: backfilled from the system; a trigger keeps it
  equal to the system's organization whenever a system is set, so a
  system-linked risk can never carry a different owner. A system-less risk is
  owned directly.
- The ``tenant_isolation`` policy on ``risks`` admits a row when either its
  ``organization_id`` or its system belongs to the tenant. The system clause
  is kept so nothing that relied on it changes.
- ``risks.register``: ``enterprise`` or ``cyber``. Backfilled: no system ->
  enterprise, otherwise cyber.
- ``risk_assessments`` (dated qualitative and quantitative assessments),
  ``risk_treatment_plans`` and ``risk_treatment_actions``: tenant tables with
  their own ``organization_id`` and the standard forced policy.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0100_risk_program"
down_revision = "0099_grc_program"
branch_labels = None
depends_on = None

_PREDICATE = "(ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant())"
_TABLES = ("risk_assessments", "risk_treatment_plans", "risk_treatment_actions")

_RISKS_PREDICATE_OLD = (
    "(ccf.current_tenant() IS NULL OR system_id IN "
    "(SELECT systems.id FROM ccf.systems WHERE systems.organization_id = ccf.current_tenant()))"
)
_RISKS_PREDICATE_NEW = (
    "(ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant() OR system_id IN "
    "(SELECT systems.id FROM ccf.systems WHERE systems.organization_id = ccf.current_tenant()))"
)


def upgrade() -> None:
    op.add_column(
        "risks",
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
            nullable=True,
        ),
        schema="ccf",
    )
    op.create_index("ix_ccf_risks_organization_id", "risks", ["organization_id"], schema="ccf")
    op.add_column(
        "risks",
        sa.Column("register", sa.String(16), nullable=False, server_default="cyber"),
        schema="ccf",
    )
    op.execute(
        "UPDATE ccf.risks r SET organization_id = s.organization_id "
        "FROM ccf.systems s WHERE s.id = r.system_id"
    )
    op.execute("UPDATE ccf.risks SET register = 'enterprise' WHERE system_id IS NULL")
    op.create_check_constraint(
        "ck_risk_register", "risks", "register IN ('enterprise', 'cyber')", schema="ccf"
    )

    # A system-linked risk always carries its system's organization.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION ccf.risk_owner_from_system() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          IF NEW.system_id IS NOT NULL THEN
            SELECT organization_id INTO NEW.organization_id
              FROM ccf.systems WHERE id = NEW.system_id;
          END IF;
          RETURN NEW;
        END $$
        """
    )
    op.execute(
        "CREATE TRIGGER risk_owner_from_system BEFORE INSERT OR UPDATE OF system_id, "
        "organization_id ON ccf.risks FOR EACH ROW EXECUTE FUNCTION ccf.risk_owner_from_system()"
    )

    op.execute("DROP POLICY IF EXISTS tenant_isolation ON ccf.risks")
    op.execute(
        f"CREATE POLICY tenant_isolation ON ccf.risks FOR ALL "
        f"USING {_RISKS_PREDICATE_NEW} WITH CHECK {_RISKS_PREDICATE_NEW}"
    )

    op.create_table(
        "risk_assessments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "risk_id",
            sa.Integer(),
            sa.ForeignKey("ccf.risks.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("assessed_on", sa.Date(), nullable=False),
        sa.Column("method", sa.String(16), nullable=False),
        sa.Column("likelihood_score", sa.Integer()),
        sa.Column("impact_score", sa.Integer()),
        sa.Column("inherent_score", sa.Integer()),
        sa.Column("residual_score", sa.Integer()),
        sa.Column("sle", sa.Float()),
        sa.Column("aro", sa.Float()),
        sa.Column("ale", sa.Float()),
        sa.Column("assessor", sa.String(255)),
        sa.Column("notes", sa.Text()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        schema="ccf",
    )
    op.create_table(
        "risk_treatment_plans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "risk_id",
            sa.Integer(),
            sa.ForeignKey("ccf.risks.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("strategy", sa.String(16), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column(
            "owner_user_id", sa.Integer(), sa.ForeignKey("ccf.users.id", ondelete="SET NULL")
        ),
        sa.Column("due_on", sa.Date()),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("target_residual_score", sa.Integer()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        schema="ccf",
    )
    op.create_table(
        "risk_treatment_actions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "plan_id",
            sa.Integer(),
            sa.ForeignKey("ccf.risk_treatment_plans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column(
            "owner_user_id", sa.Integer(), sa.ForeignKey("ccf.users.id", ondelete="SET NULL")
        ),
        sa.Column("due_on", sa.Date()),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("poam_id", sa.Integer(), sa.ForeignKey("ccf.poams.id", ondelete="SET NULL")),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        schema="ccf",
    )
    for table, col in (
        ("risk_assessments", "risk_id"),
        ("risk_treatment_plans", "risk_id"),
        ("risk_treatment_actions", "plan_id"),
    ):
        op.create_index(f"ix_ccf_{table}_{col}", table, [col], schema="ccf")
        op.create_index(f"ix_ccf_{table}_organization_id", table, ["organization_id"], schema="ccf")

    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    for table in _TABLES:
        op.execute(f"ALTER TABLE ccf.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE ccf.{table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON ccf.{table} "
            f"FOR ALL USING {_PREDICATE} WITH CHECK {_PREDICATE}"
        )


def downgrade() -> None:
    for table in reversed(_TABLES):
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON ccf.{table}")
        op.drop_table(table, schema="ccf")
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON ccf.risks")
    op.execute(
        f"CREATE POLICY tenant_isolation ON ccf.risks FOR ALL "
        f"USING {_RISKS_PREDICATE_OLD} WITH CHECK {_RISKS_PREDICATE_OLD}"
    )
    op.execute("DROP TRIGGER IF EXISTS risk_owner_from_system ON ccf.risks")
    op.execute("DROP FUNCTION IF EXISTS ccf.risk_owner_from_system()")
    op.drop_constraint("ck_risk_register", "risks", schema="ccf")
    op.drop_column("risks", "register", schema="ccf")
    op.drop_index("ix_ccf_risks_organization_id", table_name="risks", schema="ccf")
    op.drop_column("risks", "organization_id", schema="ccf")
