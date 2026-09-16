"""Waivers -- accepting a finding without erasing it.

A waiver stops a failing check's consequence (notification, auto remediation
task, POA&M upsert) while the finding itself stays exactly as recorded. The two
columns added to the existing result tables are what make that auditable:
``control_test_resource_results.waiver_id`` says which acceptance covered each
resource, and ``control_test_results.waived`` carries the count beside the
existing ``evaluated``/``failing`` pair so reporting needs no join.

``waiver_id`` is ``ON DELETE SET NULL``, never CASCADE: deleting a waiver must
never delete a recorded observation. The evidence outlives the acceptance.

Tenancy: ``waivers`` carries ``organization_id`` and gets the direct
``organization_id = ccf.current_tenant()`` policy, matching 0067. It is
therefore added to ``EXPECTED_TENANT_ISOLATION_TABLES`` in
``tests/test_rls_coverage.py`` (count 131 -> 132) and NOT to ``GLOBAL_TABLES``.
``control_test_resource_results`` keeps no policy of its own -- it is policied
through its parent chain, as its model docstring explains.

Revision ID: 0070_waivers
Revises: 0070_control_test_check_source
Create Date: 2026-09-15
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0071_waivers"
down_revision = "0070_control_test_check_source"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"
_PREDICATE = "(ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant())"


def upgrade() -> None:
    op.create_table(
        "waivers",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "system_id",
            sa.Integer(),
            sa.ForeignKey("ccf.systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("check_key", sa.String(length=128), nullable=True),
        sa.Column("control_id", sa.String(length=32), nullable=True),
        sa.Column("resource_id", sa.String(length=512), nullable=True),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column(
            "status", sa.String(length=16), nullable=False, server_default="requested"
        ),
        sa.Column("requested_by", sa.String(length=255), nullable=True),
        sa.Column("approved_by", sa.String(length=255), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_on", sa.Date(), nullable=True),
        sa.Column(
            "risk_id", sa.Integer(), sa.ForeignKey("ccf.risks.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "(check_key IS NOT NULL AND control_id IS NULL) "
            "OR (check_key IS NULL AND control_id IS NOT NULL)",
            name="ck_waiver_one_target",
        ),
        sa.CheckConstraint(
            "status IN ('requested', 'approved', 'revoked')", name="ck_waiver_status"
        ),
        schema=_SCHEMA,
    )
    op.create_index("ix_ccf_waivers_org", "waivers", ["organization_id"], schema=_SCHEMA)
    op.create_index("ix_ccf_waivers_system", "waivers", ["system_id"], schema=_SCHEMA)
    op.create_index("ix_ccf_waivers_check_key", "waivers", ["check_key"], schema=_SCHEMA)
    op.create_index("ix_ccf_waivers_control_id", "waivers", ["control_id"], schema=_SCHEMA)
    op.create_index("ix_ccf_waivers_status", "waivers", ["status"], schema=_SCHEMA)
    op.create_index("ix_ccf_waivers_expires_on", "waivers", ["expires_on"], schema=_SCHEMA)

    op.add_column(
        "control_test_results",
        sa.Column("waived", sa.Integer(), nullable=False, server_default="0"),
        schema=_SCHEMA,
    )
    op.add_column(
        "control_test_resource_results",
        sa.Column(
            "waiver_id",
            sa.BigInteger(),
            sa.ForeignKey("ccf.waivers.id", ondelete="SET NULL"),
            nullable=True,
        ),
        schema=_SCHEMA,
    )

    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    op.execute("ALTER TABLE ccf.waivers ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE ccf.waivers FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON ccf.waivers "
        f"FOR ALL USING {_PREDICATE} WITH CHECK {_PREDICATE}"
    )


def downgrade() -> None:
    op.drop_column("control_test_resource_results", "waiver_id", schema=_SCHEMA)
    op.drop_column("control_test_results", "waived", schema=_SCHEMA)
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON ccf.waivers")
    op.drop_table("waivers", schema=_SCHEMA)
