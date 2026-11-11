"""ATO workspace: system signing roles, package workflow, POA&M extensions.

Revision ID: 0103_ato_workspace
Revises: 0102_dd_received_by
Create Date: 2026-10-20

Three tables and four columns -- only what the existing models lacked to run an
authorization workflow (docs/superpowers/specs/2026-10-20-ato-workspace-design.md):

* ``system_role_assignments`` -- who the ISSO / ISSM / AO / system owner of a
  system is. Until now these were free-text names in an SSP's metadata, and the
  approval engine checked for an ``authorizing_official`` user role that the
  ``user_role`` enum cannot hold.
* ``authorization_packages.status`` (+ manifest hash, authorization expiry,
  status timestamp) and ``authorization_package_events`` -- a workflow over the
  package snapshots that already existed, with its history.
* ``poam_extensions`` -- a reviewed request for more time on a POA&M.

Existing packages become ``draft``: they were captured and never reviewed.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0103_ato_workspace"
down_revision = "0102_dd_received_by"
branch_labels = None
depends_on = None

_PREDICATE = "(ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant())"
_NEW_TABLES = ("system_role_assignments", "authorization_package_events", "poam_extensions")

_ROLES = ("system_owner", "isso", "issm", "authorizing_official")
_PACKAGE_STATUSES = (
    "draft", "isso_review", "issm_review", "ao_review", "returned",
    "authorized", "conditional", "denied", "superseded", "expired",
)
_EXTENSION_STATUSES = ("requested", "approved", "rejected", "withdrawn")


def _in(col: str, values: tuple[str, ...]) -> str:
    return f"{col} IN ({', '.join(repr(v) for v in values)})"


def _org_fk() -> sa.Column:
    return sa.Column(
        "organization_id",
        sa.Integer(),
        sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
        nullable=True,
    )


def upgrade() -> None:
    op.create_table(
        "system_role_assignments",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        _org_fk(),
        sa.Column(
            "system_id", sa.Integer(),
            sa.ForeignKey("ccf.systems.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column(
            "user_id", sa.Integer(),
            sa.ForeignKey("ccf.users.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("assigned_by", sa.String(255)),
        sa.Column(
            "assigned_at", sa.DateTime(timezone=True), nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("system_id", "role", name="uq_system_role"),
        sa.CheckConstraint(_in("role", _ROLES), name="ck_system_role_assignments_role"),
        schema="ccf",
    )
    for col in ("organization_id", "system_id", "user_id"):
        op.create_index(
            f"ix_system_role_assignments_{col}", "system_role_assignments", [col], schema="ccf"
        )

    op.add_column(
        "authorization_packages",
        sa.Column("status", sa.String(24), nullable=False, server_default="draft"),
        schema="ccf",
    )
    op.add_column(
        "authorization_packages", sa.Column("manifest_sha256", sa.String(64)), schema="ccf"
    )
    op.add_column(
        "authorization_packages", sa.Column("authorization_expires_on", sa.Date()), schema="ccf"
    )
    op.add_column(
        "authorization_packages",
        sa.Column("status_changed_at", sa.DateTime(timezone=True)),
        schema="ccf",
    )
    op.create_check_constraint(
        "ck_authorization_packages_status",
        "authorization_packages",
        _in("status", _PACKAGE_STATUSES),
        schema="ccf",
    )

    op.create_table(
        "authorization_package_events",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        _org_fk(),
        sa.Column(
            "package_id", sa.Integer(),
            sa.ForeignKey("ccf.authorization_packages.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("from_status", sa.String(24), nullable=False),
        sa.Column("to_status", sa.String(24), nullable=False),
        sa.Column("actor", sa.String(255)),
        sa.Column("acted_as", sa.String(32)),
        sa.Column("reason", sa.Text()),
        sa.Column("manifest_sha256", sa.String(64)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False,
            server_default=sa.func.now(),
        ),
        schema="ccf",
    )
    for col in ("organization_id", "package_id"):
        op.create_index(
            f"ix_authorization_package_events_{col}",
            "authorization_package_events", [col], schema="ccf",
        )

    op.create_table(
        "poam_extensions",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        _org_fk(),
        sa.Column(
            "poam_id", sa.Integer(),
            sa.ForeignKey("ccf.poams.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("previous_due_on", sa.Date()),
        sa.Column("requested_due_on", sa.Date(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="requested"),
        sa.Column("requested_by", sa.String(255)),
        sa.Column(
            "requested_at", sa.DateTime(timezone=True), nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("decided_by", sa.String(255)),
        sa.Column("decided_at", sa.DateTime(timezone=True)),
        sa.Column("decision_note", sa.Text()),
        sa.CheckConstraint(
            _in("status", _EXTENSION_STATUSES), name="ck_poam_extensions_status"
        ),
        schema="ccf",
    )
    for col in ("organization_id", "poam_id", "status"):
        op.create_index(f"ix_poam_extensions_{col}", "poam_extensions", [col], schema="ccf")

    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    for table in _NEW_TABLES:
        op.execute(f"ALTER TABLE ccf.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE ccf.{table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON ccf.{table} "
            f"FOR ALL USING {_PREDICATE} WITH CHECK {_PREDICATE}"
        )


def downgrade() -> None:
    for table in reversed(_NEW_TABLES):
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON ccf.{table}")
        op.drop_table(table, schema="ccf")
    op.drop_constraint(
        "ck_authorization_packages_status", "authorization_packages", schema="ccf"
    )
    for col in ("status_changed_at", "authorization_expires_on", "manifest_sha256", "status"):
        op.drop_column("authorization_packages", col, schema="ccf")
