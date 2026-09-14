"""Capability ontology -- the reusable unit of implementation.

Concord was control-first: narrative authored per control, evidence parented to
a (system, control) pair, and a crosswalk that ran control-to-control. One MFA
decision therefore had to be restated in every dependent control, per project,
per framework. `capabilities` is the missing object -- what the organization
*does* -- with edges to canonical controls, system components, risks, and KSIs.

Tenancy: all five tables are tenant-owned and get the standard
`tenant_isolation` policy. `organization_id` is nullable, matching `vendors`
and `people`: an unscoped principal writes a row with no organization, and the
policy predicate makes such rows invisible to every scoped tenant. They are deliberately NOT added to GLOBAL_TABLES in
tests/test_rls_registry_no_gap.py -- that allowlist is for authority-published
reference data like catalog_sources, and using it here would be an isolation
hole.

`control_implementations` gains derived_status/derived_at/derived_from as
SIBLINGS of `status`, because UNIQUE (system_id, control_id) forbids two rows.
Derivation never writes `status` and never creates a row: `status` is NOT NULL
DEFAULT 'not_implemented', so a created row would assert something about a
control nobody has claimed and could shift reported coverage.

`evidence.implementation_id` becomes nullable so evidence can hang off a
capability instead, guarded by a CHECK that at least one parent is set --
strictly stronger than the NOT NULL it replaces. Every existing row already has
implementation_id, so no data migration is needed.

Revision ID: 0067_capability_ontology
Revises: 0066_catalog_revisions
Create Date: 2026-09-14
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0067_capability_ontology"
down_revision = "0066_catalog_revisions"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"

TENANT_TABLES: tuple[str, ...] = (
    "capabilities",
    "capability_controls",
    "capability_components",
    "capability_risks",
    "capability_ksis",
)

# Verbatim from migration 0064 -- the repo standard.
_PREDICATE = "(ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant())"

_IMPL_STATUS = postgresql.ENUM(
    "not_implemented",
    "planned",
    "partial",
    "implemented",
    "inherited",
    "not_applicable",
    name="impl_status",
    schema=_SCHEMA,
    create_type=False,
)


def _org_fk() -> sa.Column:
    # Nullable, matching the established convention for tenant-owned tables in
    # this schema (vendors, people): an unscoped/global principal writes a row
    # with no organization, and the RLS predicate below makes such rows
    # invisible to any scoped tenant (NULL = current_tenant() is never true).
    return sa.Column(
        "organization_id",
        sa.Integer,
        sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
        nullable=True,
    )


def _edge_table(
    table: str, extra: list[sa.Column], unique: sa.UniqueConstraint
) -> None:
    op.create_table(
        table,
        sa.Column("id", sa.BigInteger, primary_key=True),
        _org_fk(),
        sa.Column(
            "capability_id",
            sa.BigInteger,
            sa.ForeignKey("ccf.capabilities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        *extra,
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        unique,
        schema=_SCHEMA,
    )
    op.create_index(f"ix_ccf_{table}_org", table, ["organization_id"], schema=_SCHEMA)
    op.create_index(
        f"ix_ccf_{table}_capability", table, ["capability_id"], schema=_SCHEMA
    )


def upgrade() -> None:
    op.create_table(
        "capabilities",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _org_fk(),
        sa.Column("key", sa.String(64), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("statement", sa.Text),
        sa.Column("purpose", sa.Text),
        sa.Column("responsible_role", sa.String(128)),
        sa.Column("solution", sa.String(128)),
        sa.Column(
            "status", _IMPL_STATUS, nullable=False, server_default="not_implemented"
        ),
        sa.Column("notes", sa.Text),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("organization_id", "key", name="uq_capability_org_key"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_ccf_capabilities_org", "capabilities", ["organization_id"], schema=_SCHEMA
    )
    op.create_index("ix_ccf_capabilities_key", "capabilities", ["key"], schema=_SCHEMA)
    op.create_index(
        "ix_ccf_capabilities_solution", "capabilities", ["solution"], schema=_SCHEMA
    )

    _edge_table(
        "capability_controls",
        [sa.Column("control_id", sa.String(64), nullable=False)],
        sa.UniqueConstraint("capability_id", "control_id", name="uq_capability_control"),
    )
    op.create_index(
        "ix_ccf_capability_controls_control",
        "capability_controls",
        ["control_id"],
        schema=_SCHEMA,
    )

    _edge_table(
        "capability_components",
        [
            sa.Column(
                "component_id",
                sa.BigInteger,
                sa.ForeignKey("ccf.system_components.id", ondelete="CASCADE"),
                nullable=False,
            )
        ],
        sa.UniqueConstraint(
            "capability_id", "component_id", name="uq_capability_component"
        ),
    )

    _edge_table(
        "capability_risks",
        [
            sa.Column(
                "risk_id",
                sa.Integer,
                sa.ForeignKey("ccf.risks.id", ondelete="CASCADE"),
                nullable=False,
            )
        ],
        sa.UniqueConstraint("capability_id", "risk_id", name="uq_capability_risk"),
    )

    _edge_table(
        "capability_ksis",
        [sa.Column("ksi_identifier", sa.String(32), nullable=False)],
        sa.UniqueConstraint("capability_id", "ksi_identifier", name="uq_capability_ksi"),
    )

    # --- annotate control_implementations (never replace `status`) ----------
    op.add_column(
        "control_implementations",
        sa.Column("derived_status", _IMPL_STATUS, nullable=True),
        schema=_SCHEMA,
    )
    op.add_column(
        "control_implementations",
        sa.Column("derived_at", sa.DateTime(timezone=True), nullable=True),
        schema=_SCHEMA,
    )
    op.add_column(
        "control_implementations",
        sa.Column("derived_from", postgresql.JSONB, nullable=False, server_default="{}"),
        schema=_SCHEMA,
    )

    # --- evidence may hang off a capability instead -------------------------
    op.add_column(
        "evidence",
        sa.Column(
            "capability_id",
            sa.BigInteger,
            sa.ForeignKey("ccf.capabilities.id", ondelete="CASCADE"),
            nullable=True,
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_ccf_evidence_capability", "evidence", ["capability_id"], schema=_SCHEMA
    )
    op.alter_column("evidence", "implementation_id", nullable=True, schema=_SCHEMA)
    op.create_check_constraint(
        "ck_evidence_has_parent",
        "evidence",
        "implementation_id IS NOT NULL OR capability_id IS NOT NULL",
        schema=_SCHEMA,
    )

    # Standard grant guard: no-op where the ccf_app role was never created.
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
    op.drop_constraint(
        "ck_evidence_has_parent", "evidence", schema=_SCHEMA, type_="check"
    )
    op.drop_index("ix_ccf_evidence_capability", "evidence", schema=_SCHEMA)
    op.drop_column("evidence", "capability_id", schema=_SCHEMA)
    # implementation_id is left nullable on downgrade: rows created against
    # 0067 may legitimately have no implementation_id, and restoring NOT NULL
    # would fail on them.
    for col in ("derived_from", "derived_at", "derived_status"):
        op.drop_column("control_implementations", col, schema=_SCHEMA)
    for table in reversed(TENANT_TABLES):
        op.drop_table(table, schema=_SCHEMA)
