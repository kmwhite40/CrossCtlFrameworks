"""DISA CCI reference data -- items, control references, derived overlay.

Three GLOBAL tables. DISA's CCI list is authority-published and identical for
every tenant, exactly like ``controls`` and ``catalog_revisions``, so none of
them carries ``organization_id`` and none gets a tenant_isolation policy. They
join ``GLOBAL_TABLES`` in ``tests/test_rls_registry_no_gap.py``; they must NOT
join ``EXPECTED_TENANT_ISOLATION_TABLES`` and its hardcoded count does not move.

``cci_control_refs.oscal_part_id`` is nullable because DISA's reference may name
an item the current Rev. 5 catalog does not define.

Revision ID: 0074_cci_source_spine
Revises: 0073_flaw_remediation
Create Date: 2026-09-15
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0074_cci_source_spine"
down_revision = "0073_flaw_remediation"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"


def upgrade() -> None:
    op.create_table(
        "cci_items",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("cci", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("type", sa.String(length=32), nullable=False),
        sa.Column("contributor", sa.String(length=128), nullable=True),
        sa.Column("published_date", sa.Date(), nullable=True),
        sa.Column("definition", sa.Text(), nullable=False),
        sa.Column("source_version", sa.String(length=32), nullable=False),
        sa.Column("source_sha256", sa.String(length=64), nullable=False),
        sa.Column(
            "loaded_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("cci", name="uq_cci_items_cci"),
        schema=_SCHEMA,
    )
    op.create_index("ix_cci_items_cci", "cci_items", ["cci"], schema=_SCHEMA)

    op.create_table(
        "cci_control_refs",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "cci_id",
            sa.BigInteger(),
            sa.ForeignKey("ccf.cci_items.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("revision", sa.String(length=64), nullable=False),
        sa.Column("raw_index", sa.String(length=128), nullable=False),
        sa.Column("canonical_control", sa.String(length=32), nullable=True),
        sa.Column("oscal_control_id", sa.String(length=32), nullable=True),
        sa.Column("oscal_part_id", sa.String(length=64), nullable=True),
        sa.UniqueConstraint("cci_id", "revision", "raw_index", name="uq_cci_ref"),
        schema=_SCHEMA,
    )
    op.create_index("ix_cci_control_refs_cci_id", "cci_control_refs", ["cci_id"], schema=_SCHEMA)
    op.create_index(
        "ix_cci_ref_canonical_control", "cci_control_refs", ["canonical_control"], schema=_SCHEMA
    )

    op.create_table(
        "cci_assessment_overlay",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "cci_id",
            sa.BigInteger(),
            sa.ForeignKey("ccf.cci_items.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("ap_acronym", sa.String(length=64), nullable=True),
        sa.Column("emass_identifier", sa.String(length=64), nullable=True),
        sa.Column("assessment_procedure", sa.Text(), nullable=True),
        sa.Column("assessment_methods", sa.Text(), nullable=True),
        sa.Column("source", sa.String(length=128), nullable=False),
        sa.UniqueConstraint("cci_id", "ap_acronym", name="uq_cci_overlay"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cci_assessment_overlay_cci_id", "cci_assessment_overlay", ["cci_id"], schema=_SCHEMA
    )

    # Standard since 0054: grant only if the role exists, so a developer
    # database without ccf_app migrates cleanly.
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    # No RLS: these are global reference tables (see module docstring).


def downgrade() -> None:
    op.drop_table("cci_assessment_overlay", schema=_SCHEMA)
    op.drop_table("cci_control_refs", schema=_SCHEMA)
    op.drop_table("cci_items", schema=_SCHEMA)
