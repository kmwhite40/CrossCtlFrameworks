"""Pack sources -- GitOps for a tenant's declared desired state.

The repository holds the pack manifest; the platform polls it, reports what
adopting the change would do, and installs only when told. Polling mechanics
are shared with the catalog poller (``etl/sources.py``'s helpers), but the
table is not: ``catalog_sources`` is global reference data because NIST's
catalog is the same for everyone, while a desired-state repository belongs to
one organization.

``auto_install`` defaults to false. A changed manifest lands in
``pending_manifest`` for review, because a pack rule executes against a
customer tenant and a silent change would mean an SSP that no longer describes
a reviewed decision.

Tenancy: ``pack_sources`` carries ``organization_id`` and gets the direct
``organization_id = ccf.current_tenant()`` policy, so it joins
``EXPECTED_TENANT_ISOLATION_TABLES`` in ``tests/test_rls_coverage.py``
(count 132 -> 133) and is NOT added to ``GLOBAL_TABLES``.

Revision ID: 0073_pack_sources
Revises: 0072_waiver_disclosure
Create Date: 2026-09-15
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0073_pack_sources"
down_revision = "0072_waiver_disclosure"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"
_PREDICATE = "(ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant())"


def upgrade() -> None:
    op.create_table(
        "pack_sources",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("pack_key", sa.String(length=64), nullable=False),
        sa.Column("url", sa.String(length=1024), nullable=False),
        sa.Column("ref", sa.String(length=128), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("auto_install", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("etag", sa.String(length=255), nullable=True),
        # Two digests, two questions. last_sha256 is the raw bytes at the URL
        # ("did the file change"); last_manifest_sha is the canonical manifest
        # digest install_pack stores, so divergence can compare like with like
        # -- whitespace and key order move the raw sha without changing the
        # manifest.
        sa.Column("last_sha256", sa.String(length=64), nullable=True),
        sa.Column("last_manifest_sha", sa.String(length=64), nullable=True),
        sa.Column("last_commit_sha", sa.String(length=64), nullable=True),
        sa.Column("last_status", sa.String(length=16), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "pending_manifest",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("pending_sha256", sa.String(length=64), nullable=True),
        sa.Column("pending_manifest_sha", sa.String(length=64), nullable=True),
        sa.Column("pending_commit_sha", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "organization_id", "pack_key", "url", name="uq_pack_source_org_key_url"
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_ccf_pack_sources_org", "pack_sources", ["organization_id"], schema=_SCHEMA
    )
    op.create_index(
        "ix_ccf_pack_sources_pack_key", "pack_sources", ["pack_key"], schema=_SCHEMA
    )

    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    op.execute("ALTER TABLE ccf.pack_sources ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE ccf.pack_sources FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON ccf.pack_sources "
        f"FOR ALL USING {_PREDICATE} WITH CHECK {_PREDICATE}"
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON ccf.pack_sources")
    op.drop_table("pack_sources", schema=_SCHEMA)
