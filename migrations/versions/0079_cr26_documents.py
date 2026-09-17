"""CR26 deliverable documents, stored as documents and validated on write.

FedRAMP publishes the eleven CR26 deliverables as JSON schemas and versions
each independently, so the shape is theirs, not ours: a decomposed copy would
drift and need a migration for every field they add. One table keyed by the
closed CR26_KINDS vocabulary serves all eleven, rather than eleven near-
identical tables as the SDR, OCR, VDR and SCN arrive.

Tenancy: ``cr26_documents`` carries ``organization_id`` and gets the direct
``organization_id = ccf.current_tenant()`` policy, so it joins
``EXPECTED_TENANT_ISOLATION_TABLES`` (count 137 -> 138) and is NOT added to
``GLOBAL_TABLES``.

Revision ID: 0079_cr26_documents
Revises: 0078_cr26_certification
Create Date: 2026-09-17
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0079_cr26_documents"
down_revision = "0078_cr26_certification"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"
_PREDICATE = "(ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant())"


def upgrade() -> None:
    op.create_table(
        "cr26_documents",
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
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column(
            "document",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("ruleset_version", sa.String(length=32), nullable=False),
        sa.Column("schema_version", sa.String(length=32), nullable=True),
        sa.Column("is_valid", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column(
            "validation_errors",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("updated_by", sa.String(length=255), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            server_default=sa.text("now()"), nullable=False,
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True),
            server_default=sa.text("now()"), nullable=False,
        ),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.UniqueConstraint("system_id", "kind", name="uq_cr26_document_system_kind"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_ccf_cr26_documents_org", "cr26_documents", ["organization_id"], schema=_SCHEMA
    )
    op.create_index(
        "ix_ccf_cr26_documents_system", "cr26_documents", ["system_id"], schema=_SCHEMA
    )
    op.create_index("ix_ccf_cr26_documents_kind", "cr26_documents", ["kind"], schema=_SCHEMA)

    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    op.execute("ALTER TABLE ccf.cr26_documents ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE ccf.cr26_documents FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON ccf.cr26_documents "
        f"FOR ALL USING {_PREDICATE} WITH CHECK {_PREDICATE}"
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON ccf.cr26_documents")
    op.drop_table("cr26_documents", schema=_SCHEMA)
