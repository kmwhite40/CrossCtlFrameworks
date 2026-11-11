"""A vendor's FedRAMP certification package, for the agency-side crosswalk.

Revision ID: 0121_vendor_cert_documents
Revises: 0120_ops_notify_threads
Create Date: 2026-11-11

One row per (vendor, CR26 document kind) -- the files an agency reviewer
uploads under Third-Party Risk to read a provider's package against the Rev5
baseline (``ccf.fedramp20x.crosswalk``). A tenant table: forced RLS with the
standard predicate, and ``ccf.assert_parent_org`` (0101) so a row can never
point at another organization's vendor -- foreign keys are checked without
RLS. See docs/superpowers/specs/2026-11-11-crosswalk-20x-design.md.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0121_vendor_cert_documents"
down_revision = "0120_ops_notify_threads"
branch_labels = None
depends_on = None

_PREDICATE = "(ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant())"


def upgrade() -> None:
    op.create_table(
        "vendor_cert_documents",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "vendor_id",
            sa.Integer(),
            sa.ForeignKey("ccf.vendors.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("document", postgresql.JSONB(), nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("is_valid", sa.Boolean(), nullable=False),
        sa.Column("validation_errors", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("uploaded_by", sa.String(255), nullable=False),
        sa.Column(
            "uploaded_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint("vendor_id", "kind", name="uq_vendor_cert_documents_vendor_kind"),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_vendor_cert_documents_organization_id",
        "vendor_cert_documents",
        ["organization_id"],
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_vendor_cert_documents_vendor_id",
        "vendor_cert_documents",
        ["vendor_id"],
        schema="ccf",
    )
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ccf.vendor_cert_documents TO ccf_app; "
        "GRANT USAGE, SELECT ON SEQUENCE ccf.vendor_cert_documents_id_seq TO ccf_app; END IF; END $$"
    )
    op.execute("ALTER TABLE ccf.vendor_cert_documents ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE ccf.vendor_cert_documents FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON ccf.vendor_cert_documents "
        f"FOR ALL USING {_PREDICATE} WITH CHECK {_PREDICATE}"
    )
    op.execute(
        "CREATE TRIGGER parent_org_vendor_cert_documents_vendor_id BEFORE INSERT OR UPDATE OF "
        "vendor_id, organization_id ON ccf.vendor_cert_documents FOR EACH ROW "
        "EXECUTE FUNCTION ccf.assert_parent_org('vendor_id', 'vendors')"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS ccf.vendor_cert_documents")
