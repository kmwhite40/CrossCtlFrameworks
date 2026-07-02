"""Evidence repository — versioned objects, reviews, retention, access events.

Adds ``evidence_objects`` + ``evidence_versions`` + ``evidence_reviews`` +
``evidence_retention_policies`` + ``evidence_access_events``, all tenant-isolated
(org-scoped rows directly; children via their parent object).

Revision ID: 0028_evidence_repository
Revises: 0027_identity_sso_scim
Create Date: 2026-07-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0028_evidence_repository"
down_revision = "0027_identity_sso_scim"
branch_labels = None
depends_on = None

_ORG = "organization_id = ccf.current_tenant()"
_OBJ = (
    "evidence_object_id IN (SELECT id FROM ccf.evidence_objects "
    "WHERE organization_id = ccf.current_tenant())"
)
_POLICIES = {
    "evidence_objects": _ORG,
    "evidence_retention_policies": _ORG,
    "evidence_versions": _OBJ,
    "evidence_reviews": _OBJ,
    "evidence_access_events": _OBJ,
}


def upgrade() -> None:
    op.create_table(
        "evidence_objects",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "organization_id", sa.Integer,
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
        ),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("system_id", sa.Integer, sa.ForeignKey("ccf.systems.id", ondelete="SET NULL")),
        sa.Column("control_id", sa.String(64)),
        sa.Column("framework", sa.String(64)),
        sa.Column("owner", sa.String(255)),
        sa.Column("status", sa.String(16), nullable=False, server_default="draft"),
        sa.Column("current_version_id", sa.BigInteger),
        sa.Column("expires_on", sa.Date),
        sa.Column("immutable_lock", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_evidence_objects_org", "evidence_objects", ["organization_id"], schema="ccf"
    )

    op.create_table(
        "evidence_versions",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "evidence_object_id", sa.Integer,
            sa.ForeignKey("ccf.evidence_objects.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("version", sa.Integer, nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("media_type", sa.String(128)),
        sa.Column("size_bytes", sa.Integer, nullable=False, server_default="0"),
        sa.Column("filename", sa.String(512)),
        sa.Column("storage_backend", sa.String(16), nullable=False, server_default="local"),
        sa.Column("storage_ref", sa.Text, nullable=False),
        sa.Column("uploaded_by", sa.String(255)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_evidence_versions_obj", "evidence_versions", ["evidence_object_id"], schema="ccf"
    )
    op.create_index("ix_ccf_evidence_versions_sha", "evidence_versions", ["sha256"], schema="ccf")

    op.create_table(
        "evidence_reviews",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "evidence_object_id", sa.Integer,
            sa.ForeignKey("ccf.evidence_objects.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("version_id", sa.BigInteger),
        sa.Column("reviewer", sa.String(255)),
        sa.Column("decision", sa.String(16), nullable=False),
        sa.Column("note", sa.Text),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_evidence_reviews_obj", "evidence_reviews", ["evidence_object_id"], schema="ccf"
    )

    op.create_table(
        "evidence_retention_policies",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "organization_id", sa.Integer,
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("retain_days", sa.Integer, nullable=False, server_default="365"),
        sa.Column("applies_to_framework", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_evidence_retention_org", "evidence_retention_policies",
        ["organization_id"], schema="ccf",
    )

    op.create_table(
        "evidence_access_events",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "evidence_object_id", sa.Integer,
            sa.ForeignKey("ccf.evidence_objects.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("version_id", sa.BigInteger),
        sa.Column("actor", sa.String(255)),
        sa.Column("action", sa.String(16), nullable=False, server_default="download"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_evidence_access_obj", "evidence_access_events",
        ["evidence_object_id"], schema="ccf",
    )

    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ccf.evidence_objects, ccf.evidence_versions, "
        "ccf.evidence_reviews, ccf.evidence_retention_policies, ccf.evidence_access_events "
        "TO ccf_app; GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    for table, predicate in _POLICIES.items():
        expr = f"(ccf.current_tenant() IS NULL OR {predicate})"
        op.execute(f"ALTER TABLE ccf.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE ccf.{table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON ccf.{table} "
            f"FOR ALL USING {expr} WITH CHECK {expr}"
        )


def downgrade() -> None:
    for table in _POLICIES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON ccf.{table}")
    op.drop_table("evidence_access_events", schema="ccf")
    op.drop_table("evidence_retention_policies", schema="ccf")
    op.drop_table("evidence_reviews", schema="ccf")
    op.drop_table("evidence_versions", schema="ccf")
    op.drop_table("evidence_objects", schema="ccf")
