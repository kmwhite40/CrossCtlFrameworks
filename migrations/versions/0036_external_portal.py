"""External collaboration portal — scoped, expiring customer/assessor/vendor access.

Adds the seven portal tables (see :mod:`ccf.models_portal`). Every tenant-owned
table gets row-level security: the org-scoped tables key on
``organization_id = ccf.current_tenant()``; the two share join-tables (which have
no ``organization_id`` of their own) enforce isolation transitively via a subquery
against their parent grant's organization, so a share can never be read across
tenants.

Revision ID: 0036_external_portal
Revises: 0035_self_assurance
Create Date: 2026-07-08
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0036_external_portal"
down_revision = "0035_self_assurance"
branch_labels = None
depends_on = None

# Org-scoped tables enforce the standard tenant predicate.
_ORG_SCOPED = (
    "external_principals",
    "external_access_grants",
    "external_comments",
    "external_questionnaire_requests",
    "external_portal_audit_events",
)
# Share tables have no organization_id; isolate them via their parent grant.
_SHARE_TABLES = ("external_package_shares", "external_evidence_shares")
_ALL = (*_ORG_SCOPED, *_SHARE_TABLES)


def _fk(target: str, ondelete: str = "CASCADE") -> sa.ForeignKey:
    return sa.ForeignKey(target, ondelete=ondelete)


def upgrade() -> None:
    op.create_table(
        "external_principals",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("organization_id", sa.Integer, _fk("ccf.organizations.id"), index=True),
        sa.Column("kind", sa.String(16), nullable=False, server_default="customer"),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("email", sa.String(320)),
        sa.Column("organization_name", sa.String(255)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_table(
        "external_access_grants",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("organization_id", sa.Integer, _fk("ccf.organizations.id"), index=True),
        sa.Column("principal_id", sa.Integer, _fk("ccf.external_principals.id", "SET NULL")),
        sa.Column("kind", sa.String(16), nullable=False, server_default="customer"),
        sa.Column("token", sa.String(64), nullable=False, unique=True, index=True),
        sa.Column("label", sa.String(255)),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("revoked", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("scope", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_table(
        "external_package_shares",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "grant_id", sa.Integer, _fk("ccf.external_access_grants.id"), nullable=False, index=True
        ),
        sa.Column("package_id", sa.Integer, nullable=False),
        schema="ccf",
    )
    op.create_table(
        "external_evidence_shares",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "grant_id", sa.Integer, _fk("ccf.external_access_grants.id"), nullable=False, index=True
        ),
        sa.Column("evidence_object_id", sa.Integer, nullable=False),
        schema="ccf",
    )
    op.create_table(
        "external_comments",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("organization_id", sa.Integer, _fk("ccf.organizations.id"), index=True),
        sa.Column("grant_id", sa.BigInteger),
        sa.Column("target_type", sa.String(24), nullable=False),
        sa.Column("target_id", sa.String(64), nullable=False),
        sa.Column("author", sa.String(255)),
        sa.Column("author_kind", sa.String(16), nullable=False, server_default="external"),
        sa.Column("body", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_table(
        "external_questionnaire_requests",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("organization_id", sa.Integer, _fk("ccf.organizations.id"), index=True),
        sa.Column("grant_id", sa.BigInteger),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="open"),
        sa.Column("response_body", sa.Text),
        sa.Column("responded_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_table(
        "external_portal_audit_events",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("organization_id", sa.Integer, _fk("ccf.organizations.id"), index=True),
        sa.Column("grant_id", sa.BigInteger),
        sa.Column("action", sa.String(24), nullable=False),
        sa.Column("target_type", sa.String(24)),
        sa.Column("target_id", sa.String(64)),
        sa.Column("detail", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )

    # Least-privilege grants for the RLS-bound application role.
    tables = ", ".join(f"ccf.{t}" for t in _ALL)
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON {tables} TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )

    # RLS: org-scoped tables key directly on the tenant.
    for t in _ORG_SCOPED:
        expr = "(ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant())"
        op.execute(f"ALTER TABLE ccf.{t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE ccf.{t} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON ccf.{t} FOR ALL USING {expr} WITH CHECK {expr}"
        )

    # RLS: share tables isolate via their parent grant's organization.
    for t in _SHARE_TABLES:
        expr = (
            "(ccf.current_tenant() IS NULL OR EXISTS ("
            "SELECT 1 FROM ccf.external_access_grants g "
            f"WHERE g.id = {t}.grant_id AND g.organization_id = ccf.current_tenant()))"
        )
        op.execute(f"ALTER TABLE ccf.{t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE ccf.{t} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON ccf.{t} FOR ALL USING {expr} WITH CHECK {expr}"
        )


def downgrade() -> None:
    for t in _ALL:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON ccf.{t}")
    # Drop children before parents (FK order).
    for t in (
        "external_portal_audit_events",
        "external_questionnaire_requests",
        "external_comments",
        "external_evidence_shares",
        "external_package_shares",
        "external_access_grants",
        "external_principals",
    ):
        op.drop_table(t, schema="ccf")
