"""Agencies request access to Certification Data themselves; denials start a clock.

Revision ID: 0110_cert_access_requests
Revises: 0109_portal_audit_retention
Create Date: 2026-11-05

FedRAMP CDS-TRC-SSM (SHOULD): trust centers let parties provision access to
Certification Data themselves. CDS-UTC-AAD (MUST): providers notify FedRAMP
within five business days of denying an agency access request.

- ``certification_request_links``: a revocable, unguessable link the provider
  publishes, naming the systems that may be requested through it. The link
  is the capability; there is no open per-organization form to find or spam.
- ``certification_access_requests``: one agency request. Approval does not
  issue the grant -- the requester claims it with the one-time receipt they
  got at submission and sees the token once, because Concord stores only
  token hashes. A denial carries its reason and the FedRAMP notice due date;
  the notice itself is recorded when the provider files it.

See docs/superpowers/specs/2026-11-05-trust-center-cds-design.md.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0110_cert_access_requests"
down_revision = "0109_portal_audit_retention"
branch_labels = None
depends_on = None

_PREDICATE = "(ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant())"
_TABLES = ("certification_request_links", "certification_access_requests")


def _org() -> sa.Column:
    return sa.Column(
        "organization_id",
        sa.Integer(),
        sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )


def upgrade() -> None:
    op.create_table(
        "certification_request_links",
        sa.Column("id", sa.Integer(), primary_key=True),
        _org(),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("label", sa.String(255)),
        sa.Column("system_ids", JSONB, nullable=False),
        sa.Column("created_by", sa.String(255)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_by", sa.String(255)),
        sa.CheckConstraint(
            "jsonb_typeof(system_ids) = 'array' AND jsonb_array_length(system_ids) > 0",
            name="ck_cert_request_links_systems",
        ),
        schema="ccf",
    )
    op.create_table(
        "certification_access_requests",
        sa.Column("id", sa.Integer(), primary_key=True),
        _org(),
        sa.Column(
            "link_id",
            sa.Integer(),
            sa.ForeignKey("ccf.certification_request_links.id", ondelete="SET NULL"),
            index=True,
        ),
        sa.Column("receipt_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("agency_name", sa.String(255), nullable=False),
        sa.Column("requester_name", sa.String(255), nullable=False),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("reason", sa.Text()),
        sa.Column("system_ids", JSONB, nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("decided_by", sa.String(255)),
        sa.Column("decided_at", sa.DateTime(timezone=True)),
        sa.Column("decision_reason", sa.Text()),
        sa.Column("ttl_days", sa.Integer()),
        sa.Column("approved_system_ids", JSONB),
        sa.Column(
            "grant_id",
            sa.Integer(),
            sa.ForeignKey("ccf.external_access_grants.id", ondelete="SET NULL"),
        ),
        sa.Column("claimed_at", sa.DateTime(timezone=True)),
        sa.Column("fedramp_notify_due", sa.Date()),
        sa.Column("fedramp_notified_on", sa.Date()),
        sa.Column("fedramp_notified_by", sa.String(255)),
        sa.Column("fedramp_reference", sa.String(255)),
        # When the notice was recorded, beside the self-reported filed date.
        sa.Column("fedramp_notice_recorded_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'approved', 'denied')", name="ck_cert_access_requests_status"
        ),
        sa.CheckConstraint(
            "(status = 'pending') = (decided_at IS NULL)",
            name="ck_cert_access_requests_decided",
        ),
        sa.CheckConstraint(
            "status <> 'approved' OR (ttl_days IS NOT NULL AND ttl_days > 0 "
            "AND approved_system_ids IS NOT NULL)",
            name="ck_cert_access_requests_approval",
        ),
        sa.CheckConstraint(
            "status <> 'denied' OR (length(btrim(coalesce(decision_reason, ''))) > 0 "
            "AND fedramp_notify_due IS NOT NULL)",
            name="ck_cert_access_requests_denial",
        ),
        sa.CheckConstraint(
            "claimed_at IS NULL OR status = 'approved'", name="ck_cert_access_requests_claim"
        ),
        sa.CheckConstraint(
            "fedramp_notified_on IS NULL OR (status = 'denied' "
            "AND length(btrim(coalesce(fedramp_reference, ''))) > 0 "
            "AND fedramp_notice_recorded_at IS NOT NULL)",
            name="ck_cert_access_requests_notice",
        ),
        schema="ccf",
    )
    for t in _TABLES:
        op.execute(
            "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON ccf.{t} TO ccf_app; "
            "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
        )
        op.execute(f"ALTER TABLE ccf.{t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE ccf.{t} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON ccf.{t} "
            f"FOR ALL USING {_PREDICATE} WITH CHECK {_PREDICATE}"
        )


def downgrade() -> None:
    for t in reversed(_TABLES):
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON ccf.{t}")
        op.drop_table(t, schema="ccf")
