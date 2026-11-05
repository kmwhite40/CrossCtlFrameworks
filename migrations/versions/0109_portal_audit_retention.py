"""The portal access log is append-only, kept six months, and names its grantee.

Revision ID: 0109_portal_audit_retention
Revises: 0108_grant_issuance_revocation
Create Date: 2026-11-05

FedRAMP CDS-TRC-ACL: trust centers MUST log access to Certification Data and
store summaries of access for at least six months. The model has called
``external_portal_audit_events`` immutable since 0036, and nothing made it so:
the application role held UPDATE and DELETE.

1. ``grantee_name`` / ``grantee_kind`` / ``grantee_organization``: who the
   grantee was, copied onto each row when it is written, so the history does
   not depend on the principal row surviving (``principal_id`` is SET NULL).
   Backfilled from the current grant and principal.
2. A trigger, because a REVOKE alone binds only ``ccf_app`` and unscoped
   sessions run as the bootstrap superuser (``ccf.db.set_session_tenant``):
   - UPDATE is refused, except the one the foreign key itself makes when a
     grant is deleted: ``grant_id`` to NULL, nothing else changed, and the
     grant row really gone. Without that last test anyone holding UPDATE could
     detach a live grant's events from its party's log. The grantee's identity
     is on the row, so the FK's own nulling loses nothing.
   - DELETE is refused for a row less than six months old (``interval '6
     months'``, the rule's own unit). An organization deleted outright within
     six months of portal activity is therefore refused too, on purpose.
   - TRUNCATE, which row triggers do not see, is refused by a statement
     trigger -- including ``TRUNCATE ... CASCADE`` from a parent table.
3. ``ccf_app`` loses UPDATE and DELETE on the table.

See docs/superpowers/specs/2026-11-05-trust-center-cds-design.md.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0109_portal_audit_retention"
down_revision = "0108_grant_issuance_revocation"
branch_labels = None
depends_on = None

_T = "external_portal_audit_events"
_COLUMNS = (
    "id, organization_id, action, target_type, target_id, detail, created_at, "
    "grantee_name, grantee_kind, grantee_organization"
)


def _row(alias: str) -> str:
    return "ROW(" + ", ".join(f"{alias}.{c.strip()}" for c in _COLUMNS.split(",")) + ")"


def upgrade() -> None:
    op.add_column(_T, sa.Column("grantee_name", sa.String(255)), schema="ccf")
    op.add_column(_T, sa.Column("grantee_kind", sa.String(16)), schema="ccf")
    op.add_column(_T, sa.Column("grantee_organization", sa.String(255)), schema="ccf")
    op.create_index(
        "ix_external_portal_audit_events_grant_created",
        _T,
        ["grant_id", "created_at"],
        schema="ccf",
    )
    # Before the trigger exists: this is the last UPDATE the table accepts.
    op.execute(
        """
        UPDATE ccf.external_portal_audit_events e
           SET grantee_kind = g.kind,
               grantee_name = p.name,
               grantee_organization = p.organization_name
          FROM ccf.external_access_grants g
          LEFT JOIN ccf.external_principals p ON p.id = g.principal_id
         WHERE g.id = e.grant_id
        """
    )
    op.execute(
        f"""
        CREATE OR REPLACE FUNCTION ccf.portal_audit_append_only() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            IF OLD.created_at > now() - interval '6 months' THEN
              RAISE EXCEPTION
                'external_portal_audit_events row % is within the six-month retention '
                'FedRAMP CDS-TRC-ACL requires and cannot be deleted', OLD.id;
            END IF;
            RETURN OLD;
          END IF;
          IF OLD.grant_id IS NOT NULL AND NEW.grant_id IS NULL
             AND {_row("NEW")} IS NOT DISTINCT FROM {_row("OLD")}
             AND NOT EXISTS (
               SELECT 1 FROM ccf.external_access_grants g WHERE g.id = OLD.grant_id
             ) THEN
            RETURN NEW;
          END IF;
          RAISE EXCEPTION 'external_portal_audit_events is append-only (row %)', OLD.id;
        END $$
        """
    )
    op.execute(
        "CREATE TRIGGER portal_audit_append_only BEFORE UPDATE OR DELETE "
        "ON ccf.external_portal_audit_events "
        "FOR EACH ROW EXECUTE FUNCTION ccf.portal_audit_append_only()"
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION ccf.portal_audit_no_truncate() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION 'external_portal_audit_events cannot be truncated: it keeps '
            'six months of access history (FedRAMP CDS-TRC-ACL)';
        END $$
        """
    )
    op.execute(
        "CREATE TRIGGER portal_audit_no_truncate BEFORE TRUNCATE "
        "ON ccf.external_portal_audit_events "
        "FOR EACH STATEMENT EXECUTE FUNCTION ccf.portal_audit_no_truncate()"
    )
    op.execute("REVOKE UPDATE, DELETE ON ccf.external_portal_audit_events FROM ccf_app")


def downgrade() -> None:
    op.execute("GRANT UPDATE, DELETE ON ccf.external_portal_audit_events TO ccf_app")
    op.execute(
        "DROP TRIGGER IF EXISTS portal_audit_append_only ON ccf.external_portal_audit_events"
    )
    op.execute("DROP FUNCTION IF EXISTS ccf.portal_audit_append_only()")
    op.execute(
        "DROP TRIGGER IF EXISTS portal_audit_no_truncate ON ccf.external_portal_audit_events"
    )
    op.execute("DROP FUNCTION IF EXISTS ccf.portal_audit_no_truncate()")
    op.drop_index("ix_external_portal_audit_events_grant_created", _T, schema="ccf")
    op.drop_column(_T, "grantee_organization", schema="ccf")
    op.drop_column(_T, "grantee_kind", schema="ccf")
    op.drop_column(_T, "grantee_name", schema="ccf")
