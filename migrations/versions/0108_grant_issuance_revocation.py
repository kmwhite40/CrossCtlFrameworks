"""Who issued and who revoked each portal grant, and when.

Revision ID: 0108_grant_issuance_revocation
Revises: 0107_vulnerability_evaluations
Create Date: 2026-11-05

FedRAMP CDS-TRC-AAI: a trust center MUST keep an inventory *and history* of
agency access to Certification Data and give it to FedRAMP on request. A grant
recorded revocation as a bare ``revoked`` bool, so the history could say that
access ended but not when or by whose hand.

Backfill reads the tamper-evident ``audit_log`` (the ``external_grant``
create/delete events ``portal.service`` has always written), taking the actor
and the time from the SAME row so the two cannot disagree. Where no event
exists the columns stay NULL and read as "not recorded" -- a date nobody
recorded is not invented here. See
docs/superpowers/specs/2026-11-05-trust-center-cds-design.md.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0108_grant_issuance_revocation"
down_revision = "0107_vulnerability_evaluations"
branch_labels = None
depends_on = None

_TABLE = "external_access_grants"


def upgrade() -> None:
    op.add_column(_TABLE, sa.Column("issued_by", sa.String(255)), schema="ccf")
    op.add_column(_TABLE, sa.Column("revoked_at", sa.DateTime(timezone=True)), schema="ccf")
    op.add_column(_TABLE, sa.Column("revoked_by", sa.String(255)), schema="ccf")
    # A revocation time on a grant that still resolves would be a history that
    # contradicts the access check.
    op.create_check_constraint(
        "ck_external_access_grants_revoked_at_implies_revoked",
        _TABLE,
        "revoked_at IS NULL OR revoked",
        schema="ccf",
    )
    op.execute(
        """
        UPDATE ccf.external_access_grants g
           SET issued_by = a.actor
          FROM (
            SELECT DISTINCT ON (entity_id) entity_id, actor
              FROM ccf.audit_log
             WHERE entity_type = 'external_grant' AND action = 'create'
             ORDER BY entity_id, at, id
          ) a
         WHERE a.entity_id = g.id::text
        """
    )
    op.execute(
        """
        UPDATE ccf.external_access_grants g
           SET revoked_at = a.at, revoked_by = a.actor
          FROM (
            SELECT DISTINCT ON (entity_id) entity_id, actor, at
              FROM ccf.audit_log
             WHERE entity_type = 'external_grant' AND action = 'delete'
             ORDER BY entity_id, at, id
          ) a
         WHERE a.entity_id = g.id::text AND g.revoked
        """
    )


def downgrade() -> None:
    op.drop_constraint("ck_external_access_grants_revoked_at_implies_revoked", _TABLE, schema="ccf")
    op.drop_column(_TABLE, "revoked_by", schema="ccf")
    op.drop_column(_TABLE, "revoked_at", schema="ccf")
    op.drop_column(_TABLE, "issued_by", schema="ccf")
