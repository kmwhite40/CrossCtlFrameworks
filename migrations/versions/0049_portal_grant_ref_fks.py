"""External-portal grant_id foreign keys + width normalization (DATA-07/11).

``external_comments.grant_id``, ``external_questionnaire_requests.grant_id``,
and ``external_portal_audit_events.grant_id`` were plain ``BIGINT`` columns
with no FK, and mismatched the width of ``external_access_grants.id``
(``INTEGER``) they logically reference (DATA-11) — a dangling-pointer risk on
the highest-exposure surface (the external collaboration portal), and a type
mismatch on the join.

These are historical/audit rows, so the constraint uses ``ON DELETE SET
NULL`` rather than ``CASCADE``: a comment, questionnaire request, or audit
event must survive the grant being revoked/deleted, just with the reference
cleared.

Before narrowing each column and adding the constraint, ``upgrade()`` nulls
out any orphaned ``grant_id`` (a value with no matching
``external_access_grants.id``) so the type change and FK can both be applied
against clean data.

Downgrade drops the three constraints and widens the columns back to
``BIGINT``; it does not (and cannot) restore the nulled orphan values.

Revision ID: 0049_portal_grant_ref_fks
Revises: 0048_finding_risk_poam_link
Create Date: 2026-07-22
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0049_portal_grant_ref_fks"
down_revision = "0048_finding_risk_poam_link"
branch_labels = None
depends_on = None

_TABLES = (
    "external_comments",
    "external_questionnaire_requests",
    "external_portal_audit_events",
)


def _fk_name(table: str) -> str:
    # Kept short to stay under Postgres' 63-char identifier limit for the
    # longest table name here (external_questionnaire_requests).
    return f"fk_{table}_grant_id"


def upgrade() -> None:
    for table in _TABLES:
        # --- orphan cleanup: null out grant_id values with no matching grant
        op.execute(
            f"UPDATE ccf.{table} t SET grant_id = NULL "
            "WHERE t.grant_id IS NOT NULL AND NOT EXISTS ("
            "  SELECT 1 FROM ccf.external_access_grants g WHERE g.id = t.grant_id"
            ")"
        )
        # --- width normalization: BIGINT -> INTEGER to match the PK -------
        op.alter_column(
            table,
            "grant_id",
            type_=sa.Integer(),
            existing_type=sa.BigInteger(),
            schema="ccf",
        )
        # --- add the FK on now-clean, now-matching-width data --------------
        op.create_foreign_key(
            _fk_name(table),
            source_table=table,
            referent_table="external_access_grants",
            local_cols=["grant_id"],
            remote_cols=["id"],
            source_schema="ccf",
            referent_schema="ccf",
            ondelete="SET NULL",
        )


def downgrade() -> None:
    for table in _TABLES:
        op.drop_constraint(_fk_name(table), table, schema="ccf", type_="foreignkey")
        op.alter_column(
            table,
            "grant_id",
            type_=sa.BigInteger(),
            existing_type=sa.Integer(),
            schema="ccf",
        )
