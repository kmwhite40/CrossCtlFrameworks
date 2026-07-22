"""Add real foreign keys to external-portal share rows (DATA-02).

``external_package_shares.package_id`` and ``external_evidence_shares.
evidence_object_id`` were plain integers with no FK — the highest-exposure
surface (the external collaboration portal) could reference a deleted or
foreign artifact, and the share row would dangle silently rather than being
cleaned up when the artifact was removed.

This adds ``package_id -> ccf.authorization_packages.id ON DELETE CASCADE``
and ``evidence_object_id -> ccf.evidence_objects.id ON DELETE CASCADE``.
Before creating each constraint, ``upgrade()`` deletes any orphaned share
rows (a ``package_id``/``evidence_object_id`` with no matching parent row) so
the FK can be added against real data.

Downgrade drops both constraints; it does not (and cannot) restore the
orphaned rows deleted during upgrade.

Revision ID: 0042_portal_share_fks
Revises: 0041_hash_bearer_tokens
Create Date: 2026-07-21
"""

from __future__ import annotations

from alembic import op

revision = "0042_portal_share_fks"
down_revision = "0041_hash_bearer_tokens"
branch_labels = None
depends_on = None

_PKG_FK = "fk_external_package_shares_package_id_authorization_packages"
_EV_FK = "fk_external_evidence_shares_evidence_object_id_evidence_objects"


def upgrade() -> None:
    # --- orphan cleanup: delete shares whose parent no longer exists -------
    op.execute(
        "DELETE FROM ccf.external_package_shares s "
        "WHERE NOT EXISTS ("
        "  SELECT 1 FROM ccf.authorization_packages p WHERE p.id = s.package_id"
        ")"
    )
    op.execute(
        "DELETE FROM ccf.external_evidence_shares s "
        "WHERE NOT EXISTS ("
        "  SELECT 1 FROM ccf.evidence_objects e WHERE e.id = s.evidence_object_id"
        ")"
    )

    # --- add the FKs on now-clean data --------------------------------------
    op.create_foreign_key(
        _PKG_FK,
        source_table="external_package_shares",
        referent_table="authorization_packages",
        local_cols=["package_id"],
        remote_cols=["id"],
        source_schema="ccf",
        referent_schema="ccf",
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        _EV_FK,
        source_table="external_evidence_shares",
        referent_table="evidence_objects",
        local_cols=["evidence_object_id"],
        remote_cols=["id"],
        source_schema="ccf",
        referent_schema="ccf",
        ondelete="CASCADE",
    )


def downgrade() -> None:
    op.drop_constraint(_EV_FK, "external_evidence_shares", schema="ccf", type_="foreignkey")
    op.drop_constraint(_PKG_FK, "external_package_shares", schema="ccf", type_="foreignkey")
