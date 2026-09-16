"""Retain each pack version's manifest, so desired state can be diffed.

``compliance_pack_versions`` recorded a version string and a manifest sha but
not the manifest, which made "what changed in my declared expectations between
v1 and v2" unanswerable -- a sha proves two versions differ without saying how.
P2b needs that answer: a declared posture check IS desired state, and a
desired-state change is what the Continuous Configuration & Enforcement
capability reviews before it is adopted.

No backfill is possible. The manifests of versions installed before this
migration were never stored, so existing rows keep ``{}`` and
``packs.diff.diff_posture_rules`` reports them as an unknown baseline rather
than inventing deletions from their absence.

Tenancy: no new table, so neither RLS guard list changes.
``compliance_pack_versions`` is already policied through its parent
``compliance_packs``.

Revision ID: 0069_pack_version_manifest
Revises: 0068_posture_validation_spine
Create Date: 2026-09-14
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0069_pack_version_manifest"
down_revision = "0068_posture_validation_spine"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"


def upgrade() -> None:
    op.add_column(
        "compliance_pack_versions",
        sa.Column(
            "manifest",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        schema=_SCHEMA,
    )


def downgrade() -> None:
    op.drop_column("compliance_pack_versions", "manifest", schema=_SCHEMA)
