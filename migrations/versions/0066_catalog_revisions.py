"""Catalog revisions -- retained, commit-pinned OSCAL content per source.

Bridges the currency poller (``catalog_sources`` / ``catalog_checks``) to the
sha256-pinned loader in ``ccf.catalog.oscal``. Until now the poller could detect
that an upstream authority changed but had no way to promote that content into
the catalog the platform actually reads, so drift went nowhere. A revision is
upstream content captured on disk with a generated manifest, which a human
adopts deliberately after reviewing its impact.

``catalog_revisions`` is global reference data -- no ``organization_id`` and no
RLS -- consistent with ``catalog_sources`` and ``catalog_checks``. Writes are
gated by admin RBAC at the API layer, not by row policy.

Seeds the currently bundled OSCAL content as revision 'bundled', already
adopted, with ``content_dir`` NULL so it resolves to the packaged in-wheel
directory. Nothing moves on disk, and a deployment with no ``data/oscal`` volume
keeps working exactly as before.

Revision ID: 0066_catalog_revisions
Revises: 0065_user_session_version
Create Date: 2026-09-14
"""

from __future__ import annotations

import json
from pathlib import Path

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0066_catalog_revisions"
down_revision = "0065_user_session_version"
branch_labels = None
depends_on = None

_PACKAGED_MANIFEST = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "ccf"
    / "catalog"
    / "oscal_data"
    / "MANIFEST.json"
)
_SOURCE_KEY = "nist_800_53_r5_catalog"


def upgrade() -> None:
    op.create_table(
        "catalog_revisions",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "source_id",
            sa.Integer,
            sa.ForeignKey("ccf.catalog_sources.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("revision", sa.String(64), nullable=False),
        sa.Column("upstream_commit_sha", sa.String(64)),
        sa.Column("upstream_url", sa.Text),
        sa.Column("oscal_version", sa.String(32)),
        sa.Column("content_sha256", sa.String(64)),
        sa.Column("files", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("content_index", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("content_dir", sa.Text),
        sa.Column("status", sa.String(16), nullable=False, server_default="available"),
        sa.Column(
            "retrieved_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("retrieved_by", sa.String(255)),
        sa.Column("adopted_at", sa.DateTime(timezone=True)),
        sa.Column("adopted_by", sa.String(255)),
        sa.Column("adoption_impact", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("notes", sa.Text),
        sa.UniqueConstraint("source_id", "revision", name="uq_catalog_revision"),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_catalog_revisions_source", "catalog_revisions", ["source_id"], schema="ccf"
    )
    op.create_index(
        "ix_ccf_catalog_revisions_status", "catalog_revisions", ["status"], schema="ccf"
    )
    # Exactly one adopted revision per source, enforced by the database rather
    # than by application discipline.
    op.create_index(
        "uq_catalog_revision_adopted",
        "catalog_revisions",
        ["source_id"],
        unique=True,
        postgresql_where=sa.text("status = 'adopted'"),
        schema="ccf",
    )

    # Standard grant guard: the ccf_app role exists only where RLS was set up.
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )

    _seed_bundled_revision()


def _seed_bundled_revision() -> None:
    """Record the shipped OSCAL content as the adopted 'bundled' revision."""
    if not _PACKAGED_MANIFEST.is_file():
        return  # reader/SQLite builds ship no OSCAL data
    manifest = json.loads(_PACKAGED_MANIFEST.read_text(encoding="utf-8"))
    conn = op.get_bind()
    source_id = conn.execute(
        sa.text("SELECT id FROM ccf.catalog_sources WHERE key = :k"), {"k": _SOURCE_KEY}
    ).scalar()
    if source_id is None:
        source_id = conn.execute(
            sa.text(
                "INSERT INTO ccf.catalog_sources (key, name, authority, kind, url, "
                "framework_code) VALUES (:k, :n, 'NIST', 'oscal_catalog', :u, "
                "'NIST_800_53_R5') RETURNING id"
            ),
            {
                "k": _SOURCE_KEY,
                "n": "NIST SP 800-53 Rev. 5 - control catalog (OSCAL)",
                "u": manifest.get("source_url", ""),
            },
        ).scalar()
    conn.execute(
        sa.text(
            "INSERT INTO ccf.catalog_revisions "
            "(source_id, revision, upstream_url, oscal_version, files, status, "
            " adopted_at, adopted_by, notes) "
            "VALUES (:sid, 'bundled', :url, :ver, CAST(:files AS jsonb), 'adopted', "
            " now(), 'migration:0066', :notes)"
        ),
        {
            "sid": source_id,
            "url": manifest.get("source_url"),
            "ver": manifest.get("oscal_version"),
            "files": json.dumps(manifest.get("files", {})),
            "notes": f"Bundled content, retrieved_at={manifest.get('retrieved_at')}",
        },
    )


def downgrade() -> None:
    op.drop_table("catalog_revisions", schema="ccf")
