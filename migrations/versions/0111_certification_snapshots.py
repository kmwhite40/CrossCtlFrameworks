"""Snapshots of Certification Data aligned to Ongoing Certification Reports.

Revision ID: 0111_certification_snapshots
Revises: 0110_cert_access_requests
Create Date: 2026-11-05

FedRAMP CDS-CSO-HAD: providers MUST supply snapshots of FedRAMP Certification
Data aligned to Ongoing Certification Reports to all necessary parties, and
the snapshots MUST be available for the duration of FedRAMP Certification.
``cr26_documents`` keeps one row per document and overwrites it, so no earlier
quarter could be served.

- ``certification_snapshots``: content-addressed -- one per distinct set of
  valid documents (``content_sha256`` over each included document's kind,
  key and digest), with the OCR's report period, when and by what it was
  first taken, and the documents withheld as invalid. Re-filing identical
  content adds no copy; changed content under an unchanged OCR does.
- ``certification_snapshot_filings``: one row per valid OCR stored, pointing
  at the snapshot it filed. "Current" for a report period is the snapshot
  filed most recently, so a revert (A, then corrected B, then A again) reads
  A as current, not B.
- ``certification_snapshot_documents``: the valid deliverables as they stood,
  each with its SHA-256 over canonical JSON (sorted keys, no whitespace --
  the same function the portal serves with, copied here so this migration
  does not import application code).
- Append-only, both tables, every role: a trigger refuses UPDATE, DELETE and
  TRUNCATE. Concord does not record when a certification ends, so it never
  decides a snapshot has outlived it.
- Backfill: one snapshot per live system holding a valid OCR now, with
  ``basis = 'backfill'``. Earlier quarters were overwritten before this table
  existed and cannot be recovered; the basis says so instead of passing the
  backfill off as a snapshot taken when that OCR was filed.

See docs/superpowers/specs/2026-11-05-trust-center-cds-design.md.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0111_certification_snapshots"
down_revision = "0110_cert_access_requests"
branch_labels = None
depends_on = None

_PREDICATE = "(ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant())"
_TABLES = (
    "certification_snapshots",
    "certification_snapshot_documents",
    "certification_snapshot_filings",
)


def _digest(document: Any) -> str:
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _content_digest(entries: list[tuple[str, str | None, str]]) -> str:
    """Over the sorted ``(kind, document_key, sha256)`` of what a snapshot holds."""
    return _digest(sorted([list(e) for e in entries], key=lambda e: (e[0], e[1] or "")))


def upgrade() -> None:
    op.create_table(
        "certification_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "system_id",
            sa.Integer(),
            sa.ForeignKey("ccf.systems.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("ocr_period_from", sa.Date()),
        sa.Column("ocr_period_to", sa.Date()),
        sa.Column("ocr_sha256", sa.String(64), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("basis", sa.String(16), nullable=False),
        sa.Column("taken_by", sa.String(255)),
        sa.Column(
            "taken_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("withheld_invalid", JSONB, nullable=False, server_default="[]"),
        sa.UniqueConstraint("system_id", "content_sha256", name="uq_cert_snapshots_system_content"),
        sa.CheckConstraint("basis IN ('ocr_filed', 'backfill')", name="ck_cert_snapshots_basis"),
        schema="ccf",
    )
    op.create_table(
        "certification_snapshot_documents",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "snapshot_id",
            sa.Integer(),
            sa.ForeignKey("ccf.certification_snapshots.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("system_id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("document_key", sa.String(255)),
        sa.Column("document", JSONB, nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("ruleset_version", sa.String(64)),
        sa.Column("schema_version", sa.String(64)),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint(
            "snapshot_id",
            "kind",
            "document_key",
            name="uq_cert_snapshot_documents_identity",
            postgresql_nulls_not_distinct=True,
        ),
        schema="ccf",
    )
    op.create_table(
        "certification_snapshot_filings",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "snapshot_id",
            sa.Integer(),
            sa.ForeignKey("ccf.certification_snapshots.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("filed_by", sa.String(255)),
        sa.Column(
            "filed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        schema="ccf",
    )
    for t in _TABLES:
        op.execute(
            "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
            f"GRANT SELECT, INSERT ON ccf.{t} TO ccf_app; "
            # 0010's default privileges hand every new table UPDATE and DELETE;
            # a GRANT adds to them, it does not replace them.
            f"REVOKE UPDATE, DELETE, TRUNCATE ON ccf.{t} FROM ccf_app; "
            "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
        )
        op.execute(f"ALTER TABLE ccf.{t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE ccf.{t} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON ccf.{t} "
            f"FOR ALL USING {_PREDICATE} WITH CHECK {_PREDICATE}"
        )

    _backfill()

    op.execute(
        """
        CREATE OR REPLACE FUNCTION ccf.certification_snapshot_append_only() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION '% is append-only: certification snapshots stay available for '
            'the duration of FedRAMP Certification (CDS-CSO-HAD)', TG_TABLE_NAME;
        END $$
        """
    )
    for t in _TABLES:
        op.execute(
            f"CREATE TRIGGER {t}_append_only BEFORE UPDATE OR DELETE ON ccf.{t} "
            "FOR EACH ROW EXECUTE FUNCTION ccf.certification_snapshot_append_only()"
        )
        op.execute(
            f"CREATE TRIGGER {t}_no_truncate BEFORE TRUNCATE ON ccf.{t} "
            "FOR EACH STATEMENT EXECUTE FUNCTION ccf.certification_snapshot_append_only()"
        )


def _backfill() -> None:
    bind = op.get_bind()
    ocrs = bind.execute(
        sa.text(
            "SELECT d.system_id, d.organization_id, d.document FROM ccf.cr26_documents d "
            "JOIN ccf.systems s ON s.id = d.system_id "
            "WHERE d.kind = 'ocr' AND d.document_key IS NULL AND d.is_valid "
            "AND s.deleted_at IS NULL AND d.organization_id IS NOT NULL"
        )
    ).all()
    for system_id, org_id, ocr in ocrs:
        period = (ocr or {}).get("reportPeriod") or {}
        docs = bind.execute(
            sa.text(
                "SELECT kind, document_key, document, ruleset_version, schema_version, "
                "updated_at FROM ccf.cr26_documents WHERE system_id = :sys AND is_valid "
                "AND kind <> 'common'"
            ),
            {"sys": system_id},
        ).all()
        withheld = [
            {"kind": k, "document_key": key}
            for k, key in bind.execute(
                sa.text(
                    "SELECT kind, document_key FROM ccf.cr26_documents "
                    "WHERE system_id = :sys AND NOT is_valid AND kind <> 'common' "
                    "ORDER BY kind, document_key"
                ),
                {"sys": system_id},
            ).all()
        ]
        shas = [(kind, key, _digest(document)) for kind, key, document, *_ in docs]
        snapshot_id = bind.execute(
            sa.text(
                "INSERT INTO ccf.certification_snapshots (organization_id, system_id, "
                "ocr_period_from, ocr_period_to, ocr_sha256, content_sha256, basis, taken_by, "
                "withheld_invalid) VALUES (:org, :sys, CAST(:pf AS date), CAST(:pt AS date), "
                ":sha, :content, 'backfill', 'migration 0111', CAST(:withheld AS jsonb)) "
                "RETURNING id"
            ),
            {
                "org": org_id,
                "sys": system_id,
                "pf": period.get("from"),
                "pt": period.get("to"),
                "sha": _digest(ocr),
                "content": _content_digest(shas),
                "withheld": json.dumps(withheld),
            },
        ).scalar_one()
        bind.execute(
            sa.text(
                "INSERT INTO ccf.certification_snapshot_filings (snapshot_id, organization_id, "
                "filed_by) VALUES (:snap, :org, 'migration 0111')"
            ),
            {"snap": snapshot_id, "org": org_id},
        )
        for (kind, key, document, ruleset, schema, updated), (_, _, sha) in zip(
            docs, shas, strict=True
        ):
            bind.execute(
                sa.text(
                    "INSERT INTO ccf.certification_snapshot_documents (snapshot_id, "
                    "organization_id, system_id, kind, document_key, document, sha256, "
                    "ruleset_version, schema_version, updated_at) VALUES (:snap, :org, :sys, "
                    ":kind, :key, CAST(:doc AS jsonb), :sha, :rv, :sv, :ua)"
                ),
                {
                    "snap": snapshot_id,
                    "org": org_id,
                    "sys": system_id,
                    "kind": kind,
                    "key": key,
                    "doc": json.dumps(document),
                    "sha": sha,
                    "rv": ruleset,
                    "sv": schema,
                    "ua": updated,
                },
            )


def downgrade() -> None:
    # IF EXISTS: tolerate a database at an earlier draft of this revision.
    for t in reversed(_TABLES):
        op.execute(f"DROP TABLE IF EXISTS ccf.{t}")
    op.execute("DROP FUNCTION IF EXISTS ccf.certification_snapshot_append_only()")
