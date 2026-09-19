"""Durable home for a POA&M's acceptance rationale.

CR26's VER family requires a written ``acceptanceRationale`` on every accepted
vulnerability, and until now nothing in the database held one: an
administrator authored it directly into the generated AVI/ver_history
document and each re-seed preserved it in place. That works until a reporting
window moves backwards past an accepted row -- the row falls outside the new
period, ``put_document`` replaces the stored body, and the rationale is
destroyed with no omission reported at the moment it happens. See
docs/superpowers/specs/2026-09-18-cr26-ver-family-design.md §9.1.

``acceptance_rationale`` gives the value a home independent of any generated
document. ``ccf.cr26.ver.merge_accepted`` now prefers this column and falls
back to the authored document only for rationales written before this column
existed -- the document is a read-only fallback from here on, never deleted,
because that is the only copy of every rationale authored before today.

Nullable, deliberately: every existing ``risk_accepted`` row predates this
requirement, so ``NOT NULL`` would fail the migration on any populated
database. ``src/ccf/api/routes/poams.py``'s ``_require_risk_accepted_gate``
is what keeps a NEW transition into ``risk_accepted`` from arriving without
one; the column itself stays nullable so existing rows are grandfathered
rather than bricked.

**Backfilled, not merely added.** A blank column alone would leave every
rationale that already lives ONLY inside a stored ``avi`` document exactly as
exposed to spec §9.1's defect as before this migration -- the fallback that
reads it is read-only and never promotes it on its own. So this migration
also walks every system's stored ``avi`` document and, for each accepted
entry with a non-blank ``acceptanceRationale`` whose ``poams`` row's column is
still blank, writes it in. (``ccf.cr26.ver``'s seeders additionally promote a
rationale authored into the document AFTER this migration ran, the next time
that system's AVI or ver_history is seeded -- this migration alone cannot see
the future, only backfill the present.)

Done with raw SQL against ``op.get_bind()``, not the ORM: a data migration
must not drift with the model as the model evolves after this file is
written. Idempotent (only ever fills a currently-blank column) and tolerant
of a malformed stored document -- one bad ``cr26_documents`` row must not
block every deployment, so parsing is per-entry and defensive, never raising.

This adds a COLUMN to the existing ``ccf.poams`` table, not a new table, so
``tests/test_rls_coverage.py``'s ``EXPECTED_TENANT_ISOLATION_TABLES`` count
(138) is unaffected -- ``poams`` was already in it.

Revision ID: 0080_poam_acceptance_rationale
Revises: 0079_cr26_documents
Create Date: 2026-09-18
"""

from __future__ import annotations

import json
from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "0080_poam_acceptance_rationale"
down_revision = "0079_cr26_documents"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"


def _is_blank(value: Any) -> bool:
    """Mirrors ``ccf.cr26.ver.is_blank`` -- kept as a standalone copy here on
    purpose. A migration is a point-in-time artifact and must not import
    application code that will keep changing after this file is frozen.
    """
    return not isinstance(value, str) or not value.strip()


def _as_document(raw: Any) -> dict[str, Any] | None:
    """``cr26_documents.document`` as a ``dict``, or ``None`` if it cannot be
    read as one. The driver may hand back a JSONB column as a native ``dict``
    or as its raw text -- tolerate either rather than assume one.
    """
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except (TypeError, ValueError):
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def _backfill_from_avi_documents(bind: sa.engine.Connection) -> None:
    """Walk every stored ``avi`` document and fill any currently-blank
    ``poams.acceptance_rationale`` it can account for. See the module
    docstring for why this exists and why it is tolerant rather than strict.
    """
    rows = bind.execute(
        sa.text(f"SELECT system_id, document FROM {_SCHEMA}.cr26_documents WHERE kind = 'avi'")
    ).fetchall()
    for system_id, raw_document in rows:
        document = _as_document(raw_document)
        if document is None:
            continue  # malformed stored body -- skip this system, not the migration
        entries = document.get("acceptedVulnerabilities")
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            detail = entry.get("vulnerabilityDetail")
            tracking_id = detail.get("providerTrackingId") if isinstance(detail, dict) else None
            rationale = entry.get("acceptanceRationale")
            if not isinstance(tracking_id, str) or _is_blank(rationale):
                continue
            # try/except, never `tracking_id.isdigit()`: measured,
            # `"²".isdigit()` is `True` while `int("²")` raises -- `isdigit()`
            # does not guard this `int()`, it only defers the crash to here,
            # aborting the whole migration on one hand-edited entry. The
            # tempting `tid.isascii() and tid.isdigit()` is a regression, not
            # a fix: `"٣"` (Arabic-Indic three) is non-ASCII with
            # `isdigit() == True` and `int("٣") == 3` -- it parses correctly
            # today, and narrowing to ASCII would silently stop accepting it.
            # See `ccf.cr26.ver._as_row_id`, which has the identical shape.
            try:
                poam_id = int(tracking_id)
            except ValueError:
                continue
            bind.execute(
                sa.text(
                    f"UPDATE {_SCHEMA}.poams SET acceptance_rationale = :rationale "
                    "WHERE id = :poam_id AND system_id = :system_id "
                    "AND (acceptance_rationale IS NULL "
                    "OR btrim(acceptance_rationale) = '')"
                ),
                {
                    "rationale": rationale.strip(),
                    "poam_id": poam_id,
                    "system_id": system_id,
                },
            )


def upgrade() -> None:
    op.add_column(
        "poams",
        sa.Column("acceptance_rationale", sa.Text(), nullable=True),
        schema=_SCHEMA,
    )
    _backfill_from_avi_documents(op.get_bind())


def downgrade() -> None:
    op.drop_column("poams", "acceptance_rationale", schema=_SCHEMA)
