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

This adds a COLUMN to the existing ``ccf.poams`` table, not a new table, so
``tests/test_rls_coverage.py``'s ``EXPECTED_TENANT_ISOLATION_TABLES`` count
(138) is unaffected -- ``poams`` was already in it.

Revision ID: 0080_poam_acceptance_rationale
Revises: 0079_cr26_documents
Create Date: 2026-09-18
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0080_poam_acceptance_rationale"
down_revision = "0079_cr26_documents"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"


def upgrade() -> None:
    op.add_column(
        "poams",
        sa.Column("acceptance_rationale", sa.Text(), nullable=True),
        schema=_SCHEMA,
    )


def downgrade() -> None:
    op.drop_column("poams", "acceptance_rationale", schema=_SCHEMA)
