"""An approval names the decision it authorizes.

Revision ID: 0112_approval_purpose
Revises: 0111_certification_snapshots
Create Date: 2026-11-06

One approval row per entity carried only a state, so an approval requested to
close a remediated POA&M -- which the system's ISSO may grant -- was equally
spendable on extending that POA&M's risk acceptance, and a reviewer approving
"POA&M #12" could not see which of those they were authorizing.
``purpose`` records the decision at submission; the reviewer decides that
decision, and only the gate for it can spend the approval
(``ccf.governance.approvals.PURPOSES``).

Existing rows keep ``NULL``. An unspent approval on a POA&M or risk with no
purpose authorizes nothing after this revision and must be requested again
with one: which decision it was granted for was never recorded, so the
upgrade cannot say.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0112_approval_purpose"
down_revision = "0111_certification_snapshots"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("approvals", sa.Column("purpose", sa.String(32)), schema="ccf")


def downgrade() -> None:
    op.drop_column("approvals", "purpose", schema="ccf")
