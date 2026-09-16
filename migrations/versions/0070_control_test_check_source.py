"""Persist which expectation produced a control test: platform, or which pack.

``control_tests.source`` (0068) already distinguishes 'generated' from
'authored', but that is orthogonal to *whose* expectation a generated test
enforces. ``posture.resolve.ResolvedCheck.source`` has carried that
distinction ("platform" vs. "pack:<pack_key>") since it was introduced, but
nothing persisted it -- ``posture.scan._upsert_generated_test`` hardcoded
``source="generated"`` and ``record_result`` had no way to say more. In the
authorization package an assessor could not tell a tenant's self-attested
pack verdict from a platform assessment of the same control (CRITICAL 3, PR
#13 review).

No backfill: a pre-existing generated row's provenance cannot be recovered
from its own columns without re-deriving it against the *current* check
registry, which would misattribute any row whose originating check has since
been retired or renamed. Existing rows keep ``check_source IS NULL``;
``posture.scan.effective_verdict`` treats a null value on a 'generated' row
whose ``check_key`` is still a registered platform check as platform-sourced
(a narrower, safe inference over live data, not a migration-time guess), and
every such row is overwritten with a real value on its next scan
(``_upsert_generated_test`` sets it unconditionally on every re-scan, the
same as ``control_id``/``description``).

Tenancy: no new table; the existing ``control_tests`` RLS policy already
covers every column on the row.

Revision ID: 0070_control_test_check_source
Revises: 0069_pack_version_manifest
Create Date: 2026-09-16
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0070_control_test_check_source"
down_revision = "0069_pack_version_manifest"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"


def upgrade() -> None:
    op.add_column(
        "control_tests", sa.Column("check_source", sa.String(64)), schema=_SCHEMA
    )

    # Standard grant guard: no-op where the ccf_app role was never created.
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )


def downgrade() -> None:
    op.drop_column("control_tests", "check_source", schema=_SCHEMA)
