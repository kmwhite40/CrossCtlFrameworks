"""Pack source backoff -- track consecutive poll failures.

PR #17 security review, IMPORTANT 8: an ``invalid`` (or ``error``) pack
source never advanced ``last_sha256``, so its full body was re-fetched and
re-parsed on every scheduler cycle forever -- a third-party DoS amplifier
driven entirely by tenant-supplied config. ``consecutive_failures`` backs the
bounded backoff added in ``ccf.packs.sync.check_pack_source``.

Revision ID: 0074_pack_source_backoff
Revises: 0073_pack_sources
Create Date: 2026-09-16
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0074_pack_source_backoff"
down_revision = "0073_pack_sources"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"


def upgrade() -> None:
    op.add_column(
        "pack_sources",
        sa.Column(
            "consecutive_failures",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        schema=_SCHEMA,
    )


def downgrade() -> None:
    op.drop_column("pack_sources", "consecutive_failures", schema=_SCHEMA)
