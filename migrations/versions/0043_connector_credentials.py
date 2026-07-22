"""Per-organization connector credentials (IA-05).

Adds ``encrypted_credential`` and ``key_last4`` to ``ccf.connector_configs`` so
each organization's config-capture connector (Microsoft Graph, AWS GovCloud)
can be bound to that org's own credential instead of a single global env
credential. The secret is stored only as an envelope-encrypted token (reusing
the Slice-3a cipher, :mod:`ccf.ai.cipher`); ``key_last4`` is the sole
identifier ever surfaced to callers/UI, mirroring ``ai_provider_configs``.

Revision ID: 0043_connector_credentials
Revises: 0042_portal_share_fks
Create Date: 2026-07-21
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0043_connector_credentials"
down_revision = "0042_portal_share_fks"
branch_labels = None
depends_on = None

_TABLE = "connector_configs"


def upgrade() -> None:
    op.add_column(_TABLE, sa.Column("encrypted_credential", sa.Text), schema="ccf")
    op.add_column(_TABLE, sa.Column("key_last4", sa.String(8)), schema="ccf")


def downgrade() -> None:
    op.drop_column(_TABLE, "key_last4", schema="ccf")
    op.drop_column(_TABLE, "encrypted_credential", schema="ccf")
