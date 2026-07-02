"""Assertion-based automated control tests.

Adds an optional ``assertion`` JSON to ``control_tests`` so a connector-backed
test can carry a machine-checkable rule (e.g. ``mfa_enforced == true``) that the
auto-runner evaluates against the latest captured config value — a real
pass/fail on posture rather than only checking that the connector synced.

Revision ID: 0024_control_test_assertion
Revises: 0023_scan_ingestion
Create Date: 2026-07-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0024_control_test_assertion"
down_revision = "0023_scan_ingestion"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "control_tests", sa.Column("assertion", postgresql.JSONB), schema="ccf"
    )


def downgrade() -> None:
    op.drop_column("control_tests", "assertion", schema="ccf")
