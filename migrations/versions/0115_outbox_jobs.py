"""Transactional outbox: the event bus's durable job queue.

Revision ID: 0115_outbox_jobs
Revises: 0114_approval_entity_org
Create Date: 2026-11-06

``outbox_jobs`` holds one row per (event, matching consumer), inserted in the
same transaction as the change. Workers claim rows with ``ccf.queue.claim_jobs``
and update them in place, so ``ccf_app`` keeps UPDATE but never DELETE.
``organization_id`` is NULL only for platform-only jobs; the standard tenant
predicate then matches unscoped (system) sessions only.

See docs/superpowers/specs/2026-11-06-event-bus-outbox-design.md.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0115_outbox_jobs"
down_revision = "0114_approval_entity_org"
branch_labels = None
depends_on = None

_PREDICATE = "(ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant())"


def upgrade() -> None:
    op.create_table(
        "outbox_jobs",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("consumer", sa.String(48), nullable=False),
        sa.Column("scope_key", sa.String(96), nullable=False),
        sa.Column(
            "trigger_event_id",
            sa.BigInteger(),
            sa.ForeignKey("ccf.events.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("absorbed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="5"),
        sa.Column("claimed_at", sa.DateTime(timezone=True)),
        sa.Column("claimed_by", sa.String(128)),
        sa.Column(
            "next_attempt_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.Text()),
        sa.Column("merged_into", sa.BigInteger()),
        sa.Column("result", JSONB, nullable=False, server_default="{}"),
        sa.CheckConstraint(
            "status IN ('pending', 'claimed', 'done', 'merged', 'failed')",
            name="ck_outbox_jobs_status",
        ),
        schema="ccf",
    )
    op.create_index(
        "ix_outbox_jobs_status_next", "outbox_jobs", ["status", "next_attempt_at"], schema="ccf"
    )
    op.create_index(
        "ix_outbox_jobs_consumer_scope_status",
        "outbox_jobs",
        ["consumer", "scope_key", "status"],
        schema="ccf",
    )
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE ON ccf.outbox_jobs TO ccf_app; "
        # 0010's default privileges also hand every new table DELETE and a
        # GRANT adds to them; jobs are finished or dead-lettered, never deleted.
        "REVOKE DELETE, TRUNCATE ON ccf.outbox_jobs FROM ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    op.execute("ALTER TABLE ccf.outbox_jobs ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE ccf.outbox_jobs FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON ccf.outbox_jobs "
        f"FOR ALL USING {_PREDICATE} WITH CHECK {_PREDICATE}"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS ccf.outbox_jobs")
