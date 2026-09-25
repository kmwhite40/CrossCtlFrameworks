"""Where a Concord record has been filed in an external tracker.

Push-only: this table records what Concord sent, never what the remote system
currently says. There is deliberately no column mirroring the remote ticket's
status -- a mirrored status is a second answer to a question a regulator asks
Concord, and the moment the two disagree the wrong one is on someone's screen.

RLS follows the schema standard exactly (see 0064): FORCE is required, because
the owning role `ccf` bypasses its own policy without it, which would produce a
policy that exists, reports as enabled, and is bypassed on precisely the
connections the application uses. `current_tenant() IS NULL` means unrestricted,
keeping CLI/ETL/migrations unaffected as every other tenant table does.

Revision ID: 0087_external_issue_links
Revises: 0086_ai_action_run_model
Create Date: 2026-09-25
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0087_external_issue_links"
down_revision = "0086_ai_action_run_model"
branch_labels = None
depends_on = None

_TABLE = "external_issue_links"
_PREDICATE = "(ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant())"


def upgrade() -> None:
    op.create_table(
        _TABLE,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("entity_type", sa.String(32), nullable=False),
        sa.Column("entity_id", sa.Integer(), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("external_id", sa.String(64), nullable=False),
        sa.Column("external_url", sa.Text(), nullable=False),
        sa.Column("last_pushed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(16), nullable=False, server_default="ok"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "organization_id",
            "provider",
            "entity_type",
            "entity_id",
            name="uq_external_issue_link_entity",
        ),
        schema="ccf",
    )
    op.create_index(
        "ix_external_issue_links_organization_id", _TABLE, ["organization_id"], schema="ccf"
    )
    op.create_index("ix_external_issue_links_provider", _TABLE, ["provider"], schema="ccf")
    op.create_index(
        "ix_external_issue_link_entity", _TABLE, ["entity_type", "entity_id"], schema="ccf"
    )

    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    op.execute(f"ALTER TABLE ccf.{_TABLE} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE ccf.{_TABLE} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation ON ccf.{_TABLE} "
        f"FOR ALL USING {_PREDICATE} WITH CHECK {_PREDICATE}"
    )


def downgrade() -> None:
    op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON ccf.{_TABLE}")
    op.drop_table(_TABLE, schema="ccf")
