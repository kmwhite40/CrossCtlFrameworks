"""Policy documents: template origin, parameters, the version in force.

Revision ID: 0104_policy_documents
Revises: 0103_ato_workspace
Create Date: 2026-10-20

Concord stored policies and versions but nothing could say *which* version was
in force, what a version's text hashed to, or which organization-defined
values a templated policy was rendered with. ``active_version_id`` is set only
by an approved activation (``ccf.policies.service``); ``body_sha256`` is what an
approval and an authorization package refer to; ``unresolved_parameters`` keeps
a version that still reads "[ORGANIZATION-DEFINED: x]" from being put in force.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0104_policy_documents"
down_revision = "0103_ato_workspace"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("policies", sa.Column("template_key", sa.String(64)), schema="ccf")
    op.add_column(
        "policies",
        sa.Column("parameters", JSONB(), nullable=False, server_default="{}"),
        schema="ccf",
    )
    op.add_column(
        "policies",
        sa.Column(
            "active_version_id",
            sa.BigInteger(),
            sa.ForeignKey("ccf.policy_versions.id", ondelete="SET NULL"),
        ),
        schema="ccf",
    )
    op.add_column("policy_versions", sa.Column("created_by", sa.String(255)), schema="ccf")
    op.add_column("policy_versions", sa.Column("body_sha256", sa.String(64)), schema="ccf")
    op.add_column(
        "policy_versions",
        sa.Column("unresolved_parameters", JSONB(), nullable=False, server_default="[]"),
        schema="ccf",
    )
    # Existing bodies get their hash now, so an approval can refer to them.
    op.execute(
        "UPDATE ccf.policy_versions SET body_sha256 = encode(sha256(convert_to(body, 'UTF8')), "
        "'hex') WHERE body IS NOT NULL"
    )


def downgrade() -> None:
    for col in ("unresolved_parameters", "body_sha256", "created_by"):
        op.drop_column("policy_versions", col, schema="ccf")
    for col in ("active_version_id", "parameters", "template_key"):
        op.drop_column("policies", col, schema="ccf")
