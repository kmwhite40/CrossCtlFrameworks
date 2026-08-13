"""Enable the pgvector extension for evidence-unit embeddings.

Semantic retrieval over prepared evidence needs vector similarity. Concord
already relies on pg_trgm and pgcrypto (see 0001_baseline); vector joins that
set. The extension is created here rather than in the baseline so existing
deployments pick it up on upgrade, and the DB image must be
pgvector/pgvector:pg16 (a drop-in for stock PG16).

Revision ID: 0055_pgvector_extension
Revises: 0054_ssp_project_framework
Create Date: 2026-08-10
"""

from __future__ import annotations

from alembic import op

revision = "0055_pgvector_extension"
down_revision = "0054_ssp_project_framework"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")


def downgrade() -> None:
    # Left in place: dropping it would cascade-drop any vector columns.
    pass
