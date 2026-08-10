"""Evidence preparation pipeline tables.

Seven tables backing parse → screen → expand → classify → embed. Structure is
preserved down to the table cell on ``prep_lines`` so every retrieved passage
cites a page and cell; ``prep_units.search_vector`` is the lexical half of hybrid
retrieval and is maintained by a trigger rather than application code, so a unit
written by any path is immediately searchable.

Revision ID: 0052_prep_tables
Revises: 0051_pgvector_extension
Create Date: 2026-08-10
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from pgvector.sqlalchemy import Vector
from sqlalchemy.dialects import postgresql

revision = "0052_prep_tables"
down_revision = "0051_pgvector_extension"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"


def upgrade() -> None:
    op.create_table(
        "prep_runs",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey(f"{_SCHEMA}.organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source_kind", sa.String(32), nullable=False),
        sa.Column("source_id", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("stage_parse", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("stage_screen", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("stage_expand", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("stage_classify", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("stage_embed", sa.String(32), nullable=False, server_default="pending"),
        sa.Column(
            "config_snapshot", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'")
        ),
        sa.Column("media_type", sa.String(255)),
        sa.Column("parser_name", sa.String(64)),
        sa.Column("lines_parsed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("lines_above_threshold", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("units_built", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("units_classified", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("units_embedded", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_stage", sa.String(32)),
        sa.Column("error", sa.Text()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_prep_runs_source", "prep_runs",
        ["organization_id", "source_kind", "source_id"], schema=_SCHEMA,
    )
    op.create_index("ix_prep_runs_status", "prep_runs", ["status"], schema=_SCHEMA)
    op.create_index(
        "ix_prep_runs_organization_id", "prep_runs", ["organization_id"], schema=_SCHEMA
    )

    op.create_table(
        "prep_lines",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "run_id", sa.BigInteger(),
            sa.ForeignKey(f"{_SCHEMA}.prep_runs.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "organization_id", sa.Integer(),
            sa.ForeignKey(f"{_SCHEMA}.organizations.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("line_number", sa.Integer(), nullable=False),
        sa.Column("page_number", sa.Integer()),
        sa.Column("section_path", sa.Text()),
        sa.Column("block_id", sa.String(128)),
        sa.Column("block_type", sa.String(64)),
        sa.Column("table_id", sa.String(128)),
        sa.Column("row_index", sa.Integer()),
        sa.Column("col_index", sa.Integer()),
        sa.Column("cell_label", sa.String(255)),
        sa.Column("content", sa.Text(), nullable=False),
        schema=_SCHEMA,
    )
    op.create_index("ix_prep_lines_run_line", "prep_lines", ["run_id", "line_number"], schema=_SCHEMA)
    op.create_index("ix_prep_lines_run_id", "prep_lines", ["run_id"], schema=_SCHEMA)
    op.create_index(
        "ix_prep_lines_organization_id", "prep_lines", ["organization_id"], schema=_SCHEMA
    )

    op.create_table(
        "prep_screens",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "line_id", sa.BigInteger(),
            sa.ForeignKey(f"{_SCHEMA}.prep_lines.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "run_id", sa.BigInteger(),
            sa.ForeignKey(f"{_SCHEMA}.prep_runs.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "organization_id", sa.Integer(),
            sa.ForeignKey(f"{_SCHEMA}.organizations.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("relevance_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column(
            "candidate_controls", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'")
        ),
        sa.Column("above_threshold", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("method", sa.String(32), nullable=False, server_default="catalog_fts"),
        sa.Column(
            "screened_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        schema=_SCHEMA,
    )
    for col in ("line_id", "run_id", "organization_id", "above_threshold"):
        op.create_index(f"ix_prep_screens_{col}", "prep_screens", [col], schema=_SCHEMA)

    op.create_table(
        "prep_units",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "run_id", sa.BigInteger(),
            sa.ForeignKey(f"{_SCHEMA}.prep_runs.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "organization_id", sa.Integer(),
            sa.ForeignKey(f"{_SCHEMA}.organizations.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "trigger_line_id", sa.BigInteger(),
            sa.ForeignKey(f"{_SCHEMA}.prep_lines.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "source_line_ids", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'")
        ),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column(
            "page_numbers", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'")
        ),
        sa.Column("section_path", sa.Text()),
        sa.Column("table_coordinates", postgresql.JSONB()),
        sa.Column("token_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("search_vector", postgresql.TSVECTOR()),
        sa.Column(
            "system_id", sa.Integer(),
            sa.ForeignKey(f"{_SCHEMA}.systems.id", ondelete="SET NULL"),
        ),
        sa.Column("source_kind", sa.String(32)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        schema=_SCHEMA,
    )
    for col in ("run_id", "organization_id", "trigger_line_id", "system_id", "source_kind"):
        op.create_index(f"ix_prep_units_{col}", "prep_units", [col], schema=_SCHEMA)
    op.create_index(
        "ix_prep_units_search_vector", "prep_units", ["search_vector"],
        postgresql_using="gin", schema=_SCHEMA,
    )

    # Maintained by trigger, not application code: a unit written by any path
    # (pipeline, backfill, manual repair) is immediately searchable.
    op.execute(
        f"""
        CREATE FUNCTION {_SCHEMA}.prep_units_search_vector_update()
        RETURNS trigger AS $$
        BEGIN
            NEW.search_vector :=
                setweight(to_tsvector('english', coalesce(NEW.content, '')), 'A') ||
                setweight(to_tsvector('english', coalesce(NEW.section_path, '')), 'B');
            RETURN NEW;
        END
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER prep_units_search_vector_trg
        BEFORE INSERT OR UPDATE OF content, section_path ON {_SCHEMA}.prep_units
        FOR EACH ROW EXECUTE FUNCTION {_SCHEMA}.prep_units_search_vector_update()
        """
    )

    op.create_table(
        "prep_classifications",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "unit_id", sa.BigInteger(),
            sa.ForeignKey(f"{_SCHEMA}.prep_units.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "run_id", sa.BigInteger(),
            sa.ForeignKey(f"{_SCHEMA}.prep_runs.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "organization_id", sa.Integer(),
            sa.ForeignKey(f"{_SCHEMA}.organizations.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "control_identifiers", postgresql.JSONB(), nullable=False,
            server_default=sa.text("'[]'"),
        ),
        sa.Column("artifact_type", sa.String(64)),
        sa.Column("evidence_strength", sa.String(32)),
        sa.Column("explanation", sa.Text()),
        sa.Column("model_name", sa.String(128)),
        sa.Column("model_confidence", sa.Float()),
        sa.Column(
            "ai_action_run_id", sa.BigInteger(),
            sa.ForeignKey(f"{_SCHEMA}.ai_action_runs.id", ondelete="SET NULL"),
        ),
        sa.Column(
            "classified_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        schema=_SCHEMA,
    )
    for col in ("unit_id", "run_id", "organization_id", "ai_action_run_id"):
        op.create_index(f"ix_prep_classifications_{col}", "prep_classifications", [col],
                        schema=_SCHEMA)

    op.create_table(
        "prep_embeddings",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "unit_id", sa.BigInteger(),
            sa.ForeignKey(f"{_SCHEMA}.prep_units.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "run_id", sa.BigInteger(),
            sa.ForeignKey(f"{_SCHEMA}.prep_runs.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "organization_id", sa.Integer(),
            sa.ForeignKey(f"{_SCHEMA}.organizations.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("model_name", sa.String(128), nullable=False),
        sa.Column("embedding", Vector(1024)),
        sa.Column(
            "embedded_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_prep_embeddings_unit_id", "prep_embeddings", ["unit_id"], unique=True, schema=_SCHEMA
    )
    op.create_index("ix_prep_embeddings_run_id", "prep_embeddings", ["run_id"], schema=_SCHEMA)
    op.create_index(
        "ix_prep_embeddings_organization_id", "prep_embeddings", ["organization_id"], schema=_SCHEMA
    )
    # IVFFlat needs training rows to be useful; HNSW does not, and prep corpora
    # start empty. Cosine distance matches the retriever's operator.
    op.execute(
        f"""
        CREATE INDEX ix_prep_embeddings_vector
        ON {_SCHEMA}.prep_embeddings
        USING hnsw (embedding vector_cosine_ops)
        """
    )

    op.create_table(
        "prep_jobs",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "run_id", sa.BigInteger(),
            sa.ForeignKey(f"{_SCHEMA}.prep_runs.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "organization_id", sa.Integer(),
            sa.ForeignKey(f"{_SCHEMA}.organizations.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("next_stage", sa.String(32), nullable=False, server_default="parse"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("claimed_at", sa.DateTime(timezone=True)),
        sa.Column("claimed_by", sa.String(128)),
        sa.Column("last_error", sa.Text()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        schema=_SCHEMA,
    )
    op.create_index("ix_prep_jobs_claimable", "prep_jobs", ["status", "created_at"], schema=_SCHEMA)
    op.create_index("ix_prep_jobs_run_id", "prep_jobs", ["run_id"], schema=_SCHEMA)
    op.create_index(
        "ix_prep_jobs_organization_id", "prep_jobs", ["organization_id"], schema=_SCHEMA
    )
    op.create_index("ix_prep_jobs_status", "prep_jobs", ["status"], schema=_SCHEMA)


def downgrade() -> None:
    op.drop_table("prep_jobs", schema=_SCHEMA)
    op.drop_table("prep_embeddings", schema=_SCHEMA)
    op.drop_table("prep_classifications", schema=_SCHEMA)
    op.execute(f"DROP TRIGGER IF EXISTS prep_units_search_vector_trg ON {_SCHEMA}.prep_units")
    op.execute(f"DROP FUNCTION IF EXISTS {_SCHEMA}.prep_units_search_vector_update()")
    op.drop_table("prep_units", schema=_SCHEMA)
    op.drop_table("prep_screens", schema=_SCHEMA)
    op.drop_table("prep_lines", schema=_SCHEMA)
    op.drop_table("prep_runs", schema=_SCHEMA)
