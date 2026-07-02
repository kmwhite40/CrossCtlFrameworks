"""Assurance graph — authorization digital twin (nodes, edges, runs, impact).

Adds the relational assurance-graph tables, all tenant-isolated (org-scoped rows
directly; edges/nodes/impacts via organization_id; query results via parent query).

Revision ID: 0029_assurance_graph
Revises: 0028_evidence_repository
Create Date: 2026-07-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0029_assurance_graph"
down_revision = "0028_evidence_repository"
branch_labels = None
depends_on = None

JB = postgresql.JSONB
_ORG = "organization_id = ccf.current_tenant()"
_QUERY = (
    "query_id IN (SELECT id FROM ccf.assurance_queries "
    "WHERE organization_id = ccf.current_tenant())"
)
_POLICIES = {
    "assurance_nodes": _ORG,
    "assurance_edges": _ORG,
    "assurance_build_runs": _ORG,
    "assurance_snapshots": _ORG,
    "assurance_impacts": _ORG,
    "assurance_queries": _ORG,
    "assurance_query_results": _QUERY,
}


def _org_col() -> sa.Column:
    return sa.Column(
        "organization_id", sa.Integer, sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE")
    )


def upgrade() -> None:
    op.create_table(
        "assurance_build_runs",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _org_col(),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("node_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("edge_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("status", sa.String(16), nullable=False, server_default="running"),
        sa.Column("detail", JB, server_default="{}", nullable=False),
        schema="ccf",
    )
    op.create_table(
        "assurance_nodes",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _org_col(),
        sa.Column("entity_type", sa.String(48), nullable=False),
        sa.Column("entity_id", sa.String(128), nullable=False),
        sa.Column("label", sa.String(512), nullable=False),
        sa.Column("status", sa.String(32)),
        sa.Column("metadata", JB, server_default="{}", nullable=False),
        sa.Column("build_run_id", sa.BigInteger),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("organization_id", "entity_type", "entity_id", name="uq_assurance_node"),
        schema="ccf",
    )
    op.create_index("ix_ccf_assurance_nodes_org", "assurance_nodes", ["organization_id"], schema="ccf")
    op.create_index("ix_ccf_assurance_nodes_type", "assurance_nodes", ["entity_type"], schema="ccf")

    op.create_table(
        "assurance_edges",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _org_col(),
        sa.Column(
            "source_node_id", sa.BigInteger,
            sa.ForeignKey("ccf.assurance_nodes.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "target_node_id", sa.BigInteger,
            sa.ForeignKey("ccf.assurance_nodes.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("relationship_type", sa.String(48), nullable=False),
        sa.Column("confidence", sa.Float, nullable=False, server_default="1.0"),
        sa.Column("metadata", JB, server_default="{}", nullable=False),
        sa.UniqueConstraint(
            "source_node_id", "target_node_id", "relationship_type", name="uq_assurance_edge"
        ),
        schema="ccf",
    )
    op.create_index("ix_ccf_assurance_edges_org", "assurance_edges", ["organization_id"], schema="ccf")
    op.create_index("ix_ccf_assurance_edges_src", "assurance_edges", ["source_node_id"], schema="ccf")
    op.create_index("ix_ccf_assurance_edges_tgt", "assurance_edges", ["target_node_id"], schema="ccf")

    op.create_table(
        "assurance_snapshots",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _org_col(),
        sa.Column("system_id", sa.Integer, sa.ForeignKey("ccf.systems.id", ondelete="CASCADE")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("node_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("edge_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("summary", JB, server_default="{}", nullable=False),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_assurance_snapshots_org", "assurance_snapshots", ["organization_id"], schema="ccf"
    )

    op.create_table(
        "assurance_impacts",
        sa.Column("id", sa.BigInteger, primary_key=True),
        _org_col(),
        sa.Column("impact_kind", sa.String(48), nullable=False),
        sa.Column("root_entity_type", sa.String(48), nullable=False),
        sa.Column("root_entity_id", sa.String(128), nullable=False),
        sa.Column("affected", JB, server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_assurance_impacts_org", "assurance_impacts", ["organization_id"], schema="ccf"
    )

    op.create_table(
        "assurance_queries",
        sa.Column("id", sa.Integer, primary_key=True),
        _org_col(),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("definition", JB, server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_assurance_queries_org", "assurance_queries", ["organization_id"], schema="ccf"
    )

    op.create_table(
        "assurance_query_results",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "query_id", sa.Integer,
            sa.ForeignKey("ccf.assurance_queries.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("result", JB, server_default="{}", nullable=False),
        sa.Column("note", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_assurance_query_results_q", "assurance_query_results", ["query_id"], schema="ccf"
    )

    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    for table, predicate in _POLICIES.items():
        expr = f"(ccf.current_tenant() IS NULL OR {predicate})"
        op.execute(f"ALTER TABLE ccf.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE ccf.{table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON ccf.{table} "
            f"FOR ALL USING {expr} WITH CHECK {expr}"
        )


def downgrade() -> None:
    for table in _POLICIES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON ccf.{table}")
    op.drop_table("assurance_query_results", schema="ccf")
    op.drop_table("assurance_queries", schema="ccf")
    op.drop_table("assurance_impacts", schema="ccf")
    op.drop_table("assurance_snapshots", schema="ccf")
    op.drop_table("assurance_edges", schema="ccf")
    op.drop_table("assurance_nodes", schema="ccf")
    op.drop_table("assurance_build_runs", schema="ccf")
