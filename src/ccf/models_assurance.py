"""Assurance graph — a typed, relational "authorization digital twin".

A tenant-scoped graph over Concord's existing records (systems, controls, KSIs,
evidence, scans, POA&Ms, risks, vendors, connectors, …) stored in plain Postgres
tables (no external graph DB). :class:`AssuranceNode` + :class:`AssuranceEdge` hold
the live graph; the remaining tables capture build runs, per-system snapshots,
cached impact analyses, and saved queries. Kept in a dedicated module (imported by
the assurance routes/service) so the layer is easy to review.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base


class AssuranceNode(Base):
    """One entity in the assurance graph (upserted per tenant + entity identity)."""

    __tablename__ = "assurance_nodes"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    entity_type: Mapped[str] = mapped_column(String(48), index=True)
    entity_id: Mapped[str] = mapped_column(String(128))
    label: Mapped[str] = mapped_column(String(512))
    status: Mapped[str | None] = mapped_column(String(32))
    node_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict)
    build_run_id: Mapped[int | None] = mapped_column(BigInteger)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint("organization_id", "entity_type", "entity_id", name="uq_assurance_node"),
    )


class AssuranceEdge(Base):
    """A typed, directional relationship between two :class:`AssuranceNode`s."""

    __tablename__ = "assurance_edges"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    source_node_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.assurance_nodes.id", ondelete="CASCADE"), index=True
    )
    target_node_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.assurance_nodes.id", ondelete="CASCADE"), index=True
    )
    relationship_type: Mapped[str] = mapped_column(String(48))
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    edge_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict)

    __table_args__ = (
        UniqueConstraint(
            "source_node_id", "target_node_id", "relationship_type", name="uq_assurance_edge"
        ),
    )


class AssuranceGraphBuildRun(Base):
    """Provenance for one (re)build of the assurance graph."""

    __tablename__ = "assurance_build_runs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    node_count: Mapped[int] = mapped_column(Integer, default=0)
    edge_count: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(16), default="running")  # running|ok|error
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)


class AssuranceSnapshot(Base):
    """A point-in-time capture of a system's assurance subgraph summary."""

    __tablename__ = "assurance_snapshots"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    system_id: Mapped[int | None] = mapped_column(ForeignKey("ccf.systems.id", ondelete="CASCADE"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    node_count: Mapped[int] = mapped_column(Integer, default=0)
    edge_count: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)


class AssuranceImpact(Base):
    """A cached impact-analysis result rooted at one entity."""

    __tablename__ = "assurance_impacts"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    impact_kind: Mapped[str] = mapped_column(String(48))
    root_entity_type: Mapped[str] = mapped_column(String(48))
    root_entity_id: Mapped[str] = mapped_column(String(128))
    affected: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AssuranceQuery(Base):
    """A saved assurance-graph query (definition)."""

    __tablename__ = "assurance_queries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(255))
    definition: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AssuranceQueryResult(Base):
    """A stored execution of an :class:`AssuranceQuery`."""

    __tablename__ = "assurance_query_results"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    query_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.assurance_queries.id", ondelete="CASCADE"), index=True
    )
    result: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
