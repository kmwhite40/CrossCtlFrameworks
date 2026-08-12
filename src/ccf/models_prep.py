"""Evidence preparation pipeline models — parse → screen → expand → classify → embed.

A :class:`PrepRun` prepares one immutable source document (an ``EvidenceVersion``
or a ``PolicyVersion``, addressed polymorphically so no new document table is
needed). Each stage persists its full output before the next begins and records
its own status on the run, so a failure resumes at the failed stage rather than
re-parsing.

The traceability chain is ``PrepUnit.source_line_ids -> PrepLine -> page_number +
section_path + table cell``: every retrieved passage cites a page and, for
tabular sources, a specific cell. Kept in a dedicated module so the layer is easy
to review, matching ``models_evidence`` and ``models_ai_actions``.

**These seven tables carry a ``tenant_isolation`` RLS policy** (migration
``0060``, 2026-08-12 RLS-coverage design), matching 121 of Concord's 135
``ccf`` tables. It is defence in depth, not the primary control: every prep
query still filters by ``organization_id`` explicitly
(``ccf.prep.retriever._base_filters`` and the equivalent per-stage filters in
``screen.py``/``expand.py``/``classify.py``/``embed.py``), and those checks
are not removed or relaxed by the policy's addition.
:func:`ccf.prep.jobs.claim` is **intentionally, still, unscoped** by
organization — one worker process drains every organization's queued jobs by
design — which means the RLS policy above provides no protection on that
specific path: ``ccf.prep.jobs.claim`` runs through ``ccf.db.session_scope()``,
which leaves the tenant GUC unset and the bootstrap (table-owning) role in
effect, and an unset GUC is exactly what every policy in this schema treats
as bypass. The application-level guards on that path —
:func:`ccf.prep.sources.resolve_source_organization_id` and
``ccf.prep.pipeline``'s per-stage organization reconciliation — are what
actually protect it, verified by
``tests/test_prep_tenant_isolation.py`` and (for the GUC mechanism itself)
``tests/test_rls_worker_guc_bypass.py``. See ``docs/ARCHITECTURE.md``'s
"Evidence preparation" section for the same note alongside the rest of the
pipeline's description.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, TSVECTOR
from sqlalchemy.orm import Mapped, mapped_column

# Registers ccf.ai_action_runs — the PrepClassification.ai_action_run_id FK
# target — before mapper configuration, since no importer of this module does.
from . import models_ai_actions  # noqa: F401
from .models import Base

#: Ordered pipeline stages. The order is load-bearing: resumption restarts at the
#: first stage that is not ``complete``.
PREP_STAGES = ("parse", "screen", "expand", "classify", "embed")

PREP_RUN_STATES = ("pending", "running", "complete", "failed", "unsupported", "orphaned")
PREP_STAGE_STATES = ("pending", "running", "complete", "failed", "skipped")
PREP_JOB_STATES = ("pending", "claimed", "done", "failed")
PREP_SOURCE_KINDS = ("evidence_version", "policy_version")

#: pgvector columns require a fixed dimension, so this is schema, not config.
#: ``Settings.prep_embed_dimensions`` validates the provider against it.
PREP_EMBEDDING_DIM = 1024


class PrepRun(Base):
    """One preparation pass over one immutable source document."""

    __tablename__ = "prep_runs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    # Polymorphic source ref — no FK, because the target table varies. The
    # resolver validates existence and closes the run as ``orphaned`` if the
    # source has been deleted.
    source_kind: Mapped[str] = mapped_column(String(32))
    source_id: Mapped[int] = mapped_column(BigInteger)

    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    stage_parse: Mapped[str] = mapped_column(String(32), default="pending")
    stage_screen: Mapped[str] = mapped_column(String(32), default="pending")
    stage_expand: Mapped[str] = mapped_column(String(32), default="pending")
    stage_classify: Mapped[str] = mapped_column(String(32), default="pending")
    stage_embed: Mapped[str] = mapped_column(String(32), default="pending")

    #: Thresholds and window sizes in force for this run, so a re-run is
    #: comparable and a settings change is visible rather than silent.
    config_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    media_type: Mapped[str | None] = mapped_column(String(255))
    parser_name: Mapped[str | None] = mapped_column(String(64))

    lines_parsed: Mapped[int] = mapped_column(Integer, default=0)
    lines_above_threshold: Mapped[int] = mapped_column(Integer, default=0)
    units_built: Mapped[int] = mapped_column(Integer, default=0)
    units_classified: Mapped[int] = mapped_column(Integer, default=0)
    units_embedded: Mapped[int] = mapped_column(Integer, default=0)

    error_stage: Mapped[str | None] = mapped_column(String(32))
    error: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        Index("ix_prep_runs_source", "organization_id", "source_kind", "source_id"),
    )


class PrepLine(Base):
    """One line-level record with its source structure preserved."""

    __tablename__ = "prep_lines"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    run_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.prep_runs.id", ondelete="CASCADE"), index=True
    )
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    line_number: Mapped[int] = mapped_column(Integer)
    page_number: Mapped[int | None] = mapped_column(Integer)
    #: Heading breadcrumb, e.g. "Access Control > Account Management".
    section_path: Mapped[str | None] = mapped_column(Text)
    block_id: Mapped[str | None] = mapped_column(String(128))
    #: paragraph | heading | table_cell | list_item | caption | slide_text | sheet_cell
    block_type: Mapped[str | None] = mapped_column(String(64))
    table_id: Mapped[str | None] = mapped_column(String(128))
    row_index: Mapped[int | None] = mapped_column(Integer)
    col_index: Mapped[int | None] = mapped_column(Integer)
    #: Inherited column header for a table cell — what makes a bare value legible.
    cell_label: Mapped[str | None] = mapped_column(String(255))
    content: Mapped[str] = mapped_column(Text)

    __table_args__ = (Index("ix_prep_lines_run_line", "run_id", "line_number"),)


class PrepScreen(Base):
    """Relevance screen for one line against the 800-53A catalog."""

    __tablename__ = "prep_screens"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    line_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.prep_lines.id", ondelete="CASCADE"), index=True
    )
    run_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.prep_runs.id", ondelete="CASCADE"), index=True
    )
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    relevance_score: Mapped[float] = mapped_column(Float, default=0.0)
    #: ``ccf.controls.identifier`` values, ranked best-first.
    candidate_controls: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    above_threshold: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    #: How the score was produced, so a future LLM screen is distinguishable.
    method: Mapped[str] = mapped_column(String(32), default="catalog_fts")
    screened_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class PrepUnit(Base):
    """A context-expanded, semantically complete passage."""

    __tablename__ = "prep_units"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    run_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.prep_runs.id", ondelete="CASCADE"), index=True
    )
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    trigger_line_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.prep_lines.id", ondelete="CASCADE"), index=True
    )
    #: Every line folded into this unit — the traceability chain.
    source_line_ids: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    content: Mapped[str] = mapped_column(Text)
    page_numbers: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    section_path: Mapped[str | None] = mapped_column(Text)
    table_coordinates: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    token_count: Mapped[int] = mapped_column(Integer, default=0)
    #: Lexical half of hybrid retrieval; maintained by a trigger (see migration).
    search_vector: Mapped[Any] = mapped_column(TSVECTOR, nullable=True)
    #: Denormalised for retrieval filtering without joining back through the run.
    system_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.systems.id", ondelete="SET NULL"), index=True
    )
    source_kind: Mapped[str | None] = mapped_column(String(32), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_prep_units_search_vector", "search_vector", postgresql_using="gin"),
    )


class PrepClassification(Base):
    """Model-produced classification of one unit, with provenance."""

    __tablename__ = "prep_classifications"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    unit_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.prep_units.id", ondelete="CASCADE"), index=True
    )
    run_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.prep_runs.id", ondelete="CASCADE"), index=True
    )
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    #: ``ccf.controls.identifier`` strings, not integer FKs — matching how
    #: ``EvidenceObject.control_id`` already tags controls, and durable across
    #: catalog re-ingest.
    control_identifiers: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    #: policy | procedure | technical_implementation | testing_evidence | management_approval
    artifact_type: Mapped[str | None] = mapped_column(String(64))
    #: strong | moderate | weak
    evidence_strength: Mapped[str | None] = mapped_column(String(32))
    explanation: Mapped[str | None] = mapped_column(Text)
    model_name: Mapped[str | None] = mapped_column(String(128))
    model_confidence: Mapped[float | None] = mapped_column(Float)
    #: Links to the governed AI action run carrying citations and guardrail state.
    ai_action_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.ai_action_runs.id", ondelete="SET NULL"), index=True
    )
    classified_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class PrepEmbedding(Base):
    """Vector embedding of one unit for semantic retrieval."""

    __tablename__ = "prep_embeddings"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    unit_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.prep_units.id", ondelete="CASCADE"), index=True, unique=True
    )
    run_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.prep_runs.id", ondelete="CASCADE"), index=True
    )
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    #: Recorded so a model change is detectable rather than silently mixing spaces.
    model_name: Mapped[str] = mapped_column(String(128))
    embedding: Mapped[Any] = mapped_column(Vector(PREP_EMBEDDING_DIM), nullable=True)
    embedded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class PrepJob(Base):
    """Queue entry driving a run through the pipeline."""

    __tablename__ = "prep_jobs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    run_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.prep_runs.id", ondelete="CASCADE"), index=True
    )
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    #: Resume pointer — the first stage not yet complete.
    next_stage: Mapped[str] = mapped_column(String(32), default="parse")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    claimed_by: Mapped[str | None] = mapped_column(String(128))
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (Index("ix_prep_jobs_claimable", "status", "created_at"),)
