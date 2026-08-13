# Evidence Preparation & Retrieval Spine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give Concord the ability to read an uploaded evidence or policy document — turning it into control-tagged, semantically retrievable passages that cite back to a page and table cell.

**Architecture:** A five-stage pipeline (`parse → screen → expand → classify → embed`) in a new `src/ccf/prep/` module, driven by a DB-backed job queue drained by a `ccf prep-worker` CLI command. Each stage persists before the next begins and records its own status, so a failed run resumes at the failed stage. Every seam plugs into existing Concord machinery: screening ranks against the 800-53A catalog the ETL already ingests, classification runs as a registered AI action, embeddings go through `ccf.ai.gateway`, bytes through `ccf.evidence.storage`.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy 2.0 (async, `Mapped`), Alembic, Postgres 16 + pgvector + pg_trgm, PyMuPDF, python-docx, openpyxl, python-pptx, Typer, structlog, pytest (asyncio_mode=auto).

**Spec:** [docs/superpowers/specs/2026-08-10-evidence-prep-spine-design.md](../specs/2026-08-10-evidence-prep-spine-design.md)

## Global Constraints

- **Licensing:** ATO Bot is BUSL 1.1 and its Additional Use Grant forbids inclusion as a material feature of another commercial GRC product. **No ATO Bot source may be copied.** Every file here is original work against Concord's own interfaces.
- **Python:** `requires-python = ">=3.12"`, `target-version = "py312"`.
- **Lint:** `ruff check .` — select `["E","F","W","I","UP","B","SIM","N","PL","RUF"]`, `line-length = 100`.
- **Types:** `mypy src` runs `strict = true`. Every new function needs full annotations. New third-party imports without stubs need a `[[tool.mypy.overrides]]` block with `ignore_missing_imports = true`.
- **Tests:** `pytest -q` against **real Postgres** (`postgresql+asyncpg://ccf:ccf@localhost:5432/ccf_test`). `asyncio_mode = "auto"` — do not decorate async tests with `@pytest.mark.asyncio`. Every test module starts with `pytestmark = pytest.mark.usefixtures("fresh_engine")`.
- **Schema:** all new tables live in the `ccf` Postgres schema. Models import `Base` via `from .models import Base`.
- **Migrations:** sequential, `migrations/versions/00NN_<slug>.py`, with `revision = "00NN_<slug>"` and `down_revision` pointing at the prior head. **Current head is `0050_evidence_object_impl_fk`.** Migrations are excluded from mypy and ruff.
- **Status vocabularies** (fixed; `String(32)` with application-level checks, never a Postgres enum): `prep_runs.status` = `pending|running|complete|failed|unsupported|orphaned`; each `stage_*` = `pending|running|complete|failed|skipped`; `prep_jobs.status` = `pending|claimed|done|failed`.
- **Multi-tenancy:** every new table carries `organization_id` and every query filters on it.
- **Vector width is 1024 and fixed in the schema.** `prep_embed_dimensions` is a *validation* setting, not a column width.

---

### Task 1: pgvector infrastructure, dependencies, and settings

Swaps the Postgres image for the pgvector build, enables the extension, adds the parser dependencies, and registers the `CCF_PREP_*` settings. Nothing else can be built until the extension exists.

**Files:**
- Modify: `docker-compose.yml` (db service image)
- Modify: `.github/workflows/ci.yml:17` (postgres service image)
- Modify: `pyproject.toml` (dependencies + mypy overrides)
- Modify: `src/ccf/config.py` (new settings)
- Create: `migrations/versions/0051_pgvector_extension.py`
- Create: `tests/test_prep_infra.py`

**Interfaces:**
- Consumes: nothing (first task).
- Produces: the `vector` Postgres extension; `Settings.prep_enabled: bool`, `prep_screen_threshold: float`, `prep_expand_window: int`, `prep_embed_provider: str`, `prep_embed_model: str`, `prep_embed_dimensions: int`, `prep_worker_batch_size: int`, `prep_job_stale_after_minutes: int`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_prep_infra.py`:

```python
"""pgvector extension availability and prep settings defaults."""

from __future__ import annotations

import pytest
from sqlalchemy import text

from ccf.config import get_settings
from ccf.db import session_scope

pytestmark = pytest.mark.usefixtures("fresh_engine")


async def test_vector_extension_is_installed() -> None:
    async with session_scope() as s:
        row = (
            await s.execute(text("SELECT 1 FROM pg_extension WHERE extname = 'vector'"))
        ).scalar_one_or_none()
        assert row == 1, "pgvector extension missing — is the DB image pgvector/pgvector:pg16?"


async def test_vector_column_round_trips() -> None:
    async with session_scope() as s:
        await s.execute(text("CREATE TEMP TABLE _vt (v vector(3))"))
        await s.execute(text("INSERT INTO _vt (v) VALUES ('[1,2,3]')"))
        got = (await s.execute(text("SELECT v::text FROM _vt"))).scalar_one()
        assert got == "[1,2,3]"


def test_prep_settings_defaults() -> None:
    s = get_settings()
    assert s.prep_enabled is False
    assert s.prep_screen_threshold == 0.15
    assert s.prep_expand_window == 4
    assert s.prep_embed_dimensions == 1024
    assert s.prep_worker_batch_size == 10
    assert s.prep_job_stale_after_minutes == 60
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_prep_infra.py -v`
Expected: FAIL — `test_vector_extension_is_installed` asserts `None == 1`, and `test_prep_settings_defaults` raises `AttributeError: 'Settings' object has no attribute 'prep_enabled'`.

- [ ] **Step 3: Swap the Postgres image in compose and CI**

In `docker-compose.yml`, change the `db` service image:

```yaml
  db:
    image: pgvector/pgvector:pg16
```

In `.github/workflows/ci.yml` line 17, change the service image:

```yaml
    services:
      postgres:
        image: pgvector/pgvector:pg16
```

This is a drop-in for stock PG16 — same major version and data directory layout — so no data migration is needed.

- [ ] **Step 4: Add dependencies and mypy overrides**

In `pyproject.toml`, append to `dependencies`:

```toml
    "pgvector>=0.3,<1",
    "pymupdf>=1.24,<2",
    "python-pptx>=1.0,<2",
```

Then append these override blocks:

```toml
[[tool.mypy.overrides]]
module = ["pgvector", "pgvector.*"]
ignore_missing_imports = true

[[tool.mypy.overrides]]
module = ["fitz", "fitz.*", "pptx", "pptx.*"]
ignore_missing_imports = true
```

Install them: `pip install -e ".[dev]"`

- [ ] **Step 5: Add the prep settings**

In `src/ccf/config.py`, inside `class Settings`, add after the existing `evidence_*` block:

```python
    # ---- Evidence preparation pipeline (parse → screen → expand → classify → embed)
    prep_enabled: bool = Field(default=False)
    # Screening is deliberately inclusive: false positives are cheap (resolved by
    # downstream classification), false negatives are unrecoverable.
    prep_screen_threshold: float = Field(default=0.15)
    # Lines either side of a trigger line when no block/table/section bound applies.
    prep_expand_window: int = Field(default=4)
    # Embeddings resolve independently of the generation provider: Anthropic has no
    # embeddings endpoint, so an org generating with Anthropic still embeds elsewhere.
    prep_embed_provider: str = Field(default="openai")
    prep_embed_model: str = Field(default="text-embedding-3-small")
    # Validation only — pgvector column width is fixed at 1024 in the schema. A
    # mismatch fails the embed stage loudly rather than writing truncated vectors.
    prep_embed_dimensions: int = Field(default=1024)
    prep_worker_batch_size: int = Field(default=10)
    prep_job_stale_after_minutes: int = Field(default=60)
```

- [ ] **Step 6: Write the extension migration**

Create `migrations/versions/0051_pgvector_extension.py`:

```python
"""Enable the pgvector extension for evidence-unit embeddings.

Semantic retrieval over prepared evidence needs vector similarity. Concord
already relies on pg_trgm and pgcrypto (see 0001_baseline); vector joins that
set. The extension is created here rather than in the baseline so existing
deployments pick it up on upgrade, and the DB image must be
pgvector/pgvector:pg16 (a drop-in for stock PG16).

Revision ID: 0051_pgvector_extension
Revises: 0050_evidence_object_impl_fk
Create Date: 2026-08-10
"""

from __future__ import annotations

from alembic import op

revision = "0051_pgvector_extension"
down_revision = "0050_evidence_object_impl_fk"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")


def downgrade() -> None:
    # Left in place: dropping it would cascade-drop any vector columns.
    pass
```

- [ ] **Step 7: Recreate the local database container and migrate**

The image swap requires a fresh container. Run:

```bash
docker compose down && docker compose up -d db && sleep 5 && alembic upgrade head
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `pytest tests/test_prep_infra.py -v`
Expected: PASS (3 tests)

- [ ] **Step 9: Verify lint and types are clean**

Run: `ruff check . && mypy src`
Expected: no errors.

- [ ] **Step 10: Commit**

```bash
git add docker-compose.yml .github/workflows/ci.yml pyproject.toml \
        src/ccf/config.py migrations/versions/0051_pgvector_extension.py \
        tests/test_prep_infra.py
git commit -m "feat(prep): enable pgvector, add parser deps and prep settings"
```

---

### Task 2: Prep data model and migration

The seven tables the pipeline writes to. Built in one task because the migration is a single unit and the tables are only meaningful together.

**Files:**
- Create: `src/ccf/models_prep.py`
- Create: `migrations/versions/0052_prep_tables.py`
- Create: `tests/test_prep_models.py`

**Interfaces:**
- Consumes: `vector` extension from Task 1.
- Produces: `PrepRun`, `PrepLine`, `PrepScreen`, `PrepUnit`, `PrepClassification`, `PrepEmbedding`, `PrepJob`; constants `PREP_RUN_STATES`, `PREP_STAGE_STATES`, `PREP_JOB_STATES`, `PREP_STAGES`, `PREP_SOURCE_KINDS`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_prep_models.py`:

```python
"""Prep pipeline tables — round-trip, cascade, and traceability chain."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from ccf.db import session_scope
from ccf.models import Organization
from ccf.models_prep import (
    PREP_STAGES,
    PrepClassification,
    PrepEmbedding,
    PrepLine,
    PrepRun,
    PrepScreen,
    PrepUnit,
)

pytestmark = pytest.mark.usefixtures("fresh_engine")


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return int(org.id)


async def test_run_defaults_every_stage_to_pending() -> None:
    org_id = await _org("prep-defaults")
    async with session_scope() as s:
        run = PrepRun(organization_id=org_id, source_kind="evidence_version", source_id=1)
        s.add(run)
        await s.flush()
        assert run.status == "pending"
        for stage in PREP_STAGES:
            assert getattr(run, f"stage_{stage}") == "pending"


async def test_traceability_chain_resolves_page_and_cell() -> None:
    """A unit must resolve back to the page and table cell it came from."""
    org_id = await _org("prep-trace")
    async with session_scope() as s:
        run = PrepRun(organization_id=org_id, source_kind="evidence_version", source_id=1)
        s.add(run)
        await s.flush()
        line = PrepLine(
            run_id=run.id,
            organization_id=org_id,
            line_number=7,
            page_number=3,
            section_path="Access Control > Account Management",
            block_type="table_cell",
            table_id="t1",
            row_index=2,
            col_index=1,
            cell_label="Review Frequency",
            content="Accounts are reviewed quarterly.",
        )
        s.add(line)
        await s.flush()
        unit = PrepUnit(
            run_id=run.id,
            organization_id=org_id,
            trigger_line_id=line.id,
            source_line_ids=[line.id],
            content="Accounts are reviewed quarterly.",
            page_numbers=[3],
            section_path="Access Control > Account Management",
            table_coordinates={"table_id": "t1", "row_index": 2, "col_index": 1},
            token_count=8,
        )
        s.add(unit)
        await s.flush()
        unit_id = unit.id

    async with session_scope() as s:
        unit = (await s.execute(select(PrepUnit).where(PrepUnit.id == unit_id))).scalar_one()
        origin = (
            await s.execute(select(PrepLine).where(PrepLine.id.in_(unit.source_line_ids)))
        ).scalars().all()
        assert [o.page_number for o in origin] == [3]
        assert origin[0].cell_label == "Review Frequency"


async def test_deleting_a_run_cascades_to_all_children() -> None:
    org_id = await _org("prep-cascade")
    async with session_scope() as s:
        run = PrepRun(organization_id=org_id, source_kind="policy_version", source_id=9)
        s.add(run)
        await s.flush()
        line = PrepLine(
            run_id=run.id, organization_id=org_id, line_number=1, content="MFA is required."
        )
        s.add(line)
        await s.flush()
        s.add(PrepScreen(line_id=line.id, run_id=run.id, organization_id=org_id,
                         relevance_score=0.9, candidate_controls=["IA-2"], above_threshold=True))
        unit = PrepUnit(run_id=run.id, organization_id=org_id, trigger_line_id=line.id,
                        source_line_ids=[line.id], content="MFA is required.", token_count=4)
        s.add(unit)
        await s.flush()
        s.add(PrepClassification(unit_id=unit.id, run_id=run.id, organization_id=org_id,
                                 control_identifiers=["IA-2"], artifact_type="policy",
                                 evidence_strength="strong", model_confidence=0.8))
        s.add(PrepEmbedding(unit_id=unit.id, run_id=run.id, organization_id=org_id,
                            model_name="text-embedding-3-small", embedding=[0.1] * 1024))
        await s.flush()
        run_id = run.id

    async with session_scope() as s:
        run = (await s.execute(select(PrepRun).where(PrepRun.id == run_id))).scalar_one()
        await s.delete(run)

    async with session_scope() as s:
        assert (await s.execute(select(PrepLine).where(PrepLine.run_id == run_id))).first() is None
        assert (await s.execute(select(PrepUnit).where(PrepUnit.run_id == run_id))).first() is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_prep_models.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.models_prep'`.

- [ ] **Step 3: Write the models**

Create `src/ccf/models_prep.py`:

```python
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
```

- [ ] **Step 4: Register the models for metadata discovery**

`Base.metadata` only sees imported modules. In `src/ccf/db.py`, find where the other `models_*` modules are imported for metadata registration and add `models_prep` alongside them. If no such import block exists, add this to the bottom of `src/ccf/models_prep.py`'s consumers instead — specifically, add to `src/ccf/api/main.py` near the other model imports:

```python
from .. import models_prep  # noqa: F401  — register prep tables on Base.metadata
```

Verify with: `python -c "from ccf import models_prep; from ccf.models import Base; print([t for t in Base.metadata.tables if 'prep' in t])"`
Expected: seven `ccf.prep_*` table names.

- [ ] **Step 5: Write the tables migration**

Create `migrations/versions/0052_prep_tables.py`:

```python
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
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
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
        sa.Column("screened_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
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
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
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
        sa.Column("classified_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
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
        sa.Column("embedded_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
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
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
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
```

- [ ] **Step 6: Apply the migration**

Run: `alembic upgrade head && alembic downgrade -1 && alembic upgrade head`
Expected: all three succeed. The down-then-up round trip proves `downgrade()` is correct — a broken downgrade blocks every future migration's testing.

- [ ] **Step 7: Run tests to verify they pass**

Run: `pytest tests/test_prep_models.py -v`
Expected: PASS (3 tests)

- [ ] **Step 8: Verify lint and types**

Run: `ruff check . && mypy src`
Expected: no errors.

- [ ] **Step 9: Commit**

```bash
git add src/ccf/models_prep.py migrations/versions/0052_prep_tables.py \
        tests/test_prep_models.py src/ccf/api/main.py
git commit -m "feat(prep): add pipeline tables with cell-level traceability"
```

---

### Task 3: Parser contract, dispatcher, and text parser

The shared dataclasses every parser returns, plus the simplest concrete parser. Establishing the contract first means Tasks 4–7 are independent of each other.

**Files:**
- Create: `src/ccf/prep/__init__.py`
- Create: `src/ccf/prep/parsers/__init__.py`
- Create: `src/ccf/prep/parsers/base.py`
- Create: `src/ccf/prep/parsers/text.py`
- Create: `src/ccf/prep/parsers/dispatcher.py`
- Create: `tests/test_prep_parsers_text.py`

**Interfaces:**
- Consumes: nothing from prior tasks (pure functions over bytes).
- Produces:
  - `ParsedCell(text: str, row_index: int, col_index: int, header: str | None)`
  - `ParsedBlock(block_id: str, block_type: str, text: str, heading_path: list[str], row_index: int | None, col_index: int | None, table_id: str | None, cell_label: str | None, cells: list[ParsedCell], metadata: dict[str, Any])`
  - `ParsedPage(page_number: int, blocks: list[ParsedBlock], section_title: str | None, metadata: dict[str, Any])`
  - `ParsedDocument(filename: str, media_type: str, pages: list[ParsedPage], parser_name: str, error: str | None)` with properties `success: bool` and `iter_lines() -> Iterator[ParsedLineRecord]`
  - `ParsedLineRecord(line_number: int, page_number: int | None, section_path: str | None, block_id: str | None, block_type: str | None, table_id: str | None, row_index: int | None, col_index: int | None, cell_label: str | None, content: str)`
  - `parse_text(data: bytes, filename: str) -> ParsedDocument`
  - `dispatch(data: bytes, filename: str, media_type: str | None) -> ParsedDocument`
  - `UnsupportedMediaType` exception

- [ ] **Step 1: Write the failing test**

Create `tests/test_prep_parsers_text.py`:

```python
"""Parser contract and the plain-text parser."""

from __future__ import annotations

import pytest

from ccf.prep.parsers import UnsupportedMediaType, dispatch
from ccf.prep.parsers.text import parse_text


def test_text_parser_produces_one_line_per_nonblank_line() -> None:
    doc = parse_text(b"First line.\n\nSecond line.\n", "policy.txt")
    assert doc.success
    assert doc.parser_name == "text"
    lines = list(doc.iter_lines())
    assert [line.content for line in lines] == ["First line.", "Second line."]


def test_line_numbers_are_sequential_from_one() -> None:
    doc = parse_text(b"a\nb\nc\n", "x.txt")
    assert [line.line_number for line in doc.iter_lines()] == [1, 2, 3]


def test_text_parser_decodes_utf8_and_survives_bad_bytes() -> None:
    doc = parse_text("Café requires MFA.".encode(), "p.txt")
    assert "Café" in next(iter(doc.iter_lines())).content
    # Invalid UTF-8 must degrade, not raise — evidence arrives in every encoding.
    doc2 = parse_text(b"\xff\xfe bad bytes but readable", "p.txt")
    assert doc2.success


def test_dispatch_routes_plain_text_by_media_type() -> None:
    doc = dispatch(b"hello", "note.txt", "text/plain")
    assert doc.parser_name == "text"


def test_dispatch_falls_back_to_extension_when_media_type_missing() -> None:
    doc = dispatch(b"hello", "note.txt", None)
    assert doc.parser_name == "text"


def test_dispatch_raises_for_unsupported_media_type() -> None:
    with pytest.raises(UnsupportedMediaType) as exc:
        dispatch(b"\x00", "diagram.vsdx", None)
    assert "vsdx" in str(exc.value)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_prep_parsers_text.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.prep'`.

- [ ] **Step 3: Write the parser contract**

Create `src/ccf/prep/__init__.py`:

```python
"""Evidence preparation pipeline — parse, screen, expand, classify, embed."""
```

Create `src/ccf/prep/parsers/base.py`:

```python
"""Shared parser contract.

Every parser returns a :class:`ParsedDocument` regardless of source format, so
the pipeline's parse stage is format-agnostic. Structure is preserved on the way
through — heading path, table identity, row and column index, and the inherited
column header for a cell — because a bare table value ("Quarterly") is only
evidence when you know which column it sat under.

:meth:`ParsedDocument.iter_lines` is the flattening step: it walks pages and
blocks in document order and emits the line-level records the parse stage
persists to ``prep_lines``.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ParsedCell:
    """One native cell inside a parsed table row."""

    text: str
    row_index: int
    col_index: int
    header: str | None = None


@dataclass(slots=True)
class ParsedBlock:
    """A logical source block — paragraph, heading, list item, or table cell."""

    block_id: str
    block_type: str
    text: str
    heading_path: list[str] = field(default_factory=list)
    row_index: int | None = None
    col_index: int | None = None
    table_id: str | None = None
    cell_label: str | None = None
    cells: list[ParsedCell] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ParsedPage:
    """One page, slide, or sheet."""

    page_number: int
    blocks: list[ParsedBlock] = field(default_factory=list)
    section_title: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ParsedLineRecord:
    """A flattened line ready to persist as a ``prep_lines`` row."""

    line_number: int
    content: str
    page_number: int | None = None
    section_path: str | None = None
    block_id: str | None = None
    block_type: str | None = None
    table_id: str | None = None
    row_index: int | None = None
    col_index: int | None = None
    cell_label: str | None = None


@dataclass(slots=True)
class ParsedDocument:
    """The parser-neutral result for one source document."""

    filename: str
    media_type: str
    parser_name: str
    pages: list[ParsedPage] = field(default_factory=list)
    error: str | None = None

    @property
    def success(self) -> bool:
        return self.error is None and any(page.blocks for page in self.pages)

    def iter_lines(self) -> Iterator[ParsedLineRecord]:
        """Walk pages and blocks in document order, numbering lines from 1."""
        line_number = 0
        for page in self.pages:
            for block in page.blocks:
                text = block.text.strip()
                if not text:
                    continue
                line_number += 1
                yield ParsedLineRecord(
                    line_number=line_number,
                    content=text,
                    page_number=page.page_number,
                    section_path=" > ".join(block.heading_path) or None,
                    block_id=block.block_id,
                    block_type=block.block_type,
                    table_id=block.table_id,
                    row_index=block.row_index,
                    col_index=block.col_index,
                    cell_label=block.cell_label,
                )


def decode_text(data: bytes) -> str:
    """Decode bytes to text, degrading rather than raising.

    Evidence arrives in every encoding and a single bad byte must not fail a
    whole document — losing one character is always better than losing the file.
    """
    return data.decode("utf-8", errors="replace")
```

- [ ] **Step 4: Write the text parser**

Create `src/ccf/prep/parsers/text.py`:

```python
"""Plain-text parser — one block per non-blank line."""

from __future__ import annotations

from .base import ParsedBlock, ParsedDocument, ParsedPage, decode_text

PARSER_NAME = "text"


def parse_text(data: bytes, filename: str, media_type: str = "text/plain") -> ParsedDocument:
    """Parse plain text into a single page of paragraph blocks."""
    blocks = [
        ParsedBlock(block_id=f"p{index}", block_type="paragraph", text=stripped)
        for index, raw in enumerate(decode_text(data).splitlines(), start=1)
        if (stripped := raw.strip())
    ]
    return ParsedDocument(
        filename=filename,
        media_type=media_type,
        parser_name=PARSER_NAME,
        pages=[ParsedPage(page_number=1, blocks=blocks)],
    )
```

- [ ] **Step 5: Write the dispatcher**

Create `src/ccf/prep/parsers/dispatcher.py`:

```python
"""Route a source document to the right parser by media type or extension.

Unsupported formats raise :class:`UnsupportedMediaType` rather than failing
silently — the pipeline records the run as ``unsupported`` so the coverage gap is
visible in the data. Image OCR and Visio are deliberately out of scope for this
slice (see the design spec).
"""

from __future__ import annotations

from pathlib import Path

from .base import ParsedDocument
from .text import parse_text


class UnsupportedMediaType(RuntimeError):
    """No parser is registered for this document's format."""


#: Extension → media type. Consulted when the caller has no media type, which is
#: common for policy documents referenced only by URI.
_EXTENSION_MEDIA_TYPES = {
    ".txt": "text/plain",
    ".md": "text/plain",
    ".csv": "text/plain",
    ".pdf": "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}


def resolve_media_type(filename: str, media_type: str | None) -> str:
    """Prefer the declared media type; fall back to the filename extension."""
    if media_type:
        return media_type.split(";")[0].strip().lower()
    suffix = Path(filename).suffix.lower()
    resolved = _EXTENSION_MEDIA_TYPES.get(suffix)
    if resolved is None:
        raise UnsupportedMediaType(f"no parser for '{suffix or filename}'")
    return resolved


def dispatch(data: bytes, filename: str, media_type: str | None = None) -> ParsedDocument:
    """Parse ``data`` with the parser registered for its format."""
    resolved = resolve_media_type(filename, media_type)
    if resolved.startswith("text/"):
        return parse_text(data, filename, resolved)
    raise UnsupportedMediaType(f"no parser for '{resolved}'")
```

Create `src/ccf/prep/parsers/__init__.py`:

```python
"""Document parsers producing a format-neutral :class:`ParsedDocument`."""

from __future__ import annotations

from .base import (
    ParsedBlock,
    ParsedCell,
    ParsedDocument,
    ParsedLineRecord,
    ParsedPage,
    decode_text,
)
from .dispatcher import UnsupportedMediaType, dispatch, resolve_media_type

__all__ = [
    "ParsedBlock",
    "ParsedCell",
    "ParsedDocument",
    "ParsedLineRecord",
    "ParsedPage",
    "UnsupportedMediaType",
    "decode_text",
    "dispatch",
    "resolve_media_type",
]
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `pytest tests/test_prep_parsers_text.py -v`
Expected: PASS (6 tests)

- [ ] **Step 7: Verify lint and types**

Run: `ruff check . && mypy src`
Expected: no errors.

- [ ] **Step 8: Commit**

```bash
git add src/ccf/prep tests/test_prep_parsers_text.py
git commit -m "feat(prep): add parser contract, dispatcher, and text parser"
```

---

### Task 4: DOCX parser

Word documents are where policies and procedures actually live. The two things that must survive: the heading breadcrumb a paragraph sits under, and the column header a table cell sits beneath.

**Files:**
- Create: `src/ccf/prep/parsers/docx.py`
- Modify: `src/ccf/prep/parsers/dispatcher.py` (register the parser)
- Create: `tests/test_prep_parsers_docx.py`

**Interfaces:**
- Consumes: `ParsedBlock`, `ParsedCell`, `ParsedDocument`, `ParsedPage` from Task 3.
- Produces: `parse_docx(data: bytes, filename: str, media_type: str = ...) -> ParsedDocument`, `PARSER_NAME = "docx"`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_prep_parsers_docx.py`:

```python
"""DOCX parser — heading breadcrumbs and table cell headers."""

from __future__ import annotations

import io

import pytest
from docx import Document

from ccf.prep.parsers import dispatch
from ccf.prep.parsers.docx import parse_docx


def _docx_bytes() -> bytes:
    doc = Document()
    doc.add_heading("Access Control", level=1)
    doc.add_heading("Account Management", level=2)
    doc.add_paragraph("Accounts are reviewed by the system owner.")
    table = doc.add_table(rows=2, cols=2)
    table.cell(0, 0).text = "Activity"
    table.cell(0, 1).text = "Review Frequency"
    table.cell(1, 0).text = "Privileged account review"
    table.cell(1, 1).text = "Quarterly"
    doc.add_heading("Audit and Accountability", level=1)
    doc.add_paragraph("Audit logs are retained for one year.")
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def test_paragraph_inherits_its_heading_breadcrumb() -> None:
    doc = parse_docx(_docx_bytes(), "policy.docx")
    line = next(x for x in doc.iter_lines() if x.content.startswith("Accounts are reviewed"))
    assert line.section_path == "Access Control > Account Management"


def test_breadcrumb_resets_when_a_higher_level_heading_appears() -> None:
    """A level-1 heading must clear the stale level-2 crumb, not append to it."""
    doc = parse_docx(_docx_bytes(), "policy.docx")
    line = next(x for x in doc.iter_lines() if x.content.startswith("Audit logs"))
    assert line.section_path == "Audit and Accountability"


def test_table_cell_carries_its_column_header_and_coordinates() -> None:
    doc = parse_docx(_docx_bytes(), "policy.docx")
    line = next(x for x in doc.iter_lines() if x.content == "Quarterly")
    assert line.cell_label == "Review Frequency"
    assert line.block_type == "table_cell"
    assert (line.row_index, line.col_index) == (1, 1)
    assert line.table_id is not None


def test_header_row_cells_have_no_self_referential_label() -> None:
    doc = parse_docx(_docx_bytes(), "policy.docx")
    line = next(x for x in doc.iter_lines() if x.content == "Review Frequency")
    assert line.cell_label is None


def test_dispatch_routes_docx() -> None:
    doc = dispatch(_docx_bytes(), "policy.docx", None)
    assert doc.parser_name == "docx"
    assert doc.success


def test_corrupt_docx_returns_an_error_document_rather_than_raising() -> None:
    doc = parse_docx(b"not a real docx", "broken.docx")
    assert not doc.success
    assert doc.error is not None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_prep_parsers_docx.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.prep.parsers.docx'`.

- [ ] **Step 3: Write the DOCX parser**

Create `src/ccf/prep/parsers/docx.py`:

```python
"""Word document parser.

Two structures matter and both are easy to lose. A paragraph's meaning depends on
the heading it sits under, so headings are tracked as a stack that truncates when
a higher level appears — otherwise "Accounts are reviewed quarterly" under
Audit inherits a stale Access Control crumb. And a table cell's meaning depends
on its column header: "Quarterly" is not evidence, "Review Frequency: Quarterly"
is.

python-docx exposes paragraphs and tables as separate collections, losing their
relative order. Document order is recovered by walking the body's XML children
and mapping each element back to its wrapper.
"""

from __future__ import annotations

import io
import logging
from typing import Any

from docx import Document
from docx.document import Document as DocxDocument
from docx.table import Table
from docx.text.paragraph import Paragraph

from .base import ParsedBlock, ParsedCell, ParsedDocument, ParsedPage

log = logging.getLogger(__name__)

PARSER_NAME = "docx"
MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def _heading_level(paragraph: Paragraph) -> int | None:
    """Return the outline level of a heading paragraph, or ``None`` if it is body text."""
    style = (paragraph.style.name or "") if paragraph.style is not None else ""
    if not style.startswith("Heading"):
        return None
    tail = style.removeprefix("Heading").strip()
    return int(tail) if tail.isdigit() else 1


def _iter_body(document: DocxDocument) -> list[Paragraph | Table]:
    """Yield paragraphs and tables in true document order."""
    paragraphs = {p._element: p for p in document.paragraphs}  # noqa: SLF001
    tables = {t._element: t for t in document.tables}  # noqa: SLF001
    ordered: list[Paragraph | Table] = []
    for element in document.element.body.iterchildren():
        found = paragraphs.get(element) or tables.get(element)
        if found is not None:
            ordered.append(found)
    return ordered


def _table_blocks(table: Table, table_index: int, heading_path: list[str]) -> list[ParsedBlock]:
    """Flatten a table to one block per non-empty cell, carrying its column header."""
    table_id = f"t{table_index}"
    rows = table.rows
    if not rows:
        return []
    headers = [cell.text.strip() for cell in rows[0].cells]
    blocks: list[ParsedBlock] = []
    for row_index, row in enumerate(rows):
        cells = [
            ParsedCell(
                text=cell.text.strip(),
                row_index=row_index,
                col_index=col_index,
                header=headers[col_index] if col_index < len(headers) else None,
            )
            for col_index, cell in enumerate(row.cells)
        ]
        for cell in cells:
            if not cell.text:
                continue
            blocks.append(
                ParsedBlock(
                    block_id=f"{table_id}r{cell.row_index}c{cell.col_index}",
                    block_type="table_cell",
                    text=cell.text,
                    heading_path=list(heading_path),
                    row_index=cell.row_index,
                    col_index=cell.col_index,
                    table_id=table_id,
                    # The header row labels itself otherwise, which is noise.
                    cell_label=cell.header if row_index > 0 else None,
                    cells=cells,
                )
            )
    return blocks


def parse_docx(data: bytes, filename: str, media_type: str = MEDIA_TYPE) -> ParsedDocument:
    """Parse a .docx into heading-aware paragraph and table-cell blocks."""
    try:
        document = Document(io.BytesIO(data))
    except Exception as exc:  # noqa: BLE001 — any malformed file must not kill the run
        log.warning("prep.parse.docx_failed", extra={"filename": filename, "error": str(exc)})
        return ParsedDocument(
            filename=filename, media_type=media_type, parser_name=PARSER_NAME,
            error=f"could not open document: {exc}",
        )

    blocks: list[ParsedBlock] = []
    heading_path: list[str] = []
    table_index = 0
    paragraph_index = 0

    for item in _iter_body(document):
        if isinstance(item, Table):
            table_index += 1
            blocks.extend(_table_blocks(item, table_index, heading_path))
            continue

        text = item.text.strip()
        if not text:
            continue
        level = _heading_level(item)
        if level is not None:
            # Truncate to the parent depth before pushing, so a level-1 heading
            # discards any deeper crumbs left over from the previous section.
            del heading_path[level - 1 :]
            heading_path.append(text)
            block_type = "heading"
        else:
            block_type = "paragraph"
        paragraph_index += 1
        blocks.append(
            ParsedBlock(
                block_id=f"p{paragraph_index}",
                block_type=block_type,
                text=text,
                heading_path=list(heading_path),
            )
        )

    metadata: dict[str, Any] = {"block_count": len(blocks)}
    return ParsedDocument(
        filename=filename,
        media_type=media_type,
        parser_name=PARSER_NAME,
        pages=[ParsedPage(page_number=1, blocks=blocks, metadata=metadata)],
    )
```

Note on the heading breadcrumb: a heading includes *itself* in its own `heading_path`, which is what makes `section_path` on a heading line self-describing. Body paragraphs inherit the stack as-is.

- [ ] **Step 4: Register DOCX in the dispatcher**

In `src/ccf/prep/parsers/dispatcher.py`, add the import and the branch:

```python
from .docx import MEDIA_TYPE as DOCX_MEDIA_TYPE
from .docx import parse_docx
```

and inside `dispatch`, before the final `raise`:

```python
    if resolved == DOCX_MEDIA_TYPE:
        return parse_docx(data, filename, resolved)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_prep_parsers_docx.py -v`
Expected: PASS (6 tests)

- [ ] **Step 6: Verify lint and types**

Run: `ruff check . && mypy src`
Expected: no errors. If mypy objects to `python-docx` internals, add a `[[tool.mypy.overrides]]` block for `module = ["docx", "docx.*"]` with `ignore_missing_imports = true`.

- [ ] **Step 7: Commit**

```bash
git add src/ccf/prep/parsers/docx.py src/ccf/prep/parsers/dispatcher.py \
        tests/test_prep_parsers_docx.py pyproject.toml
git commit -m "feat(prep): add DOCX parser preserving headings and cell headers"
```

---

### Task 5: XLSX parser

Spreadsheets carry control matrices, asset inventories, and account reviews. Every cell needs its column header, and the sheet name is the section.

**Files:**
- Create: `src/ccf/prep/parsers/xlsx.py`
- Modify: `src/ccf/prep/parsers/dispatcher.py`
- Create: `tests/test_prep_parsers_xlsx.py`

**Interfaces:**
- Consumes: `ParsedBlock`, `ParsedCell`, `ParsedDocument`, `ParsedPage` from Task 3.
- Produces: `parse_xlsx(data: bytes, filename: str, media_type: str = ...) -> ParsedDocument`, `PARSER_NAME = "xlsx"`. Each worksheet becomes one `ParsedPage` numbered from 1 in sheet order, with `section_title` set to the sheet name.

- [ ] **Step 1: Write the failing test**

Create `tests/test_prep_parsers_xlsx.py`:

```python
"""XLSX parser — per-sheet pages, column headers, coordinate fidelity."""

from __future__ import annotations

import io

import openpyxl

from ccf.prep.parsers import dispatch
from ccf.prep.parsers.xlsx import parse_xlsx


def _xlsx_bytes() -> bytes:
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Account Review"
    ws.append(["Account", "Last Reviewed", "Reviewer"])
    ws.append(["svc-backup", "2026-07-01", "system owner"])
    ws2 = wb.create_sheet("Audit Retention")
    ws2.append(["Log Source", "Retention"])
    ws2.append(["firewall", "365 days"])
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def test_each_sheet_becomes_its_own_page_named_by_section_title() -> None:
    doc = parse_xlsx(_xlsx_bytes(), "inventory.xlsx")
    assert [p.section_title for p in doc.pages] == ["Account Review", "Audit Retention"]
    assert [p.page_number for p in doc.pages] == [1, 2]


def test_cell_carries_column_header_and_sheet_scoped_table_id() -> None:
    doc = parse_xlsx(_xlsx_bytes(), "inventory.xlsx")
    line = next(x for x in doc.iter_lines() if x.content == "2026-07-01")
    assert line.cell_label == "Last Reviewed"
    assert line.row_index == 1
    assert line.col_index == 1
    assert line.table_id == "Account Review"


def test_section_path_is_the_sheet_name() -> None:
    doc = parse_xlsx(_xlsx_bytes(), "inventory.xlsx")
    line = next(x for x in doc.iter_lines() if x.content == "365 days")
    assert line.section_path == "Audit Retention"


def test_blank_cells_are_skipped_but_do_not_shift_coordinates() -> None:
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "S"
    ws.append(["A", "B", "C"])
    ws.append(["one", None, "three"])
    buf = io.BytesIO()
    wb.save(buf)
    doc = parse_xlsx(buf.getvalue(), "s.xlsx")
    line = next(x for x in doc.iter_lines() if x.content == "three")
    assert line.col_index == 2
    assert line.cell_label == "C"


def test_numeric_cells_are_stringified() -> None:
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(["Days"])
    ws.append([365])
    buf = io.BytesIO()
    wb.save(buf)
    doc = parse_xlsx(buf.getvalue(), "n.xlsx")
    assert any(x.content == "365" for x in doc.iter_lines())


def test_dispatch_routes_xlsx() -> None:
    doc = dispatch(_xlsx_bytes(), "inventory.xlsx", None)
    assert doc.parser_name == "xlsx"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_prep_parsers_xlsx.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.prep.parsers.xlsx'`.

- [ ] **Step 3: Write the XLSX parser**

Create `src/ccf/prep/parsers/xlsx.py`:

```python
"""Spreadsheet parser.

Each worksheet becomes a page and the sheet name becomes both the section and the
table id — a control matrix and an asset inventory in the same workbook are
different evidence, and flattening them together would lose that. Row 1 is
treated as the header row, so every value below it carries the column label that
makes it legible.

Blank cells are skipped but never shift coordinates: ``col_index`` is the true
spreadsheet column, so a citation points at the cell a reader would actually
find.
"""

from __future__ import annotations

import io
import logging

import openpyxl

from .base import ParsedBlock, ParsedCell, ParsedDocument, ParsedPage

log = logging.getLogger(__name__)

PARSER_NAME = "xlsx"
MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def _as_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value).strip()


def parse_xlsx(data: bytes, filename: str, media_type: str = MEDIA_TYPE) -> ParsedDocument:
    """Parse a .xlsx into one page per worksheet of header-labelled cell blocks."""
    try:
        workbook = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
    except Exception as exc:  # noqa: BLE001 — a malformed workbook must not kill the run
        log.warning("prep.parse.xlsx_failed", extra={"filename": filename, "error": str(exc)})
        return ParsedDocument(
            filename=filename, media_type=media_type, parser_name=PARSER_NAME,
            error=f"could not open workbook: {exc}",
        )

    pages: list[ParsedPage] = []
    try:
        for page_number, sheet in enumerate(workbook.worksheets, start=1):
            rows = list(sheet.iter_rows(values_only=True))
            if not rows:
                pages.append(ParsedPage(page_number=page_number, section_title=sheet.title))
                continue
            headers = [_as_text(v) for v in rows[0]]
            blocks: list[ParsedBlock] = []
            for row_index, row in enumerate(rows):
                cells = [
                    ParsedCell(
                        text=_as_text(value),
                        row_index=row_index,
                        col_index=col_index,
                        header=headers[col_index] if col_index < len(headers) else None,
                    )
                    for col_index, value in enumerate(row)
                ]
                for cell in cells:
                    if not cell.text:
                        continue
                    blocks.append(
                        ParsedBlock(
                            block_id=f"{sheet.title}r{cell.row_index}c{cell.col_index}",
                            block_type="sheet_cell",
                            text=cell.text,
                            heading_path=[sheet.title],
                            row_index=cell.row_index,
                            col_index=cell.col_index,
                            table_id=sheet.title,
                            cell_label=cell.header if row_index > 0 else None,
                            cells=cells,
                        )
                    )
            pages.append(
                ParsedPage(page_number=page_number, blocks=blocks, section_title=sheet.title)
            )
    finally:
        workbook.close()

    return ParsedDocument(
        filename=filename, media_type=media_type, parser_name=PARSER_NAME, pages=pages
    )
```

- [ ] **Step 4: Register XLSX in the dispatcher**

In `src/ccf/prep/parsers/dispatcher.py`, add:

```python
from .xlsx import MEDIA_TYPE as XLSX_MEDIA_TYPE
from .xlsx import parse_xlsx
```

and inside `dispatch`, before the final `raise`:

```python
    if resolved == XLSX_MEDIA_TYPE:
        return parse_xlsx(data, filename, resolved)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_prep_parsers_xlsx.py -v`
Expected: PASS (6 tests)

- [ ] **Step 6: Verify lint and types**

Run: `ruff check . && mypy src`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add src/ccf/prep/parsers/xlsx.py src/ccf/prep/parsers/dispatcher.py \
        tests/test_prep_parsers_xlsx.py
git commit -m "feat(prep): add XLSX parser with per-sheet pages and column labels"
```

---

### Task 6: PDF parser

PDF is the format most real evidence arrives in — signed policies, scan reports, screenshots of consoles. PyMuPDF gives per-page text blocks with coordinates; page number is the citation that matters here.

**Files:**
- Create: `src/ccf/prep/parsers/pdf.py`
- Modify: `src/ccf/prep/parsers/dispatcher.py`
- Create: `tests/test_prep_parsers_pdf.py`

**Interfaces:**
- Consumes: `ParsedBlock`, `ParsedDocument`, `ParsedPage` from Task 3.
- Produces: `parse_pdf(data: bytes, filename: str, media_type: str = "application/pdf") -> ParsedDocument`, `PARSER_NAME = "pdf"`. A page with no extractable text (a scanned image) yields an empty block list and sets `metadata["text_extractable"] = False` rather than erroring — that is the OCR gap, recorded rather than hidden.

- [ ] **Step 1: Write the failing test**

Create `tests/test_prep_parsers_pdf.py`:

```python
"""PDF parser — page fidelity, block ordering, and the scanned-page gap."""

from __future__ import annotations

import fitz

from ccf.prep.parsers import dispatch
from ccf.prep.parsers.pdf import parse_pdf


def _pdf_bytes() -> bytes:
    doc = fitz.open()
    page1 = doc.new_page()
    page1.insert_text((72, 72), "Access control policy")
    page1.insert_text((72, 120), "Accounts are reviewed quarterly.")
    page2 = doc.new_page()
    page2.insert_text((72, 72), "Audit logs are retained for one year.")
    data: bytes = doc.tobytes()
    doc.close()
    return data


def test_lines_carry_their_true_page_number() -> None:
    doc = parse_pdf(_pdf_bytes(), "policy.pdf")
    line = next(x for x in doc.iter_lines() if "Audit logs" in x.content)
    assert line.page_number == 2


def test_page_count_matches_the_source() -> None:
    doc = parse_pdf(_pdf_bytes(), "policy.pdf")
    assert len(doc.pages) == 2


def test_blocks_are_emitted_in_reading_order_within_a_page() -> None:
    doc = parse_pdf(_pdf_bytes(), "policy.pdf")
    page_one = [x.content for x in doc.iter_lines() if x.page_number == 1]
    assert page_one.index("Access control policy") < page_one.index(
        "Accounts are reviewed quarterly."
    )


def test_page_with_no_extractable_text_is_flagged_not_failed() -> None:
    doc = fitz.open()
    doc.new_page()
    data = doc.tobytes()
    doc.close()
    parsed = parse_pdf(data, "scan.pdf")
    assert parsed.pages[0].metadata["text_extractable"] is False
    assert parsed.error is None


def test_corrupt_pdf_returns_an_error_document_rather_than_raising() -> None:
    parsed = parse_pdf(b"not a pdf at all", "broken.pdf")
    assert not parsed.success
    assert parsed.error is not None


def test_dispatch_routes_pdf() -> None:
    parsed = dispatch(_pdf_bytes(), "policy.pdf", "application/pdf")
    assert parsed.parser_name == "pdf"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_prep_parsers_pdf.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.prep.parsers.pdf'`.

- [ ] **Step 3: Write the PDF parser**

Create `src/ccf/prep/parsers/pdf.py`:

```python
"""PDF parser built on PyMuPDF.

Page number is the citation that matters for a PDF — an assessor checking a
finding turns to a page, not a byte offset. Text is extracted per block in
PyMuPDF's reading order and each block becomes one line record carrying its page.

A page with no extractable text is a scanned image. This slice has no OCR (see
the design spec), so such a page is flagged ``text_extractable = False`` rather
than raising: the gap belongs in the data where it can be reported, not hidden
behind a failed run.
"""

from __future__ import annotations

import logging
from typing import Any

import fitz

from .base import ParsedBlock, ParsedDocument, ParsedPage

log = logging.getLogger(__name__)

PARSER_NAME = "pdf"
MEDIA_TYPE = "application/pdf"

#: Index of the text payload in PyMuPDF's ``get_text("blocks")`` tuples
#: (x0, y0, x1, y1, text, block_no, block_type).
_BLOCK_TEXT = 4
_BLOCK_NO = 5


def parse_pdf(data: bytes, filename: str, media_type: str = MEDIA_TYPE) -> ParsedDocument:
    """Parse a PDF into one page per source page of text blocks."""
    try:
        document = fitz.open(stream=data, filetype="pdf")
    except Exception as exc:  # noqa: BLE001 — a malformed file must not kill the run
        log.warning("prep.parse.pdf_failed", extra={"filename": filename, "error": str(exc)})
        return ParsedDocument(
            filename=filename, media_type=media_type, parser_name=PARSER_NAME,
            error=f"could not open PDF: {exc}",
        )

    pages: list[ParsedPage] = []
    try:
        for page_index, page in enumerate(document, start=1):
            blocks: list[ParsedBlock] = []
            for raw in sorted(page.get_text("blocks"), key=lambda b: (b[1], b[0])):
                text = str(raw[_BLOCK_TEXT]).strip()
                if not text:
                    continue
                blocks.append(
                    ParsedBlock(
                        block_id=f"p{page_index}b{raw[_BLOCK_NO]}",
                        block_type="paragraph",
                        text=text,
                    )
                )
            metadata: dict[str, Any] = {"text_extractable": bool(blocks)}
            if not blocks:
                log.info(
                    "prep.parse.pdf_page_not_extractable",
                    extra={"filename": filename, "page": page_index},
                )
            pages.append(
                ParsedPage(page_number=page_index, blocks=blocks, metadata=metadata)
            )
    finally:
        document.close()

    return ParsedDocument(
        filename=filename, media_type=media_type, parser_name=PARSER_NAME, pages=pages
    )
```

Note: `ParsedDocument.success` requires at least one block, so an all-scanned PDF reports `success is False` with `error is None` — distinguishable from a parse failure, which sets `error`.

- [ ] **Step 4: Register PDF in the dispatcher**

In `src/ccf/prep/parsers/dispatcher.py`, add:

```python
from .pdf import MEDIA_TYPE as PDF_MEDIA_TYPE
from .pdf import parse_pdf
```

and inside `dispatch`, before the final `raise`:

```python
    if resolved == PDF_MEDIA_TYPE:
        return parse_pdf(data, filename, resolved)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_prep_parsers_pdf.py -v`
Expected: PASS (6 tests)

- [ ] **Step 6: Verify lint and types**

Run: `ruff check . && mypy src`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add src/ccf/prep/parsers/pdf.py src/ccf/prep/parsers/dispatcher.py \
        tests/test_prep_parsers_pdf.py
git commit -m "feat(prep): add PDF parser with page fidelity and scanned-page flag"
```

---

### Task 7: PPTX parser

Slide decks carry architecture briefings and control walkthroughs. Slide number is the citation; the title placeholder is the section.

**Files:**
- Create: `src/ccf/prep/parsers/pptx.py`
- Modify: `src/ccf/prep/parsers/dispatcher.py`
- Create: `tests/test_prep_parsers_pptx.py`

**Interfaces:**
- Consumes: `ParsedBlock`, `ParsedDocument`, `ParsedPage` from Task 3.
- Produces: `parse_pptx(data: bytes, filename: str, media_type: str = ...) -> ParsedDocument`, `PARSER_NAME = "pptx"`. One `ParsedPage` per slide, `section_title` from the title placeholder, `block_type="slide_text"`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_prep_parsers_pptx.py`:

```python
"""PPTX parser — slide numbering and title-derived sections."""

from __future__ import annotations

import io

from pptx import Presentation
from pptx.util import Inches

from ccf.prep.parsers import dispatch
from ccf.prep.parsers.pptx import parse_pptx


def _pptx_bytes() -> bytes:
    prs = Presentation()
    slide = prs.slides.add_slide(prs.slide_layouts[1])
    slide.shapes.title.text = "Access Control Architecture"
    slide.placeholders[1].text = "All administrative access requires MFA."
    slide2 = prs.slides.add_slide(prs.slide_layouts[5])
    slide2.shapes.title.text = "Audit Pipeline"
    box = slide2.shapes.add_textbox(Inches(1), Inches(2), Inches(4), Inches(1))
    box.text_frame.text = "Logs ship to the SIEM within five minutes."
    buf = io.BytesIO()
    prs.save(buf)
    return buf.getvalue()


def test_body_text_carries_its_slide_number() -> None:
    doc = parse_pptx(_pptx_bytes(), "brief.pptx")
    line = next(x for x in doc.iter_lines() if "SIEM" in x.content)
    assert line.page_number == 2


def test_slide_title_becomes_the_section_path() -> None:
    doc = parse_pptx(_pptx_bytes(), "brief.pptx")
    line = next(x for x in doc.iter_lines() if "MFA" in x.content)
    assert line.section_path == "Access Control Architecture"


def test_section_title_is_recorded_on_the_page() -> None:
    doc = parse_pptx(_pptx_bytes(), "brief.pptx")
    assert [p.section_title for p in doc.pages] == [
        "Access Control Architecture",
        "Audit Pipeline",
    ]


def test_block_type_marks_slide_text() -> None:
    doc = parse_pptx(_pptx_bytes(), "brief.pptx")
    assert all(x.block_type == "slide_text" for x in doc.iter_lines())


def test_corrupt_pptx_returns_an_error_document_rather_than_raising() -> None:
    doc = parse_pptx(b"not a pptx", "broken.pptx")
    assert not doc.success
    assert doc.error is not None


def test_dispatch_routes_pptx() -> None:
    doc = dispatch(_pptx_bytes(), "brief.pptx", None)
    assert doc.parser_name == "pptx"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_prep_parsers_pptx.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.prep.parsers.pptx'`.

- [ ] **Step 3: Write the PPTX parser**

Create `src/ccf/prep/parsers/pptx.py`:

```python
"""Slide deck parser.

Slide number is the citation an assessor can act on, and the title placeholder is
the only reliable section label a deck offers, so it becomes both the page's
``section_title`` and the heading path for every block on that slide. Shapes are
walked in the order python-pptx exposes them; the title shape is emitted first so
a slide reads title-then-body.
"""

from __future__ import annotations

import io
import logging

from pptx import Presentation

from .base import ParsedBlock, ParsedDocument, ParsedPage

log = logging.getLogger(__name__)

PARSER_NAME = "pptx"
MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.presentationml.presentation"


def parse_pptx(data: bytes, filename: str, media_type: str = MEDIA_TYPE) -> ParsedDocument:
    """Parse a .pptx into one page per slide of title-scoped text blocks."""
    try:
        presentation = Presentation(io.BytesIO(data))
    except Exception as exc:  # noqa: BLE001 — a malformed deck must not kill the run
        log.warning("prep.parse.pptx_failed", extra={"filename": filename, "error": str(exc)})
        return ParsedDocument(
            filename=filename, media_type=media_type, parser_name=PARSER_NAME,
            error=f"could not open presentation: {exc}",
        )

    pages: list[ParsedPage] = []
    for slide_number, slide in enumerate(presentation.slides, start=1):
        title_shape = slide.shapes.title
        title = (title_shape.text or "").strip() if title_shape is not None else ""
        heading_path = [title] if title else []

        ordered = (
            [title_shape, *[s for s in slide.shapes if s is not title_shape]]
            if title_shape is not None
            else list(slide.shapes)
        )
        blocks: list[ParsedBlock] = []
        for shape_index, shape in enumerate(ordered):
            if not getattr(shape, "has_text_frame", False):
                continue
            text = (shape.text_frame.text or "").strip()
            if not text:
                continue
            blocks.append(
                ParsedBlock(
                    block_id=f"s{slide_number}shape{shape_index}",
                    block_type="slide_text",
                    text=text,
                    heading_path=list(heading_path),
                )
            )
        pages.append(
            ParsedPage(
                page_number=slide_number, blocks=blocks, section_title=title or None
            )
        )

    return ParsedDocument(
        filename=filename, media_type=media_type, parser_name=PARSER_NAME, pages=pages
    )
```

- [ ] **Step 4: Register PPTX in the dispatcher**

In `src/ccf/prep/parsers/dispatcher.py`, add:

```python
from .pptx import MEDIA_TYPE as PPTX_MEDIA_TYPE
from .pptx import parse_pptx
```

and inside `dispatch`, before the final `raise`:

```python
    if resolved == PPTX_MEDIA_TYPE:
        return parse_pptx(data, filename, resolved)
```

- [ ] **Step 5: Run the full parser suite**

Run: `pytest tests/test_prep_parsers_*.py -v`
Expected: PASS (30 tests across five modules)

- [ ] **Step 6: Verify lint and types**

Run: `ruff check . && mypy src`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add src/ccf/prep/parsers/pptx.py src/ccf/prep/parsers/dispatcher.py \
        tests/test_prep_parsers_pptx.py
git commit -m "feat(prep): add PPTX parser with slide-scoped sections"
```

---

### Task 8: Source resolution and the parse stage

Resolves a polymorphic `(source_kind, source_id)` to bytes and persists parsed lines. This is where the pipeline's resumption contract is established.

**Files:**
- Create: `src/ccf/prep/sources.py`
- Create: `src/ccf/prep/pipeline.py`
- Create: `tests/test_prep_pipeline_parse.py`

**Interfaces:**
- Consumes: `dispatch`, `UnsupportedMediaType` (Task 3); `PrepRun`, `PrepLine`, `PREP_STAGES` (Task 2); `ccf.evidence.storage.get_backend`.
- Produces:
  - `ResolvedSource(data: bytes, filename: str, media_type: str | None, organization_id: int, system_id: int | None)`
  - `SourceMissing` exception
  - `async resolve_source(session: AsyncSession, source_kind: str, source_id: int) -> ResolvedSource`
  - `async create_run(session, *, organization_id: int, source_kind: str, source_id: int) -> PrepRun`
  - `async run_stage_parse(session, run: PrepRun) -> int` — returns lines persisted
  - `async advance(session, run: PrepRun) -> PrepRun` — runs every stage not yet `complete`, in order
  - `next_stage(run: PrepRun) -> str | None`

- [ ] **Step 1: Write the failing test**

Create `tests/test_prep_pipeline_parse.py`:

```python
"""Source resolution and the parse stage, including resumption semantics."""

from __future__ import annotations

import hashlib

import pytest
from sqlalchemy import select

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.evidence import storage
from ccf.models import Organization, Policy, PolicyVersion, System
from ccf.models_evidence import EvidenceObject, EvidenceVersion
from ccf.models_prep import PrepLine, PrepRun
from ccf.prep import pipeline
from ccf.prep.sources import SourceMissing, resolve_source

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(autouse=True)
def _local_evidence_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("CCF_EVIDENCE_BACKEND", "local")
    monkeypatch.setenv("CCF_EVIDENCE_LOCAL_DIR", str(tmp_path / "evidence"))
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return int(org.id)


async def _evidence_version(org_id: int, payload: bytes, filename: str) -> tuple[int, int]:
    """Store bytes through the real backend and return (version_id, system_id)."""
    digest = hashlib.sha256(payload).hexdigest()
    ref = storage.get_backend().put(digest, payload, "text/plain")
    async with session_scope() as s:
        system = System(organization_id=org_id, name="Test System")
        s.add(system)
        await s.flush()
        obj = EvidenceObject(organization_id=org_id, title=filename, system_id=system.id)
        s.add(obj)
        await s.flush()
        ver = EvidenceVersion(
            evidence_object_id=obj.id, version=1, sha256=digest, media_type="text/plain",
            size_bytes=len(payload), filename=filename, storage_backend="local", storage_ref=ref,
        )
        s.add(ver)
        await s.flush()
        return int(ver.id), int(system.id)


async def test_resolve_evidence_version_returns_bytes_and_system() -> None:
    org_id = await _org("prep-src-ev")
    version_id, system_id = await _evidence_version(org_id, b"MFA is required.", "p.txt")
    async with session_scope() as s:
        resolved = await resolve_source(s, "evidence_version", version_id)
    assert resolved.data == b"MFA is required."
    assert resolved.organization_id == org_id
    assert resolved.system_id == system_id
    assert resolved.filename == "p.txt"


async def test_resolve_policy_version_uses_inline_body() -> None:
    org_id = await _org("prep-src-pol")
    async with session_scope() as s:
        policy = Policy(organization_id=org_id, name="Access Control Policy")
        s.add(policy)
        await s.flush()
        ver = PolicyVersion(policy_id=policy.id, version="1.0", body="Accounts are reviewed.")
        s.add(ver)
        await s.flush()
        version_id = int(ver.id)
    async with session_scope() as s:
        resolved = await resolve_source(s, "policy_version", version_id)
    assert b"Accounts are reviewed." in resolved.data
    assert resolved.organization_id == org_id
    assert resolved.system_id is None


async def test_resolve_raises_source_missing_for_a_deleted_source() -> None:
    async with session_scope() as s:
        with pytest.raises(SourceMissing):
            await resolve_source(s, "evidence_version", 999_999)


async def test_parse_stage_persists_lines_and_marks_stage_complete() -> None:
    org_id = await _org("prep-parse")
    version_id, _ = await _evidence_version(org_id, b"One.\nTwo.\n", "p.txt")
    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="evidence_version", source_id=version_id
        )
        count = await pipeline.run_stage_parse(s, run)
        assert count == 2
        assert run.stage_parse == "complete"
        assert run.lines_parsed == 2
        assert run.parser_name == "text"
        lines = (
            await s.execute(select(PrepLine).where(PrepLine.run_id == run.id))
        ).scalars().all()
        assert sorted(x.content for x in lines) == ["One.", "Two."]
        assert all(x.organization_id == org_id for x in lines)


async def test_unsupported_media_type_marks_the_run_unsupported_not_failed() -> None:
    org_id = await _org("prep-unsupported")
    version_id, _ = await _evidence_version(org_id, b"\x00\x01", "diagram.vsdx")
    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="evidence_version", source_id=version_id
        )
        await pipeline.run_stage_parse(s, run)
        assert run.status == "unsupported"
        assert run.stage_parse == "skipped"
        assert run.error_stage is None


async def test_reparsing_replaces_prior_lines_rather_than_duplicating() -> None:
    """Re-running a stage must be idempotent — a resumed run cannot double-write."""
    org_id = await _org("prep-reparse")
    version_id, _ = await _evidence_version(org_id, b"One.\nTwo.\n", "p.txt")
    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="evidence_version", source_id=version_id
        )
        await pipeline.run_stage_parse(s, run)
        await pipeline.run_stage_parse(s, run)
        lines = (
            await s.execute(select(PrepLine).where(PrepLine.run_id == run.id))
        ).scalars().all()
        assert len(lines) == 2


async def test_next_stage_reports_the_first_incomplete_stage() -> None:
    org_id = await _org("prep-next")
    async with session_scope() as s:
        run = PrepRun(organization_id=org_id, source_kind="evidence_version", source_id=1)
        s.add(run)
        await s.flush()
        assert pipeline.next_stage(run) == "parse"
        run.stage_parse = "complete"
        assert pipeline.next_stage(run) == "screen"
        for stage in ("screen", "expand", "classify", "embed"):
            setattr(run, f"stage_{stage}", "complete")
        assert pipeline.next_stage(run) is None


async def test_config_snapshot_records_the_thresholds_in_force() -> None:
    org_id = await _org("prep-snapshot")
    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="evidence_version", source_id=1
        )
        assert run.config_snapshot["screen_threshold"] == get_settings().prep_screen_threshold
        assert run.config_snapshot["expand_window"] == get_settings().prep_expand_window
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_prep_pipeline_parse.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.prep.sources'`.

- [ ] **Step 3: Write source resolution**

Create `src/ccf/prep/sources.py`:

```python
"""Resolve a polymorphic prep source to bytes.

A run addresses its source as ``(source_kind, source_id)`` rather than through a
new document table, so the same pipeline prepares system evidence and enterprise
policy without either library learning about the other. Evidence bytes come from
the configured storage backend; policy versions may carry inline ``body`` text or
a ``uri``, and inline text is preferred because it needs no network.

Deletion is expected, not exceptional: an ``EvidenceVersion`` can be removed
after a run is queued, so :class:`SourceMissing` is raised for the pipeline to
close the run as ``orphaned``.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..evidence.storage import get_backend
from ..models import Policy, PolicyVersion
from ..models_evidence import EvidenceObject, EvidenceVersion
from ..models_prep import PREP_SOURCE_KINDS


class SourceMissing(LookupError):
    """The referenced source row or its content no longer exists."""


@dataclass(slots=True)
class ResolvedSource:
    """Bytes plus the tenancy context a run needs to write org-scoped rows."""

    data: bytes
    filename: str
    media_type: str | None
    organization_id: int
    system_id: int | None


async def _resolve_evidence_version(session: AsyncSession, source_id: int) -> ResolvedSource:
    row = (
        await session.execute(
            select(EvidenceVersion, EvidenceObject)
            .join(EvidenceObject, EvidenceObject.id == EvidenceVersion.evidence_object_id)
            .where(EvidenceVersion.id == source_id)
        )
    ).first()
    if row is None:
        raise SourceMissing(f"evidence_version {source_id} not found")
    version, obj = row
    if obj.organization_id is None:
        raise SourceMissing(f"evidence_version {source_id} has no organization")
    data = get_backend().get(version.storage_ref)
    if data is None:
        raise SourceMissing(f"evidence_version {source_id} content missing from storage")
    return ResolvedSource(
        data=data,
        filename=version.filename or f"evidence-{source_id}",
        media_type=version.media_type,
        organization_id=int(obj.organization_id),
        system_id=int(obj.system_id) if obj.system_id is not None else None,
    )


async def _resolve_policy_version(session: AsyncSession, source_id: int) -> ResolvedSource:
    row = (
        await session.execute(
            select(PolicyVersion, Policy)
            .join(Policy, Policy.id == PolicyVersion.policy_id)
            .where(PolicyVersion.id == source_id)
        )
    ).first()
    if row is None:
        raise SourceMissing(f"policy_version {source_id} not found")
    version, policy = row
    if policy.organization_id is None:
        raise SourceMissing(f"policy_version {source_id} has no organization")
    if not version.body:
        # A URI-only policy points at a document Concord does not hold. Fetching
        # it is a connector concern, not a parser one.
        raise SourceMissing(
            f"policy_version {source_id} has no inline body (uri-only sources are not preparable)"
        )
    return ResolvedSource(
        data=version.body.encode("utf-8"),
        filename=f"{policy.name}-{version.version}.txt",
        media_type="text/plain",
        organization_id=int(policy.organization_id),
        system_id=None,
    )


async def resolve_source(
    session: AsyncSession, source_kind: str, source_id: int
) -> ResolvedSource:
    """Load the bytes and tenancy context for one prep source."""
    if source_kind not in PREP_SOURCE_KINDS:
        raise SourceMissing(f"unknown source kind '{source_kind}'")
    if source_kind == "evidence_version":
        return await _resolve_evidence_version(session, source_id)
    return await _resolve_policy_version(session, source_id)
```

- [ ] **Step 4: Write the pipeline orchestrator and parse stage**

Create `src/ccf/prep/pipeline.py`:

```python
"""Stage orchestration for the evidence preparation pipeline.

Stages run in :data:`PREP_STAGES` order and each persists its full output before
the next begins, so a failure is recoverable: :func:`next_stage` returns the
first stage that is not ``complete`` and :func:`advance` restarts there rather
than re-parsing a document that already parsed cleanly.

Every stage is idempotent — it deletes its own prior output before writing — so a
resumed or retried run cannot double-write. That property is what makes retry
safe without a distributed transaction.
"""

from __future__ import annotations

from typing import Any

import structlog
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..models_prep import PREP_STAGES, PrepLine, PrepRun
from .parsers import UnsupportedMediaType, dispatch
from .sources import SourceMissing, resolve_source

log = structlog.get_logger(__name__)


def next_stage(run: PrepRun) -> str | None:
    """Return the first stage that is not ``complete``, or ``None`` if all are."""
    for stage in PREP_STAGES:
        if getattr(run, f"stage_{stage}") not in ("complete", "skipped"):
            return stage
    return None


async def create_run(
    session: AsyncSession, *, organization_id: int, source_kind: str, source_id: int
) -> PrepRun:
    """Open a run, snapshotting the thresholds in force so re-runs are comparable."""
    settings = get_settings()
    snapshot: dict[str, Any] = {
        "screen_threshold": settings.prep_screen_threshold,
        "expand_window": settings.prep_expand_window,
        "embed_provider": settings.prep_embed_provider,
        "embed_model": settings.prep_embed_model,
        "embed_dimensions": settings.prep_embed_dimensions,
    }
    run = PrepRun(
        organization_id=organization_id,
        source_kind=source_kind,
        source_id=source_id,
        status="pending",
        config_snapshot=snapshot,
    )
    session.add(run)
    await session.flush()
    return run


def _fail(run: PrepRun, stage: str, message: str) -> None:
    run.status = "failed"
    setattr(run, f"stage_{stage}", "failed")
    run.error_stage = stage
    run.error = message
    log.warning("prep.stage_failed", run_id=run.id, stage=stage, error=message)


async def run_stage_parse(session: AsyncSession, run: PrepRun) -> int:
    """Parse the source into ``prep_lines``. Returns the number of lines persisted."""
    run.status = "running"
    run.stage_parse = "running"

    try:
        source = await resolve_source(session, run.source_kind, run.source_id)
    except SourceMissing as exc:
        run.status = "orphaned"
        run.stage_parse = "skipped"
        run.error = str(exc)
        log.info("prep.source_missing", run_id=run.id, reason=str(exc))
        return 0

    run.media_type = source.media_type
    try:
        parsed = dispatch(source.data, source.filename, source.media_type)
    except UnsupportedMediaType as exc:
        # A known coverage gap (image OCR, Visio), not an error: recording it as
        # ``unsupported`` keeps it visible and reportable rather than noise in
        # the failure counts.
        run.status = "unsupported"
        run.stage_parse = "skipped"
        run.error = str(exc)
        log.info("prep.unsupported_media_type", run_id=run.id, reason=str(exc))
        return 0

    if parsed.error is not None:
        _fail(run, "parse", parsed.error)
        return 0

    # Idempotent: clear prior output so a resumed run cannot double-write.
    await session.execute(delete(PrepLine).where(PrepLine.run_id == run.id))

    count = 0
    for record in parsed.iter_lines():
        session.add(
            PrepLine(
                run_id=run.id,
                organization_id=source.organization_id,
                line_number=record.line_number,
                page_number=record.page_number,
                section_path=record.section_path,
                block_id=record.block_id,
                block_type=record.block_type,
                table_id=record.table_id,
                row_index=record.row_index,
                col_index=record.col_index,
                cell_label=record.cell_label,
                content=record.content,
            )
        )
        count += 1

    run.parser_name = parsed.parser_name
    run.lines_parsed = count
    run.stage_parse = "complete"
    await session.flush()
    log.info("prep.parse_complete", run_id=run.id, lines=count, parser=parsed.parser_name)
    return count


async def load_run(session: AsyncSession, run_id: int) -> PrepRun | None:
    return (
        await session.execute(select(PrepRun).where(PrepRun.id == run_id))
    ).scalar_one_or_none()


#: Stage implementations are registered here as later tasks add them, keeping
#: :func:`advance` free of a growing if/elif ladder.
_STAGE_RUNNERS: dict[str, Any] = {"parse": run_stage_parse}


async def advance(session: AsyncSession, run: PrepRun) -> PrepRun:
    """Run every stage not yet complete, in order, stopping on failure."""
    while (stage := next_stage(run)) is not None:
        runner = _STAGE_RUNNERS.get(stage)
        if runner is None:
            # Stage not yet implemented — leave the run resumable rather than
            # marking it complete on work that never ran.
            log.info("prep.stage_not_implemented", run_id=run.id, stage=stage)
            break
        await runner(session, run)
        if run.status in ("failed", "unsupported", "orphaned"):
            return run
    if next_stage(run) is None:
        run.status = "complete"
    await session.flush()
    return run
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_prep_pipeline_parse.py -v`
Expected: PASS (8 tests)

- [ ] **Step 6: Verify lint and types**

Run: `ruff check . && mypy src`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add src/ccf/prep/sources.py src/ccf/prep/pipeline.py \
        tests/test_prep_pipeline_parse.py
git commit -m "feat(prep): add source resolution and the resumable parse stage"
```

---

### Task 9: Catalog-driven screen stage

The cheap gate that makes per-unit LLM reasoning affordable. Ranks every parsed line against `ccf.controls` using the tsvector index the ETL already maintains — no keyword dictionary to write or keep current.

**Files:**
- Create: `src/ccf/prep/screen.py`
- Modify: `src/ccf/prep/pipeline.py` (register the stage)
- Create: `tests/test_prep_screen.py`

**Interfaces:**
- Consumes: `PrepLine`, `PrepScreen`, `PrepRun` (Task 2); `Control` from `ccf.models`.
- Produces:
  - `async score_line(session, *, content: str, limit: int = 5) -> list[tuple[str, float]]` — `(control identifier, rank)` best-first
  - `async run_stage_screen(session, run: PrepRun) -> int` — returns count above threshold

- [ ] **Step 1: Write the failing test**

Create `tests/test_prep_screen.py`:

```python
"""Catalog-driven relevance screening against ccf.controls."""

from __future__ import annotations

import pytest
from sqlalchemy import select, text

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Control, Organization
from ccf.models_prep import PrepLine, PrepRun, PrepScreen
from ccf.prep import pipeline
from ccf.prep.screen import run_stage_screen, score_line

pytestmark = pytest.mark.usefixtures("fresh_engine")


async def _seed_controls() -> int:
    """Seed two catalog controls and refresh the tsvector the screen relies on."""
    async with session_scope() as s:
        s.add(
            Control(
                identifier="IA-2",
                control_name="Identification and Authentication (Organizational Users)",
                description=(
                    "Uniquely identify and authenticate organizational users and associate "
                    "that unique identification with processes acting on behalf of those users."
                ),
                assessment_objective="multifactor authentication is implemented for network access",
            )
        )
        s.add(
            Control(
                identifier="CP-9",
                control_name="System Backup",
                description=(
                    "Conduct backups of user-level information and system-level information "
                    "contained in the system."
                ),
                assessment_objective="backups of system documentation are conducted",
            )
        )
        await s.flush()
        await s.execute(
            text(
                "UPDATE ccf.controls SET search_vector = "
                "to_tsvector('english', coalesce(control_name,'') || ' ' || "
                "coalesce(description,'') || ' ' || coalesce(assessment_objective,''))"
            )
        )
        org = Organization(name="screen-org")
        s.add(org)
        await s.flush()
        return int(org.id)


async def test_score_line_ranks_the_right_control_first() -> None:
    await _seed_controls()
    async with session_scope() as s:
        ranked = await score_line(s, content="All administrators must use multifactor authentication.")
    assert ranked, "expected at least one candidate control"
    assert ranked[0][0] == "IA-2"
    assert ranked[0][1] > 0


async def test_score_line_distinguishes_unrelated_subject_matter() -> None:
    await _seed_controls()
    async with session_scope() as s:
        ranked = await score_line(s, content="Nightly backups are written to offsite storage.")
    assert ranked[0][0] == "CP-9"


async def test_score_line_returns_empty_for_text_with_no_catalog_signal() -> None:
    await _seed_controls()
    async with session_scope() as s:
        ranked = await score_line(s, content="The quick brown fox jumped.")
    assert ranked == []


async def test_screen_stage_flags_relevant_lines_above_threshold() -> None:
    org_id = await _seed_controls()
    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        run.stage_parse = "complete"
        s.add(PrepLine(run_id=run.id, organization_id=org_id, line_number=1,
                       content="Administrators must use multifactor authentication."))
        s.add(PrepLine(run_id=run.id, organization_id=org_id, line_number=2,
                       content="The quick brown fox jumped."))
        await s.flush()

        above = await run_stage_screen(s, run)
        assert above == 1
        assert run.stage_screen == "complete"
        assert run.lines_above_threshold == 1

        screens = (
            await s.execute(
                select(PrepScreen, PrepLine)
                .join(PrepLine, PrepLine.id == PrepScreen.line_id)
                .where(PrepScreen.run_id == run.id)
                .order_by(PrepLine.line_number)
            )
        ).all()
        assert [x.PrepScreen.above_threshold for x in screens] == [True, False]
        assert "IA-2" in screens[0].PrepScreen.candidate_controls
        assert screens[0].PrepScreen.method == "catalog_fts"


async def test_screen_stage_is_idempotent_on_rerun() -> None:
    org_id = await _seed_controls()
    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        run.stage_parse = "complete"
        s.add(PrepLine(run_id=run.id, organization_id=org_id, line_number=1,
                       content="Multifactor authentication is required."))
        await s.flush()
        await run_stage_screen(s, run)
        await run_stage_screen(s, run)
        rows = (
            await s.execute(select(PrepScreen).where(PrepScreen.run_id == run.id))
        ).scalars().all()
        assert len(rows) == 1


async def test_threshold_is_read_from_the_run_snapshot_not_live_settings() -> None:
    """A settings change mid-flight must not silently reinterpret an open run."""
    org_id = await _seed_controls()
    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        run.stage_parse = "complete"
        run.config_snapshot = {**run.config_snapshot, "screen_threshold": 99.0}
        s.add(PrepLine(run_id=run.id, organization_id=org_id, line_number=1,
                       content="Multifactor authentication is required."))
        await s.flush()
        above = await run_stage_screen(s, run)
    assert above == 0, "an impossibly high snapshot threshold must gate everything out"
    assert get_settings().prep_screen_threshold < 99.0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_prep_screen.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.prep.screen'`.

- [ ] **Step 3: Write the screen stage**

Create `src/ccf/prep/screen.py`:

```python
"""First-pass relevance screening against Concord's own 800-53A catalog.

The pipeline cannot afford to reason over every line of every document, so a
cheap gate decides what reaches the model. Concord's ETL already loads the full
catalog into ``ccf.controls`` with a GIN-indexed ``search_vector`` covering the
control name, description and assessment objective — so screening is a ranked
full-text join against data the platform already owns. There is no keyword
dictionary to write, and the screen tracks catalog updates automatically on the
next workbook ingest.

Screening is deliberately inclusive. A false positive costs one classification
call and is corrected downstream; a false negative silently removes evidence from
every assessment that would have cited it. The threshold lives in the run's
``config_snapshot`` rather than live settings, so changing the default cannot
retroactively reinterpret a run already in flight.
"""

from __future__ import annotations

import structlog
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Control
from ..models_prep import PrepLine, PrepRun, PrepScreen

log = structlog.get_logger(__name__)

#: Candidate controls recorded per line. Enough to give the classifier real
#: choice without turning the prompt into a catalog dump.
_MAX_CANDIDATES = 5

#: Lines shorter than this carry no usable signal ("Yes", "N/A", a page number)
#: and would otherwise match noisily against short control names.
_MIN_CONTENT_CHARS = 12


async def score_line(
    session: AsyncSession, *, content: str, limit: int = _MAX_CANDIDATES
) -> list[tuple[str, float]]:
    """Rank catalog controls against one line, best first."""
    if len(content.strip()) < _MIN_CONTENT_CHARS:
        return []
    query = func.websearch_to_tsquery("english", content)
    rank = func.ts_rank(Control.search_vector, query)
    rows = (
        await session.execute(
            select(Control.identifier, rank.label("rank"))
            .where(Control.search_vector.op("@@")(query))
            .order_by(rank.desc())
            .limit(limit)
        )
    ).all()
    return [(str(identifier), float(value)) for identifier, value in rows]


async def run_stage_screen(session: AsyncSession, run: PrepRun) -> int:
    """Screen every parsed line. Returns the count above threshold."""
    run.stage_screen = "running"
    threshold = float(run.config_snapshot.get("screen_threshold", 0.0))

    # Idempotent: clear prior output so a resumed run cannot double-write.
    await session.execute(delete(PrepScreen).where(PrepScreen.run_id == run.id))

    lines = (
        await session.execute(
            select(PrepLine).where(PrepLine.run_id == run.id).order_by(PrepLine.line_number)
        )
    ).scalars().all()

    above = 0
    for line in lines:
        ranked = await score_line(session, content=line.content)
        score = ranked[0][1] if ranked else 0.0
        is_above = bool(ranked) and score >= threshold
        above += int(is_above)
        session.add(
            PrepScreen(
                line_id=line.id,
                run_id=run.id,
                organization_id=run.organization_id,
                relevance_score=score,
                candidate_controls=[identifier for identifier, _ in ranked],
                above_threshold=is_above,
                method="catalog_fts",
            )
        )

    run.lines_above_threshold = above
    run.stage_screen = "complete"
    await session.flush()
    log.info(
        "prep.screen_complete",
        run_id=run.id, lines=len(lines), above_threshold=above, threshold=threshold,
    )
    return above
```

- [ ] **Step 4: Register the stage**

In `src/ccf/prep/pipeline.py`, add the import at the top:

```python
from .screen import run_stage_screen
```

and extend the registry:

```python
_STAGE_RUNNERS: dict[str, Any] = {
    "parse": run_stage_parse,
    "screen": run_stage_screen,
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_prep_screen.py tests/test_prep_pipeline_parse.py -v`
Expected: PASS (14 tests)

- [ ] **Step 6: Verify lint and types**

Run: `ruff check . && mypy src`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add src/ccf/prep/screen.py src/ccf/prep/pipeline.py tests/test_prep_screen.py
git commit -m "feat(prep): screen lines against the 800-53A catalog via ts_rank"
```

---

### Task 10: Context expansion stage

A trigger line alone is rarely assessable — "Quarterly" means nothing without its column header, and a procedure step means nothing without the steps around it. This stage builds semantically complete units.

**Files:**
- Create: `src/ccf/prep/expand.py`
- Modify: `src/ccf/prep/pipeline.py`
- Create: `tests/test_prep_expand.py`

**Interfaces:**
- Consumes: `PrepLine`, `PrepScreen`, `PrepUnit`, `PrepRun` (Task 2).
- Produces:
  - `ExpansionResult(trigger_line_id: int, source_line_ids: list[int], content: str, page_numbers: list[int], section_path: str | None, table_coordinates: dict[str, Any] | None, token_count: int, strategy: str)`
  - `expand_line(trigger: PrepLine, siblings: list[PrepLine], *, window: int) -> ExpansionResult`
  - `async run_stage_expand(session, run: PrepRun) -> int`

- [ ] **Step 1: Write the failing test**

Create `tests/test_prep_expand.py`:

```python
"""Context expansion — block, table row, section, and window strategies."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from ccf.db import session_scope
from ccf.models import Organization
from ccf.models_prep import PrepLine, PrepScreen, PrepUnit
from ccf.prep import pipeline
from ccf.prep.expand import expand_line, run_stage_expand

pytestmark = pytest.mark.usefixtures("fresh_engine")


def _line(**kw: object) -> PrepLine:
    base: dict[str, object] = {"run_id": 1, "organization_id": 1, "content": "x"}
    line = PrepLine(**{**base, **kw})
    line.id = int(kw.get("line_number", 1))  # type: ignore[arg-type]
    return line


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return int(org.id)


def test_table_cell_expands_to_its_row_with_headers_inherited() -> None:
    siblings = [
        _line(line_number=1, content="Activity", table_id="t1", row_index=0, col_index=0,
              block_type="table_cell"),
        _line(line_number=2, content="Review Frequency", table_id="t1", row_index=0,
              col_index=1, block_type="table_cell"),
        _line(line_number=3, content="Privileged account review", table_id="t1", row_index=1,
              col_index=0, block_type="table_cell", cell_label="Activity"),
        _line(line_number=4, content="Quarterly", table_id="t1", row_index=1, col_index=1,
              block_type="table_cell", cell_label="Review Frequency"),
    ]
    result = expand_line(siblings[3], siblings, window=4)
    assert result.strategy == "table_row"
    # Both cells in the row, each labelled by its column header.
    assert "Activity: Privileged account review" in result.content
    assert "Review Frequency: Quarterly" in result.content
    assert sorted(result.source_line_ids) == [3, 4]
    assert result.table_coordinates == {"table_id": "t1", "row_index": 1, "col_index": 1}


def test_paragraph_expands_to_a_bounded_window_within_its_section() -> None:
    siblings = [
        _line(line_number=n, content=f"Sentence {n}.", section_path="AC > Accounts",
              block_type="paragraph")
        for n in range(1, 8)
    ]
    result = expand_line(siblings[3], siblings, window=2)
    assert result.strategy == "window"
    assert sorted(result.source_line_ids) == [2, 3, 4, 5, 6]
    assert "Sentence 4." in result.content


def test_window_does_not_cross_a_section_boundary() -> None:
    siblings = [
        _line(line_number=1, content="Access text.", section_path="AC", block_type="paragraph"),
        _line(line_number=2, content="Trigger text.", section_path="AC", block_type="paragraph"),
        _line(line_number=3, content="Audit text.", section_path="AU", block_type="paragraph"),
    ]
    result = expand_line(siblings[1], siblings, window=3)
    assert 3 not in result.source_line_ids


def test_window_does_not_cross_a_page_boundary() -> None:
    siblings = [
        _line(line_number=1, content="Page one text.", page_number=1, block_type="paragraph"),
        _line(line_number=2, content="Trigger text.", page_number=1, block_type="paragraph"),
        _line(line_number=3, content="Page two text.", page_number=2, block_type="paragraph"),
    ]
    result = expand_line(siblings[1], siblings, window=3)
    assert 3 not in result.source_line_ids
    assert result.page_numbers == [1]


def test_isolated_line_falls_back_to_itself() -> None:
    only = _line(line_number=1, content="Standalone statement.", block_type="paragraph")
    result = expand_line(only, [only], window=4)
    assert result.strategy == "line"
    assert result.source_line_ids == [1]


def test_token_count_is_estimated_and_positive() -> None:
    only = _line(line_number=1, content="A statement worth about ten tokens here.",
                 block_type="paragraph")
    assert expand_line(only, [only], window=4).token_count > 0


async def test_expand_stage_builds_units_only_for_lines_above_threshold() -> None:
    org_id = await _org("prep-expand")
    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        run.stage_parse = "complete"
        run.stage_screen = "complete"
        keep = PrepLine(run_id=run.id, organization_id=org_id, line_number=1,
                        content="Multifactor authentication is required for admins.",
                        block_type="paragraph")
        drop = PrepLine(run_id=run.id, organization_id=org_id, line_number=2,
                        content="The quick brown fox jumped.", block_type="paragraph")
        s.add_all([keep, drop])
        await s.flush()
        s.add(PrepScreen(line_id=keep.id, run_id=run.id, organization_id=org_id,
                         relevance_score=0.9, candidate_controls=["IA-2"], above_threshold=True))
        s.add(PrepScreen(line_id=drop.id, run_id=run.id, organization_id=org_id,
                         relevance_score=0.0, candidate_controls=[], above_threshold=False))
        await s.flush()

        built = await run_stage_expand(s, run)
        assert built == 1
        assert run.units_built == 1
        assert run.stage_expand == "complete"
        units = (
            await s.execute(select(PrepUnit).where(PrepUnit.run_id == run.id))
        ).scalars().all()
        assert len(units) == 1
        assert units[0].trigger_line_id == keep.id
        assert units[0].source_kind == "policy_version"


async def test_expand_stage_populates_the_search_vector_via_trigger() -> None:
    """The tsvector must be maintained by the DB trigger, not application code."""
    org_id = await _org("prep-expand-tsv")
    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        run.stage_parse = run.stage_screen = "complete"
        line = PrepLine(run_id=run.id, organization_id=org_id, line_number=1,
                        content="Backups are written to offsite storage nightly.",
                        block_type="paragraph")
        s.add(line)
        await s.flush()
        s.add(PrepScreen(line_id=line.id, run_id=run.id, organization_id=org_id,
                         relevance_score=0.5, candidate_controls=["CP-9"], above_threshold=True))
        await s.flush()
        await run_stage_expand(s, run)
        unit = (
            await s.execute(select(PrepUnit).where(PrepUnit.run_id == run.id))
        ).scalar_one()
        await s.refresh(unit)
        assert unit.search_vector is not None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_prep_expand.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.prep.expand'`.

- [ ] **Step 3: Write the expansion stage**

Create `src/ccf/prep/expand.py`:

```python
"""Context expansion — turning a trigger line into an assessable passage.

A screened line is a pointer, not evidence. "Quarterly" is meaningless without
the column header above it; a procedure step is meaningless without the steps
around it. This stage grows each trigger line into the smallest passage that
stands on its own, preferring the tightest bound that still carries meaning:

1. the same table row, with every cell labelled by its column header
2. a bounded window of neighbouring lines within the same page and section
3. the trigger line alone

Windows never cross a page or section boundary. Splicing text from two sections
into one unit would produce a citation that points at a passage no reader can
find, which is worse than a narrower unit.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import structlog
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models_prep import PrepLine, PrepRun, PrepScreen, PrepUnit

log = structlog.get_logger(__name__)

#: Rough token estimate. Exact tokenisation would need the target model's
#: tokeniser; this is only used to bound prompt size, so an approximation is fine.
_CHARS_PER_TOKEN = 4


@dataclass(slots=True)
class ExpansionResult:
    """One expanded passage plus the provenance needed to cite it."""

    trigger_line_id: int
    source_line_ids: list[int]
    content: str
    page_numbers: list[int]
    section_path: str | None
    table_coordinates: dict[str, Any] | None
    token_count: int
    strategy: str


def _estimate_tokens(text: str) -> int:
    return max(1, len(text) // _CHARS_PER_TOKEN)


def _render_cell(line: PrepLine) -> str:
    """Label a cell with its column header, which is what makes it legible."""
    return f"{line.cell_label}: {line.content}" if line.cell_label else line.content


def _build(
    trigger: PrepLine, members: list[PrepLine], strategy: str, content: str
) -> ExpansionResult:
    pages = sorted({m.page_number for m in members if m.page_number is not None})
    coordinates = (
        {
            "table_id": trigger.table_id,
            "row_index": trigger.row_index,
            "col_index": trigger.col_index,
        }
        if trigger.table_id is not None
        else None
    )
    return ExpansionResult(
        trigger_line_id=trigger.id,
        source_line_ids=[m.id for m in members],
        content=content,
        page_numbers=pages,
        section_path=trigger.section_path,
        table_coordinates=coordinates,
        token_count=_estimate_tokens(content),
        strategy=strategy,
    )


def expand_line(trigger: PrepLine, siblings: list[PrepLine], *, window: int) -> ExpansionResult:
    """Grow ``trigger`` into the tightest passage that still stands alone."""
    if trigger.table_id is not None and trigger.row_index is not None:
        row = [
            line
            for line in siblings
            if line.table_id == trigger.table_id and line.row_index == trigger.row_index
        ]
        if len(row) > 1:
            row.sort(key=lambda line: (line.col_index if line.col_index is not None else 0))
            return _build(trigger, row, "table_row", " | ".join(_render_cell(x) for x in row))

    ordered = sorted(siblings, key=lambda line: line.line_number)
    try:
        position = next(
            index for index, line in enumerate(ordered) if line.id == trigger.id
        )
    except StopIteration:  # pragma: no cover — trigger is always among its siblings
        return _build(trigger, [trigger], "line", trigger.content)

    neighbours = ordered[max(0, position - window) : position + window + 1]
    members = [
        line
        for line in neighbours
        if line.page_number == trigger.page_number
        and line.section_path == trigger.section_path
    ]
    if len(members) > 1:
        return _build(trigger, members, "window", " ".join(x.content for x in members))

    return _build(trigger, [trigger], "line", trigger.content)


async def run_stage_expand(session: AsyncSession, run: PrepRun) -> int:
    """Build a unit for every above-threshold line. Returns the count built."""
    run.stage_expand = "running"

    # Idempotent: clear prior output so a resumed run cannot double-write.
    await session.execute(delete(PrepUnit).where(PrepUnit.run_id == run.id))

    all_lines = (
        await session.execute(
            select(PrepLine).where(PrepLine.run_id == run.id).order_by(PrepLine.line_number)
        )
    ).scalars().all()
    triggers = (
        await session.execute(
            select(PrepLine)
            .join(PrepScreen, PrepScreen.line_id == PrepLine.id)
            .where(PrepScreen.run_id == run.id, PrepScreen.above_threshold.is_(True))
            .order_by(PrepLine.line_number)
        )
    ).scalars().all()

    window = int(run.config_snapshot.get("expand_window", 4))
    system_id = await _system_id_for(session, run)

    built = 0
    for trigger in triggers:
        result = expand_line(trigger, list(all_lines), window=window)
        session.add(
            PrepUnit(
                run_id=run.id,
                organization_id=run.organization_id,
                trigger_line_id=result.trigger_line_id,
                source_line_ids=result.source_line_ids,
                content=result.content,
                page_numbers=result.page_numbers,
                section_path=result.section_path,
                table_coordinates=result.table_coordinates,
                token_count=result.token_count,
                system_id=system_id,
                source_kind=run.source_kind,
            )
        )
        built += 1

    run.units_built = built
    run.stage_expand = "complete"
    await session.flush()
    log.info("prep.expand_complete", run_id=run.id, units=built, window=window)
    return built


async def _system_id_for(session: AsyncSession, run: PrepRun) -> int | None:
    """Denormalise the owning system onto units so retrieval filters without a join."""
    if run.source_kind != "evidence_version":
        return None
    from .sources import SourceMissing, resolve_source  # noqa: PLC0415 — avoids a cycle

    try:
        return (await resolve_source(session, run.source_kind, run.source_id)).system_id
    except SourceMissing:
        return None
```

- [ ] **Step 4: Register the stage**

In `src/ccf/prep/pipeline.py`, add the import:

```python
from .expand import run_stage_expand
```

and extend the registry:

```python
_STAGE_RUNNERS: dict[str, Any] = {
    "parse": run_stage_parse,
    "screen": run_stage_screen,
    "expand": run_stage_expand,
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_prep_expand.py -v`
Expected: PASS (8 tests)

- [ ] **Step 6: Verify lint and types**

Run: `ruff check . && mypy src`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add src/ccf/prep/expand.py src/ccf/prep/pipeline.py tests/test_prep_expand.py
git commit -m "feat(prep): expand screened lines into assessable units"
```

---

### Task 11: Provider embedding support

Extends the existing AI gateway with embeddings. Anthropic has no embeddings endpoint, so this cannot be a required abstract method — the base class raises and OpenAI overrides.

**Files:**
- Modify: `src/ccf/ai/providers/base.py`
- Modify: `src/ccf/ai/providers/openai.py`
- Modify: `src/ccf/ai/providers/__init__.py`
- Modify: `src/ccf/ai/gateway.py`
- Create: `tests/test_prep_embed_provider.py`

**Interfaces:**
- Consumes: `AIProvider`, `ProviderError`, `build_provider`, `gateway.resolve` (existing).
- Produces:
  - `EmbedRequest(texts: list[str], model: str)`, `EmbedResponse(vectors: list[list[float]], model: str, input_tokens: int)` in `providers/base.py`
  - `AIProvider.supports_embeddings: bool = False` and `async AIProvider.embed(request: EmbedRequest) -> EmbedResponse` raising `ProviderError` by default
  - `OpenAIProvider.supports_embeddings = True` with a working `embed`
  - `async gateway.embed(session, org_id, *, texts: list[str], purpose: str, provider: str | None = None, model: str | None = None, actor: str | None = None) -> EmbedResponse`

- [ ] **Step 1: Write the failing test**

Create `tests/test_prep_embed_provider.py`:

```python
"""Embedding support on the provider interface and the org-scoped gateway."""

from __future__ import annotations

import pytest

from ccf.ai import gateway
from ccf.ai.providers import build_provider
from ccf.ai.providers.base import AIProvider, EmbedRequest, EmbedResponse, ProviderError
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization

pytestmark = pytest.mark.usefixtures("fresh_engine")

_KEY = "sk-test-embedding-key-0001"


@pytest.fixture(autouse=True)
def _master_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CCF_AI_CREDENTIAL_MASTER_KEY", "unit-test-master-key-32-chars-xx")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


class _FakeEmbedProvider(AIProvider):
    """Deterministic adapter — no network, stable vectors."""

    name = "fake"
    supports_embeddings = True

    async def validate_credential(self):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    async def generate_text(self, request):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    async def generate_structured_output(self, request):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    async def list_supported_models(self):  # type: ignore[no-untyped-def]
        return []

    async def embed(self, request: EmbedRequest) -> EmbedResponse:
        return EmbedResponse(
            vectors=[[float(len(text) % 7)] * 1024 for text in request.texts],
            model=request.model,
            input_tokens=sum(len(t) for t in request.texts) // 4,
        )


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return int(org.id)


async def test_anthropic_reports_no_embedding_support() -> None:
    provider = build_provider("anthropic", _KEY)
    assert provider.supports_embeddings is False


async def test_calling_embed_on_an_unsupported_provider_raises_provider_error() -> None:
    provider = build_provider("anthropic", _KEY)
    with pytest.raises(ProviderError) as exc:
        await provider.embed(EmbedRequest(texts=["hello"], model="claude-opus-4-8"))
    assert "embedding" in str(exc.value).lower()


async def test_openai_reports_embedding_support() -> None:
    provider = build_provider("openai", _KEY)
    assert provider.supports_embeddings is True


async def test_gateway_embed_returns_one_vector_per_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = await _org("embed-org")
    async with session_scope() as s:
        await gateway.set_credential(
            s, org_id, "openai", api_key=_KEY, enabled=True,
            default_model="text-embedding-3-small",
        )
    monkeypatch.setattr(gateway, "build_provider", lambda *a, **kw: _FakeEmbedProvider())
    async with session_scope() as s:
        response = await gateway.embed(
            s, org_id, texts=["one", "two", "three"], purpose="prep.classify"
        )
    assert len(response.vectors) == 3
    assert all(len(v) == 1024 for v in response.vectors)


async def test_gateway_embed_rejects_an_empty_batch() -> None:
    org_id = await _org("embed-empty")
    async with session_scope() as s:
        with pytest.raises(gateway.GatewayError):
            await gateway.embed(s, org_id, texts=[], purpose="prep.classify")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_prep_embed_provider.py -v`
Expected: FAIL — `ImportError: cannot import name 'EmbedRequest' from 'ccf.ai.providers.base'`.

- [ ] **Step 3: Extend the provider contract**

In `src/ccf/ai/providers/base.py`, add the dataclasses after `StructuredGenerationResponse`:

```python
@dataclass(slots=True)
class EmbedRequest:
    texts: list[str]
    model: str


@dataclass(slots=True)
class EmbedResponse:
    vectors: list[list[float]]
    model: str
    input_tokens: int = 0
```

Then, inside `class AIProvider`, add the capability flag next to `name` and a concrete `embed`:

```python
    #: Whether this vendor exposes an embeddings endpoint. Anthropic does not —
    #: it directs users to third-party embedding providers — so embedding is a
    #: capability, not a requirement, and callers must check before dispatching.
    supports_embeddings: bool = False

    async def embed(self, request: EmbedRequest) -> EmbedResponse:
        """Embed texts. Overridden only by providers that support it."""
        raise ProviderError(f"provider '{self.name}' does not support embedding")
```

Note it is deliberately **not** `@abstractmethod` — making it abstract would force `AnthropicProvider` to implement a method it can only ever raise from.

- [ ] **Step 4: Implement embedding on the OpenAI provider**

In `src/ccf/ai/providers/openai.py`, set the flag on the class:

```python
    supports_embeddings = True
```

and add the method, following the transport pattern the file already uses for `generate_text` (same `httpx` client construction, same auth header, same error translation to `ProviderError`):

```python
    async def embed(self, request: EmbedRequest) -> EmbedResponse:
        """Call POST /v1/embeddings and normalise the response."""
        payload = {"model": request.model, "input": request.texts}
        data = await self._post_json("/v1/embeddings", payload)
        items = sorted(data.get("data", []), key=lambda row: int(row.get("index", 0)))
        vectors = [[float(x) for x in row["embedding"]] for row in items]
        if len(vectors) != len(request.texts):
            raise ProviderError(
                f"embedding count mismatch: sent {len(request.texts)}, got {len(vectors)}"
            )
        return EmbedResponse(
            vectors=vectors,
            model=str(data.get("model", request.model)),
            input_tokens=int(data.get("usage", {}).get("prompt_tokens", 0)),
        )
```

Add `EmbedRequest` and `EmbedResponse` to the file's imports from `.base`. If the existing file has no `_post_json` helper, use whatever request helper `generate_text` already calls, keeping the auth and base-URL handling identical.

- [ ] **Step 5: Export the new types**

In `src/ccf/ai/providers/__init__.py`, add `EmbedRequest` and `EmbedResponse` to both the `from .base import (...)` block and `__all__`.

- [ ] **Step 6: Add the gateway entrypoint**

In `src/ccf/ai/gateway.py`, add the import and the function after `generate_structured`:

```python
async def embed(
    session: AsyncSession,
    org_id: int,
    *,
    texts: list[str],
    purpose: str,
    provider: str | None = None,
    model: str | None = None,
    actor: str | None = None,
) -> EmbedResponse:
    """Embed a batch of texts using the org's embedding provider.

    Resolves independently of the generation provider: an org generating with
    Anthropic still embeds elsewhere, because Anthropic has no embeddings API.
    """
    if not texts:
        raise GatewayError("embed requires at least one text")
    settings = get_settings()
    rp = await resolve(
        session,
        org_id,
        provider=provider or settings.prep_embed_provider,
        model=model or settings.prep_embed_model,
    )
    if not rp.provider.supports_embeddings:
        raise GatewayError(
            f"provider '{rp.config.provider}' does not support embedding; "
            "set CCF_PREP_EMBED_PROVIDER to one that does"
        )
    resp = await rp.provider.embed(EmbedRequest(texts=texts, model=rp.model))
    log.info(
        "ai.gateway.embed",
        org_id=org_id,
        provider=rp.config.provider,
        model=rp.model,
        purpose=purpose,
        actor=actor,
        batch_size=len(texts),
        input_tokens=resp.input_tokens,
    )
    return resp
```

Add `EmbedRequest, EmbedResponse` to the existing `from .providers...` import in that module.

- [ ] **Step 7: Run tests to verify they pass**

Run: `pytest tests/test_prep_embed_provider.py tests/test_ai_gateway.py tests/test_ai_providers.py -v`
Expected: PASS — the new module's 5 tests plus the existing AI suites, which must not regress.

- [ ] **Step 8: Verify lint and types**

Run: `ruff check . && mypy src`
Expected: no errors.

- [ ] **Step 9: Commit**

```bash
git add src/ccf/ai tests/test_prep_embed_provider.py
git commit -m "feat(ai): add embedding support to the provider interface and gateway"
```

---

### Task 12: Classify stage as a governed AI action

Classification is the only stage that asks a model to reason, so it runs through the existing AI action machinery — citations, guardrails, and review state come free rather than being rebuilt.

**Files:**
- Modify: `src/ccf/ai_actions/registry.py`
- Create: `src/ccf/prep/classify.py`
- Modify: `src/ccf/prep/pipeline.py`
- Create: `tests/test_prep_classify.py`

**Interfaces:**
- Consumes: `gateway.generate_structured` (existing); `PrepUnit`, `PrepClassification`, `PrepScreen` (Task 2); `ActionDef` (existing registry).
- Produces:
  - `ActionDef("classify_evidence_unit", …)` registered in `ACTIONS`
  - `CLASSIFICATION_SCHEMA: dict[str, Any]` — the JSON schema the model must satisfy
  - `ARTIFACT_TYPES: tuple[str, ...]`, `EVIDENCE_STRENGTHS: tuple[str, ...]`
  - `build_prompt(unit_content: str, candidates: list[str]) -> str`
  - `async run_stage_classify(session, run: PrepRun) -> int`

- [ ] **Step 1: Write the failing test**

Create `tests/test_prep_classify.py`:

```python
"""Classification stage — schema, prompt bounding, and persistence."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import select

from ccf.ai import gateway
from ccf.ai_actions.registry import get_action
from ccf.db import session_scope
from ccf.models import Organization
from ccf.models_prep import PrepClassification, PrepLine, PrepScreen, PrepUnit
from ccf.prep import pipeline
from ccf.prep.classify import (
    ARTIFACT_TYPES,
    CLASSIFICATION_SCHEMA,
    build_prompt,
    run_stage_classify,
)

pytestmark = pytest.mark.usefixtures("fresh_engine")


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return int(org.id)


def test_action_is_registered_and_requires_citation() -> None:
    action = get_action("classify_evidence_unit")
    assert action is not None
    assert action.citation_required is True
    # Classification writes only to prep tables — it must never mutate an
    # authoritative record.
    assert action.allowed_mutation is None


def test_schema_constrains_artifact_type_to_the_known_vocabulary() -> None:
    enum = CLASSIFICATION_SCHEMA["properties"]["artifact_type"]["enum"]
    assert tuple(enum) == ARTIFACT_TYPES


def test_prompt_includes_the_unit_and_bounds_the_candidate_controls() -> None:
    prompt = build_prompt("Accounts are reviewed quarterly.", ["AC-2", "AC-2(1)"])
    assert "Accounts are reviewed quarterly." in prompt
    assert "AC-2(1)" in prompt


def test_prompt_states_that_the_model_does_not_decide_compliance() -> None:
    """The model classifies; application code and assessors decide."""
    prompt = build_prompt("Some evidence.", ["AC-2"])
    assert "not" in prompt.lower() and "determination" in prompt.lower()


async def test_classify_stage_persists_one_classification_per_unit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = await _org("prep-classify")

    async def _fake_structured(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "control_identifiers": ["AC-2"],
            "artifact_type": "procedure",
            "evidence_strength": "moderate",
            "explanation": "Describes a recurring account review.",
            "confidence": 0.72,
        }

    monkeypatch.setattr(gateway, "generate_structured", _fake_structured)

    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        run.stage_parse = run.stage_screen = run.stage_expand = "complete"
        line = PrepLine(run_id=run.id, organization_id=org_id, line_number=1,
                        content="Accounts are reviewed quarterly.")
        s.add(line)
        await s.flush()
        s.add(PrepScreen(line_id=line.id, run_id=run.id, organization_id=org_id,
                         relevance_score=0.5, candidate_controls=["AC-2"], above_threshold=True))
        s.add(PrepUnit(run_id=run.id, organization_id=org_id, trigger_line_id=line.id,
                       source_line_ids=[line.id], content="Accounts are reviewed quarterly.",
                       token_count=6))
        await s.flush()

        count = await run_stage_classify(s, run)
        assert count == 1
        assert run.units_classified == 1
        assert run.stage_classify == "complete"

        row = (
            await s.execute(select(PrepClassification).where(PrepClassification.run_id == run.id))
        ).scalar_one()
        assert row.control_identifiers == ["AC-2"]
        assert row.artifact_type == "procedure"
        assert row.evidence_strength == "moderate"
        assert row.model_confidence == pytest.approx(0.72)


async def test_classify_stage_is_idempotent_on_rerun(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = await _org("prep-classify-rerun")

    async def _fake_structured(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "control_identifiers": ["AC-2"], "artifact_type": "policy",
            "evidence_strength": "weak", "explanation": "x", "confidence": 0.4,
        }

    monkeypatch.setattr(gateway, "generate_structured", _fake_structured)
    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        run.stage_parse = run.stage_screen = run.stage_expand = "complete"
        line = PrepLine(run_id=run.id, organization_id=org_id, line_number=1, content="Text.")
        s.add(line)
        await s.flush()
        s.add(PrepUnit(run_id=run.id, organization_id=org_id, trigger_line_id=line.id,
                       source_line_ids=[line.id], content="Text.", token_count=2))
        await s.flush()
        await run_stage_classify(s, run)
        await run_stage_classify(s, run)
        rows = (
            await s.execute(select(PrepClassification).where(PrepClassification.run_id == run.id))
        ).scalars().all()
        assert len(rows) == 1


async def test_provider_failure_leaves_the_run_resumable_with_prior_stages_intact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = await _org("prep-classify-fail")

    async def _boom(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise gateway.GatewayError("provider unavailable")

    monkeypatch.setattr(gateway, "generate_structured", _boom)
    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        run.stage_parse = run.stage_screen = run.stage_expand = "complete"
        line = PrepLine(run_id=run.id, organization_id=org_id, line_number=1, content="Text.")
        s.add(line)
        await s.flush()
        s.add(PrepUnit(run_id=run.id, organization_id=org_id, trigger_line_id=line.id,
                       source_line_ids=[line.id], content="Text.", token_count=2))
        await s.flush()
        await run_stage_classify(s, run)

    assert run.status == "failed"
    assert run.error_stage == "classify"
    assert run.stage_parse == "complete", "a classify failure must not undo parsing"
    assert pipeline.next_stage(run) == "classify"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_prep_classify.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.prep.classify'`.

- [ ] **Step 3: Register the action**

In `src/ccf/ai_actions/registry.py`, add to the `_DEFS` list, before the closing `]`:

```python
    ActionDef("classify_evidence_unit", "Classify an evidence unit",
              "Classify a prepared evidence passage by control, artifact type, and strength.",
              ("evidence_object", "system"), False, True, None),
```

`requires_approval=False` because classification writes only to prep tables — nothing authoritative — while `citation_required=True` keeps the unit's own text as the cited source.

- [ ] **Step 4: Write the classify stage**

Create `src/ccf/prep/classify.py`:

```python
"""Model-driven classification of prepared evidence units.

This is the only stage that asks a model to reason, so it runs through the AI
gateway with a strict JSON schema and records its output as data, never as prose.
The model's scope is bounded three ways: it sees one unit at a time, it chooses
from the candidate controls screening already surfaced, and it returns values
from a fixed vocabulary. What the classification *means* — whether a control is
satisfied — is decided later by application code and an assessor, never here.

Screening candidates bound the prompt because handing the model the whole 800-53
catalog would both cost more and invite invention.
"""

from __future__ import annotations

from typing import Any

import structlog
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..ai import gateway
from ..models_prep import PrepClassification, PrepRun, PrepScreen, PrepUnit

log = structlog.get_logger(__name__)

ACTION_KEY = "classify_evidence_unit"

ARTIFACT_TYPES = (
    "policy",
    "procedure",
    "technical_implementation",
    "testing_evidence",
    "management_approval",
    "other",
)

EVIDENCE_STRENGTHS = ("strong", "moderate", "weak")

CLASSIFICATION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "control_identifiers": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Controls this passage supports, from the candidates offered.",
        },
        "artifact_type": {"type": "string", "enum": list(ARTIFACT_TYPES)},
        "evidence_strength": {"type": "string", "enum": list(EVIDENCE_STRENGTHS)},
        "explanation": {"type": "string"},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
    },
    "required": ["control_identifiers", "artifact_type", "evidence_strength", "confidence"],
    "additionalProperties": False,
}

_SYSTEM_PROMPT = (
    "You classify passages from security documentation against NIST SP 800-53 Rev 5 "
    "controls. You are not making a compliance determination and you do not decide "
    "whether a control is satisfied — an assessor does that later. Classify only what "
    "the passage actually says. If it does not support any of the candidate controls, "
    "return an empty control_identifiers array."
)


def build_prompt(unit_content: str, candidates: list[str]) -> str:
    """Build the classification prompt for one unit, bounded by its candidates."""
    offered = ", ".join(candidates) if candidates else "(none surfaced by screening)"
    return (
        f"Candidate controls: {offered}\n\n"
        f"Passage:\n{unit_content}\n\n"
        "Classify this passage. Choose control identifiers only from the candidates. "
        "artifact_type describes what kind of material this is. evidence_strength is how "
        "well it would support an assessment objective: 'strong' for a specific, dated, "
        "verifiable statement; 'moderate' for a clear but general one; 'weak' for a vague "
        "or aspirational one. This is a classification, not a determination."
    )


async def _candidates_for(session: AsyncSession, unit: PrepUnit) -> list[str]:
    row = (
        await session.execute(
            select(PrepScreen).where(PrepScreen.line_id == unit.trigger_line_id)
        )
    ).scalar_one_or_none()
    return [str(x) for x in row.candidate_controls] if row is not None else []


async def run_stage_classify(session: AsyncSession, run: PrepRun) -> int:
    """Classify every unit in the run. Returns the count classified."""
    run.stage_classify = "running"

    # Idempotent: clear prior output so a resumed run cannot double-write.
    await session.execute(
        delete(PrepClassification).where(PrepClassification.run_id == run.id)
    )

    units = (
        await session.execute(select(PrepUnit).where(PrepUnit.run_id == run.id))
    ).scalars().all()

    classified = 0
    for unit in units:
        candidates = await _candidates_for(session, unit)
        try:
            data = await gateway.generate_structured(
                session,
                run.organization_id,
                prompt=build_prompt(unit.content, candidates),
                schema=CLASSIFICATION_SCHEMA,
                purpose=ACTION_KEY,
                system=_SYSTEM_PROMPT,
            )
        except Exception as exc:  # noqa: BLE001 — any provider fault leaves the run resumable
            run.status = "failed"
            run.stage_classify = "failed"
            run.error_stage = "classify"
            run.error = f"classification failed: {exc}"
            await session.flush()
            log.warning("prep.classify_failed", run_id=run.id, error=str(exc))
            return classified

        # Trust the schema for shape, but never let the model widen its own scope
        # beyond the controls screening actually surfaced.
        allowed = set(candidates)
        chosen = [c for c in data.get("control_identifiers", []) if not allowed or c in allowed]

        session.add(
            PrepClassification(
                unit_id=unit.id,
                run_id=run.id,
                organization_id=run.organization_id,
                control_identifiers=chosen,
                artifact_type=data.get("artifact_type"),
                evidence_strength=data.get("evidence_strength"),
                explanation=data.get("explanation"),
                model_confidence=float(data.get("confidence", 0.0)),
            )
        )
        classified += 1

    run.units_classified = classified
    run.stage_classify = "complete"
    await session.flush()
    log.info("prep.classify_complete", run_id=run.id, units=classified)
    return classified
```

- [ ] **Step 5: Register the stage**

In `src/ccf/prep/pipeline.py`, add the import and extend the registry:

```python
from .classify import run_stage_classify
```

```python
_STAGE_RUNNERS: dict[str, Any] = {
    "parse": run_stage_parse,
    "screen": run_stage_screen,
    "expand": run_stage_expand,
    "classify": run_stage_classify,
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `pytest tests/test_prep_classify.py tests/test_ai_actions.py -v`
Expected: PASS — the new module's 7 tests, plus the existing AI action suite, which must not regress now that the registry has a new entry.

- [ ] **Step 7: Verify lint and types**

Run: `ruff check . && mypy src`
Expected: no errors.

- [ ] **Step 8: Commit**

```bash
git add src/ccf/prep/classify.py src/ccf/prep/pipeline.py \
        src/ccf/ai_actions/registry.py tests/test_prep_classify.py
git commit -m "feat(prep): classify units as a governed AI action"
```

---

### Task 13: Embed stage

The last pipeline stage. Batched, dimension-validated, and recorded with its model so a provider change is detectable rather than silently mixing vector spaces.

**Files:**
- Create: `src/ccf/prep/embed.py`
- Modify: `src/ccf/prep/pipeline.py`
- Create: `tests/test_prep_embed_stage.py`

**Interfaces:**
- Consumes: `gateway.embed` (Task 11); `PrepUnit`, `PrepEmbedding`, `PREP_EMBEDDING_DIM` (Task 2).
- Produces: `async run_stage_embed(session, run: PrepRun) -> int`, `DimensionMismatch` exception.

- [ ] **Step 1: Write the failing test**

Create `tests/test_prep_embed_stage.py`:

```python
"""Embed stage — batching, dimension validation, and model recording."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import select

from ccf.ai import gateway
from ccf.ai.providers.base import EmbedResponse
from ccf.db import session_scope
from ccf.models import Organization
from ccf.models_prep import PrepEmbedding, PrepLine, PrepUnit
from ccf.prep import pipeline
from ccf.prep.embed import run_stage_embed

pytestmark = pytest.mark.usefixtures("fresh_engine")


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return int(org.id)


async def _run_with_units(org_id: int, count: int) -> int:
    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        run.stage_parse = run.stage_screen = "complete"
        run.stage_expand = run.stage_classify = "complete"
        for n in range(count):
            line = PrepLine(run_id=run.id, organization_id=org_id, line_number=n + 1,
                            content=f"Statement {n}.")
            s.add(line)
            await s.flush()
            s.add(PrepUnit(run_id=run.id, organization_id=org_id, trigger_line_id=line.id,
                           source_line_ids=[line.id], content=f"Statement {n}.", token_count=3))
        await s.flush()
        return int(run.id)


def _fake_embed(dim: int = 1024):
    async def _embed(session: Any, org_id: int, *, texts: list[str], **kw: Any) -> EmbedResponse:
        return EmbedResponse(
            vectors=[[0.01] * dim for _ in texts],
            model="text-embedding-3-small",
            input_tokens=len(texts),
        )

    return _embed


async def test_embed_stage_writes_one_vector_per_unit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = await _org("prep-embed")
    run_id = await _run_with_units(org_id, 3)
    monkeypatch.setattr(gateway, "embed", _fake_embed())
    async with session_scope() as s:
        run = await pipeline.load_run(s, run_id)
        assert run is not None
        count = await run_stage_embed(s, run)
        assert count == 3
        assert run.units_embedded == 3
        assert run.stage_embed == "complete"
        rows = (
            await s.execute(select(PrepEmbedding).where(PrepEmbedding.run_id == run_id))
        ).scalars().all()
        assert len(rows) == 3
        assert all(r.model_name == "text-embedding-3-small" for r in rows)


async def test_dimension_mismatch_fails_the_stage_rather_than_writing_bad_vectors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = await _org("prep-embed-dim")
    run_id = await _run_with_units(org_id, 1)
    monkeypatch.setattr(gateway, "embed", _fake_embed(dim=512))
    async with session_scope() as s:
        run = await pipeline.load_run(s, run_id)
        assert run is not None
        await run_stage_embed(s, run)
        assert run.status == "failed"
        assert run.error_stage == "embed"
        assert "512" in (run.error or "")
        rows = (
            await s.execute(select(PrepEmbedding).where(PrepEmbedding.run_id == run_id))
        ).scalars().all()
        assert rows == []


async def test_embed_stage_is_idempotent_on_rerun(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = await _org("prep-embed-rerun")
    run_id = await _run_with_units(org_id, 2)
    monkeypatch.setattr(gateway, "embed", _fake_embed())
    async with session_scope() as s:
        run = await pipeline.load_run(s, run_id)
        assert run is not None
        await run_stage_embed(s, run)
        await run_stage_embed(s, run)
        rows = (
            await s.execute(select(PrepEmbedding).where(PrepEmbedding.run_id == run_id))
        ).scalars().all()
        assert len(rows) == 2


async def test_a_run_with_no_units_completes_without_calling_the_provider() -> None:
    org_id = await _org("prep-embed-empty")
    run_id = await _run_with_units(org_id, 0)
    async with session_scope() as s:
        run = await pipeline.load_run(s, run_id)
        assert run is not None
        # No monkeypatch: a provider call here would raise, proving none is made.
        assert await run_stage_embed(s, run) == 0
        assert run.stage_embed == "complete"


async def test_advance_drives_a_run_to_complete(monkeypatch: pytest.MonkeyPatch) -> None:
    """End-to-end: with every stage registered, advance reaches status=complete."""
    org_id = await _org("prep-advance")
    run_id = await _run_with_units(org_id, 1)
    monkeypatch.setattr(gateway, "embed", _fake_embed())
    async with session_scope() as s:
        run = await pipeline.load_run(s, run_id)
        assert run is not None
        await pipeline.advance(s, run)
        assert run.status == "complete"
        assert pipeline.next_stage(run) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_prep_embed_stage.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.prep.embed'`.

- [ ] **Step 3: Write the embed stage**

Create `src/ccf/prep/embed.py`:

```python
"""Vector embedding of prepared units.

Batched because per-unit round trips dominate wall-clock on any real corpus, and
dimension-validated because pgvector columns are fixed width: a provider or model
change that alters the vector length must fail loudly at the stage boundary
rather than write truncated vectors that silently poison retrieval.

``model_name`` is recorded per row so a corpus embedded across a model change is
detectable — mixing two embedding spaces in one index degrades ranking in ways
that are very hard to diagnose after the fact.
"""

from __future__ import annotations

import structlog
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..ai import gateway
from ..config import get_settings
from ..models_prep import PREP_EMBEDDING_DIM, PrepEmbedding, PrepRun, PrepUnit

log = structlog.get_logger(__name__)


class DimensionMismatch(ValueError):
    """The provider returned vectors of an unexpected width."""


async def run_stage_embed(session: AsyncSession, run: PrepRun) -> int:
    """Embed every unit in the run. Returns the count embedded."""
    run.stage_embed = "running"

    # Idempotent: clear prior output so a resumed run cannot double-write.
    await session.execute(delete(PrepEmbedding).where(PrepEmbedding.run_id == run.id))

    units = (
        await session.execute(
            select(PrepUnit).where(PrepUnit.run_id == run.id).order_by(PrepUnit.id)
        )
    ).scalars().all()
    if not units:
        run.units_embedded = 0
        run.stage_embed = "complete"
        await session.flush()
        return 0

    settings = get_settings()
    batch_size = max(1, settings.prep_worker_batch_size)
    expected = int(run.config_snapshot.get("embed_dimensions", settings.prep_embed_dimensions))

    embedded = 0
    for start in range(0, len(units), batch_size):
        batch = units[start : start + batch_size]
        try:
            response = await gateway.embed(
                session,
                run.organization_id,
                texts=[unit.content for unit in batch],
                purpose="prep.embed",
            )
            for vector in response.vectors:
                if len(vector) != expected or len(vector) != PREP_EMBEDDING_DIM:
                    raise DimensionMismatch(
                        f"provider returned {len(vector)}-dimension vectors; "
                        f"schema requires {PREP_EMBEDDING_DIM}"
                    )
        except Exception as exc:  # noqa: BLE001 — any fault leaves the run resumable
            run.status = "failed"
            run.stage_embed = "failed"
            run.error_stage = "embed"
            run.error = f"embedding failed: {exc}"
            # Discard partial vectors: a half-embedded corpus ranks worse than
            # an unembedded one, because absence is at least detectable.
            await session.execute(
                delete(PrepEmbedding).where(PrepEmbedding.run_id == run.id)
            )
            await session.flush()
            log.warning("prep.embed_failed", run_id=run.id, error=str(exc))
            return 0

        for unit, vector in zip(batch, response.vectors, strict=True):
            session.add(
                PrepEmbedding(
                    unit_id=unit.id,
                    run_id=run.id,
                    organization_id=run.organization_id,
                    model_name=response.model,
                    embedding=vector,
                )
            )
            embedded += 1

    run.units_embedded = embedded
    run.stage_embed = "complete"
    await session.flush()
    log.info("prep.embed_complete", run_id=run.id, units=embedded)
    return embedded
```

- [ ] **Step 4: Register the stage**

In `src/ccf/prep/pipeline.py`, add the import and complete the registry:

```python
from .embed import run_stage_embed
```

```python
_STAGE_RUNNERS: dict[str, Any] = {
    "parse": run_stage_parse,
    "screen": run_stage_screen,
    "expand": run_stage_expand,
    "classify": run_stage_classify,
    "embed": run_stage_embed,
}
```

- [ ] **Step 5: Run the whole prep suite**

Run: `pytest tests/test_prep_*.py -v`
Expected: PASS — every prep module including the new 5 tests.

- [ ] **Step 6: Verify lint and types**

Run: `ruff check . && mypy src`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add src/ccf/prep/embed.py src/ccf/prep/pipeline.py tests/test_prep_embed_stage.py
git commit -m "feat(prep): add dimension-validated embed stage completing the pipeline"
```

---

### Task 14: Hybrid retrieval

The payoff. Fuses vector similarity with lexical rank because each alone fails on the other's strength — embeddings miss exact control identifiers and hostnames, lexical search misses paraphrased policy language.

**Files:**
- Create: `src/ccf/prep/retriever.py`
- Create: `tests/test_prep_retriever.py`

**Interfaces:**
- Consumes: `gateway.embed` (Task 11); `PrepUnit`, `PrepEmbedding`, `PrepClassification`, `PrepLine` (Task 2).
- Produces:
  - `RetrievedUnit(unit_id: int, content: str, score: float, page_numbers: list[int], section_path: str | None, table_coordinates: dict[str, Any] | None, source_kind: str | None, control_identifiers: list[str], evidence_strength: str | None, lexical_rank: int | None, vector_rank: int | None)`
  - `def fuse(lexical: list[int], vector: list[int], *, k: int = 60) -> list[tuple[int, float]]`
  - `async retrieve(session, *, org_id: int, control_identifier: str, query_text: str | None = None, system_id: int | None = None, source_kind: str | None = None, limit: int | None = None) -> list[RetrievedUnit]`

- [ ] **Step 1: Write the failing test**

Create `tests/test_prep_retriever.py`:

```python
"""Hybrid retrieval — RRF fusion, filtering, and citation fidelity."""

from __future__ import annotations

from typing import Any

import pytest

from ccf.ai import gateway
from ccf.ai.providers.base import EmbedResponse
from ccf.db import session_scope
from ccf.models import Organization, System
from ccf.models_prep import PrepClassification, PrepEmbedding, PrepLine, PrepUnit
from ccf.prep import pipeline
from ccf.prep.retriever import fuse, retrieve

pytestmark = pytest.mark.usefixtures("fresh_engine")


def test_fuse_ranks_a_unit_found_by_both_backends_above_either_alone() -> None:
    """The core claim of hybrid retrieval, asserted directly on the fusion."""
    fused = dict(fuse(lexical=[1, 2], vector=[3, 1]))
    assert fused[1] > fused[2]
    assert fused[1] > fused[3]


def test_fuse_returns_units_found_by_only_one_backend() -> None:
    ids = [unit_id for unit_id, _ in fuse(lexical=[1], vector=[2])]
    assert sorted(ids) == [1, 2]


def test_fuse_of_two_empty_rankings_is_empty() -> None:
    assert fuse(lexical=[], vector=[]) == []


async def _seed(org_name: str) -> tuple[int, int, dict[str, int]]:
    """Three units: one MFA policy, one backup policy, one unrelated."""
    async with session_scope() as s:
        org = Organization(name=org_name)
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name="Sys")
        s.add(system)
        await s.flush()
        run = await pipeline.create_run(
            s, organization_id=org.id, source_kind="evidence_version", source_id=1
        )
        ids: dict[str, int] = {}
        rows = [
            ("mfa", "Administrators authenticate with multifactor authentication.", "IA-2",
             [0.9] * 1024),
            ("backup", "Nightly backups are replicated offsite.", "CP-9", [0.1] * 1024),
            ("noise", "The cafeteria closes at five.", "AC-1", [0.0] * 1024),
        ]
        for key, content, control, vector in rows:
            line = PrepLine(run_id=run.id, organization_id=org.id, line_number=len(ids) + 1,
                            page_number=3, section_path="Access Control", content=content)
            s.add(line)
            await s.flush()
            unit = PrepUnit(run_id=run.id, organization_id=org.id, trigger_line_id=line.id,
                            source_line_ids=[line.id], content=content, page_numbers=[3],
                            section_path="Access Control", token_count=8,
                            system_id=system.id, source_kind="evidence_version")
            s.add(unit)
            await s.flush()
            ids[key] = int(unit.id)
            s.add(PrepClassification(unit_id=unit.id, run_id=run.id, organization_id=org.id,
                                     control_identifiers=[control], artifact_type="policy",
                                     evidence_strength="strong", model_confidence=0.8))
            s.add(PrepEmbedding(unit_id=unit.id, run_id=run.id, organization_id=org.id,
                                model_name="text-embedding-3-small", embedding=vector))
        await s.flush()
        return int(org.id), int(system.id), ids


def _fake_embed(vector: list[float]):
    async def _embed(session: Any, org_id: int, *, texts: list[str], **kw: Any) -> EmbedResponse:
        return EmbedResponse(vectors=[vector], model="text-embedding-3-small")

    return _embed


async def test_retrieve_returns_the_matching_unit_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id, _, ids = await _seed("retr-basic")
    monkeypatch.setattr(gateway, "embed", _fake_embed([0.9] * 1024))
    async with session_scope() as s:
        results = await retrieve(
            s, org_id=org_id, control_identifier="IA-2",
            query_text="multifactor authentication", limit=3,
        )
    assert results
    assert results[0].unit_id == ids["mfa"]


async def test_results_carry_the_citation_back_to_page_and_section(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id, _, _ = await _seed("retr-cite")
    monkeypatch.setattr(gateway, "embed", _fake_embed([0.9] * 1024))
    async with session_scope() as s:
        results = await retrieve(
            s, org_id=org_id, control_identifier="IA-2", query_text="mfa", limit=1
        )
    assert results[0].page_numbers == [3]
    assert results[0].section_path == "Access Control"
    assert "IA-2" in results[0].control_identifiers


async def test_retrieval_is_scoped_to_the_requesting_organization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_a, _, _ = await _seed("retr-tenant-a")
    org_b, _, _ = await _seed("retr-tenant-b")
    monkeypatch.setattr(gateway, "embed", _fake_embed([0.9] * 1024))
    async with session_scope() as s:
        results = await retrieve(
            s, org_id=org_a, control_identifier="IA-2", query_text="mfa", limit=10
        )
    async with session_scope() as s:
        b_units = {
            r.unit_id
            for r in await retrieve(
                s, org_id=org_b, control_identifier="IA-2", query_text="mfa", limit=10
            )
        }
    assert not ({r.unit_id for r in results} & b_units)


async def test_system_filter_excludes_other_systems(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id, system_id, _ = await _seed("retr-system")
    monkeypatch.setattr(gateway, "embed", _fake_embed([0.9] * 1024))
    async with session_scope() as s:
        matched = await retrieve(
            s, org_id=org_id, control_identifier="IA-2", query_text="mfa",
            system_id=system_id, limit=10,
        )
        missed = await retrieve(
            s, org_id=org_id, control_identifier="IA-2", query_text="mfa",
            system_id=system_id + 9_999, limit=10,
        )
    assert matched
    assert missed == []


async def test_retrieval_falls_back_to_lexical_when_embedding_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A provider outage must degrade retrieval, not break it."""
    org_id, _, ids = await _seed("retr-fallback")

    async def _boom(*args: Any, **kwargs: Any) -> EmbedResponse:
        raise gateway.GatewayError("provider unavailable")

    monkeypatch.setattr(gateway, "embed", _boom)
    async with session_scope() as s:
        results = await retrieve(
            s, org_id=org_id, control_identifier="IA-2",
            query_text="multifactor authentication", limit=3,
        )
    assert results
    assert results[0].unit_id == ids["mfa"]
    assert results[0].vector_rank is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_prep_retriever.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.prep.retriever'`.

- [ ] **Step 3: Write the retriever**

Create `src/ccf/prep/retriever.py`:

```python
"""Hybrid retrieval over prepared evidence units.

Neither backend is sufficient alone. Embeddings handle paraphrase — "reviewed
every three months" against "quarterly review" — but treat control identifiers,
hostnames and product names as near-noise, because those tokens carry almost no
distributional meaning. Lexical search is exact on precisely those tokens and
blind to paraphrase. Reciprocal-rank fusion combines the two rankings without
needing their scores to be on comparable scales, which they are not.

Retrieval degrades rather than fails: if the embedding provider is unavailable,
results come back lexical-only with ``vector_rank`` unset, because a narrower
answer is worth more than an error to a caller assembling evidence for a control.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..ai import gateway
from ..config import get_settings
from ..models_prep import PrepClassification, PrepEmbedding, PrepUnit

log = structlog.get_logger(__name__)

#: RRF damping constant. 60 is the value from the original Cormack et al. work
#: and is deliberately large relative to the result-set size, which keeps any
#: single backend from dominating on rank-1 alone.
_RRF_K = 60

#: How deep each backend ranks before fusion. Wider than the returned limit so a
#: unit ranked mid-list by both still has a chance to win on combined score.
_CANDIDATE_DEPTH = 50


@dataclass(slots=True)
class RetrievedUnit:
    """One retrieved passage with everything needed to cite it."""

    unit_id: int
    content: str
    score: float
    page_numbers: list[int]
    section_path: str | None
    table_coordinates: dict[str, Any] | None
    source_kind: str | None
    control_identifiers: list[str]
    evidence_strength: str | None
    lexical_rank: int | None
    vector_rank: int | None


def fuse(lexical: list[int], vector: list[int], *, k: int = _RRF_K) -> list[tuple[int, float]]:
    """Reciprocal-rank fusion of two ranked id lists, best first."""
    scores: dict[int, float] = {}
    for ranking in (lexical, vector):
        for position, unit_id in enumerate(ranking, start=1):
            scores[unit_id] = scores.get(unit_id, 0.0) + 1.0 / (k + position)
    return sorted(scores.items(), key=lambda pair: pair[1], reverse=True)


def _base_filters(stmt: Any, *, org_id: int, system_id: int | None, source_kind: str | None):
    stmt = stmt.where(PrepUnit.organization_id == org_id)
    if system_id is not None:
        stmt = stmt.where(PrepUnit.system_id == system_id)
    if source_kind is not None:
        stmt = stmt.where(PrepUnit.source_kind == source_kind)
    return stmt


async def _lexical_ids(
    session: AsyncSession,
    *,
    org_id: int,
    query_text: str,
    system_id: int | None,
    source_kind: str | None,
) -> list[int]:
    query = func.websearch_to_tsquery("english", query_text)
    rank = func.ts_rank(PrepUnit.search_vector, query)
    stmt = select(PrepUnit.id).where(PrepUnit.search_vector.op("@@")(query))
    stmt = _base_filters(stmt, org_id=org_id, system_id=system_id, source_kind=source_kind)
    rows = (await session.execute(stmt.order_by(rank.desc()).limit(_CANDIDATE_DEPTH))).all()
    return [int(r[0]) for r in rows]


async def _vector_ids(
    session: AsyncSession,
    *,
    org_id: int,
    query_text: str,
    system_id: int | None,
    source_kind: str | None,
) -> list[int]:
    try:
        response = await gateway.embed(
            session, org_id, texts=[query_text], purpose="prep.retrieve"
        )
    except Exception as exc:  # noqa: BLE001 — degrade to lexical, never fail the caller
        log.info("prep.retrieve_vector_unavailable", org_id=org_id, error=str(exc))
        return []
    vector = response.vectors[0]
    distance = PrepEmbedding.embedding.cosine_distance(vector)
    stmt = select(PrepUnit.id).join(PrepEmbedding, PrepEmbedding.unit_id == PrepUnit.id)
    stmt = _base_filters(stmt, org_id=org_id, system_id=system_id, source_kind=source_kind)
    rows = (await session.execute(stmt.order_by(distance).limit(_CANDIDATE_DEPTH))).all()
    return [int(r[0]) for r in rows]


async def retrieve(
    session: AsyncSession,
    *,
    org_id: int,
    control_identifier: str,
    query_text: str | None = None,
    system_id: int | None = None,
    source_kind: str | None = None,
    limit: int | None = None,
) -> list[RetrievedUnit]:
    """Retrieve prepared units supporting a control, best first."""
    top_n = limit if limit is not None else get_settings().ai_max_context_docs
    text_query = query_text or control_identifier

    lexical = await _lexical_ids(
        session, org_id=org_id, query_text=text_query,
        system_id=system_id, source_kind=source_kind,
    )
    vector = await _vector_ids(
        session, org_id=org_id, query_text=text_query,
        system_id=system_id, source_kind=source_kind,
    )

    # Units the classifier tagged with this control rank first regardless of
    # text similarity: an explicit classification is a stronger signal than any
    # similarity score, and this is what makes retrieval control-aware rather
    # than merely semantic.
    tagged_stmt = (
        select(PrepUnit.id)
        .join(PrepClassification, PrepClassification.unit_id == PrepUnit.id)
        .where(PrepClassification.control_identifiers.op("@>")([control_identifier]))
    )
    tagged_stmt = _base_filters(
        tagged_stmt, org_id=org_id, system_id=system_id, source_kind=source_kind
    )
    tagged = [int(r[0]) for r in (await session.execute(tagged_stmt)).all()]

    fused = fuse(lexical=lexical, vector=vector)
    tagged_set = set(tagged)
    # Boost, not filter: an untagged unit can still be the best evidence when
    # classification was conservative.
    ordered = sorted(
        fused,
        key=lambda pair: (pair[0] in tagged_set, pair[1]),
        reverse=True,
    )[:top_n]
    if not ordered:
        return []

    lexical_positions = {unit_id: i + 1 for i, unit_id in enumerate(lexical)}
    vector_positions = {unit_id: i + 1 for i, unit_id in enumerate(vector)}

    unit_ids = [unit_id for unit_id, _ in ordered]
    rows = (
        await session.execute(
            select(PrepUnit, PrepClassification)
            .outerjoin(PrepClassification, PrepClassification.unit_id == PrepUnit.id)
            .where(PrepUnit.id.in_(unit_ids))
        )
    ).all()
    by_id = {int(unit.id): (unit, classification) for unit, classification in rows}

    results: list[RetrievedUnit] = []
    for unit_id, score in ordered:
        found = by_id.get(unit_id)
        if found is None:
            continue
        unit, classification = found
        results.append(
            RetrievedUnit(
                unit_id=unit_id,
                content=unit.content,
                score=score,
                page_numbers=[int(p) for p in (unit.page_numbers or [])],
                section_path=unit.section_path,
                table_coordinates=unit.table_coordinates,
                source_kind=unit.source_kind,
                control_identifiers=(
                    [str(c) for c in classification.control_identifiers]
                    if classification is not None
                    else []
                ),
                evidence_strength=(
                    classification.evidence_strength if classification is not None else None
                ),
                lexical_rank=lexical_positions.get(unit_id),
                vector_rank=vector_positions.get(unit_id),
            )
        )
    return results
```

**Note on the containment operator:** `.op("@>")` is Postgres JSONB containment — it asks whether the stored array contains the given element. SQLAlchemy's generic `.contains()` means something different on a JSONB column, so use `.op("@>")` as written.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_prep_retriever.py -v`
Expected: PASS (8 tests)

- [ ] **Step 5: Verify lint and types**

Run: `ruff check . && mypy src`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add src/ccf/prep/retriever.py tests/test_prep_retriever.py
git commit -m "feat(prep): add hybrid RRF retrieval over prepared units"
```

---

### Task 15: Job queue and the `prep-worker` CLI

Makes the pipeline runnable outside a request. Follows the existing `poller`/`scheduler` compose-profile pattern rather than introducing a new runtime service type.

**Files:**
- Create: `src/ccf/prep/jobs.py`
- Modify: `src/ccf/cli.py`
- Modify: `docker-compose.yml`
- Modify: `Makefile`
- Create: `tests/test_prep_jobs.py`

**Interfaces:**
- Consumes: `PrepJob`, `PrepRun` (Task 2); `pipeline.advance`, `pipeline.create_run`, `pipeline.next_stage` (Tasks 8–13).
- Produces:
  - `async enqueue(session, *, organization_id: int, source_kind: str, source_id: int) -> PrepJob`
  - `async claim(session, *, worker: str, limit: int) -> list[PrepJob]`
  - `async reap_stale(session, *, older_than_minutes: int) -> int`
  - `async run_once(session, *, worker: str, limit: int) -> dict[str, int]`
  - CLI command `ccf prep-worker [--once] [--limit N] [--worker NAME]`

- [ ] **Step 1: Write the failing test**

Create `tests/test_prep_jobs.py`:

```python
"""Job queue — claiming, reaping, retry accounting, and worker cycles."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select

from ccf.ai import gateway
from ccf.ai.providers.base import EmbedResponse
from ccf.db import session_scope
from ccf.models import Organization
from ccf.models_prep import PrepJob, PrepRun
from ccf.prep import jobs

pytestmark = pytest.mark.usefixtures("fresh_engine")


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return int(org.id)


async def test_enqueue_creates_a_run_and_a_pending_job() -> None:
    org_id = await _org("jobs-enqueue")
    async with session_scope() as s:
        job = await jobs.enqueue(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        assert job.status == "pending"
        assert job.next_stage == "parse"
        run = (
            await s.execute(select(PrepRun).where(PrepRun.id == job.run_id))
        ).scalar_one()
        assert run.organization_id == org_id


async def test_claim_marks_jobs_and_records_the_worker() -> None:
    org_id = await _org("jobs-claim")
    async with session_scope() as s:
        for n in range(3):
            await jobs.enqueue(
                s, organization_id=org_id, source_kind="policy_version", source_id=n
            )
    async with session_scope() as s:
        claimed = await jobs.claim(s, worker="worker-a", limit=2)
        assert len(claimed) == 2
        assert all(j.status == "claimed" for j in claimed)
        assert all(j.claimed_by == "worker-a" for j in claimed)


async def test_a_claimed_job_is_not_claimed_twice() -> None:
    org_id = await _org("jobs-exclusive")
    async with session_scope() as s:
        await jobs.enqueue(s, organization_id=org_id, source_kind="policy_version", source_id=1)
    async with session_scope() as s:
        assert len(await jobs.claim(s, worker="worker-a", limit=5)) == 1
    async with session_scope() as s:
        assert await jobs.claim(s, worker="worker-b", limit=5) == []


async def test_reap_returns_stale_claimed_jobs_to_pending() -> None:
    """A crashed container must not strand work forever."""
    org_id = await _org("jobs-reap")
    async with session_scope() as s:
        job = await jobs.enqueue(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        job.status = "claimed"
        job.claimed_by = "dead-worker"
        job.claimed_at = datetime.now(UTC) - timedelta(hours=3)
        await s.flush()
        job_id = int(job.id)

    async with session_scope() as s:
        assert await jobs.reap_stale(s, older_than_minutes=60) == 1
        reaped = (await s.execute(select(PrepJob).where(PrepJob.id == job_id))).scalar_one()
        assert reaped.status == "pending"
        assert reaped.claimed_by is None


async def test_reap_leaves_a_freshly_claimed_job_alone() -> None:
    org_id = await _org("jobs-reap-fresh")
    async with session_scope() as s:
        job = await jobs.enqueue(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        job.status = "claimed"
        job.claimed_at = datetime.now(UTC)
        await s.flush()
    async with session_scope() as s:
        assert await jobs.reap_stale(s, older_than_minutes=60) == 0


async def test_run_once_drives_a_job_to_done(monkeypatch: pytest.MonkeyPatch) -> None:
    org_id = await _org("jobs-cycle")

    async def _embed(session: Any, org_id_: int, *, texts: list[str], **kw: Any) -> EmbedResponse:
        return EmbedResponse(vectors=[[0.01] * 1024 for _ in texts], model="m")

    monkeypatch.setattr(gateway, "embed", _embed)
    async with session_scope() as s:
        # A policy_version source that does not exist resolves to orphaned, which
        # is a terminal state — the job must still close rather than spin.
        await jobs.enqueue(s, organization_id=org_id, source_kind="policy_version", source_id=1)
    async with session_scope() as s:
        stats = await jobs.run_once(s, worker="w1", limit=5)
        assert stats["claimed"] == 1
        assert stats["finished"] == 1
    async with session_scope() as s:
        job = (await s.execute(select(PrepJob))).scalars().one()
        assert job.status == "done"


async def test_a_failing_job_records_its_error_and_increments_attempts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = await _org("jobs-failure")

    async def _boom(session: Any, run: Any) -> Any:
        raise RuntimeError("stage exploded")

    monkeypatch.setattr(jobs.pipeline, "advance", _boom)
    async with session_scope() as s:
        await jobs.enqueue(s, organization_id=org_id, source_kind="policy_version", source_id=1)
    async with session_scope() as s:
        await jobs.run_once(s, worker="w1", limit=5)
    async with session_scope() as s:
        job = (await s.execute(select(PrepJob))).scalars().one()
        assert job.status == "failed"
        assert job.attempts == 1
        assert "stage exploded" in (job.last_error or "")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_prep_jobs.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.prep.jobs'`.

- [ ] **Step 3: Write the job queue**

Create `src/ccf/prep/jobs.py`:

```python
"""Database-backed job queue for preparation runs.

Preparation is too slow for a request cycle — a large PDF is minutes of parsing
and model calls — so runs are queued and drained by a worker process. The queue
lives in Postgres rather than Redis because Concord ships as a single image
against a single database, and ``SELECT ... FOR UPDATE SKIP LOCKED`` gives
exactly-once claiming across concurrent workers without another stateful service.

Crashes are expected: a container killed mid-run leaves its job ``claimed``
forever, so :func:`reap_stale` returns anything held past a deadline to
``pending``. This is safe precisely because every stage is idempotent — the
reaped job resumes at its first incomplete stage and rewrites only that stage's
output.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..models_prep import PrepJob
from . import pipeline

log = structlog.get_logger(__name__)

#: Terminal run states — a job on such a run is finished, not retryable.
_TERMINAL = ("complete", "unsupported", "orphaned")


async def enqueue(
    session: AsyncSession, *, organization_id: int, source_kind: str, source_id: int
) -> PrepJob:
    """Open a run and queue it for the worker."""
    run = await pipeline.create_run(
        session, organization_id=organization_id, source_kind=source_kind, source_id=source_id
    )
    job = PrepJob(
        run_id=run.id, organization_id=organization_id, status="pending", next_stage="parse"
    )
    session.add(job)
    await session.flush()
    log.info("prep.job_enqueued", job_id=job.id, run_id=run.id, source_kind=source_kind)
    return job


async def claim(session: AsyncSession, *, worker: str, limit: int) -> list[PrepJob]:
    """Atomically claim up to ``limit`` pending jobs for this worker."""
    candidates = (
        await session.execute(
            select(PrepJob.id)
            .where(PrepJob.status == "pending")
            .order_by(PrepJob.created_at)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
    ).scalars().all()
    if not candidates:
        return []
    await session.execute(
        update(PrepJob)
        .where(PrepJob.id.in_(candidates))
        .values(status="claimed", claimed_by=worker, claimed_at=datetime.now(UTC))
    )
    await session.flush()
    claimed = (
        await session.execute(select(PrepJob).where(PrepJob.id.in_(candidates)))
    ).scalars().all()
    log.info("prep.jobs_claimed", worker=worker, count=len(claimed))
    return list(claimed)


async def reap_stale(session: AsyncSession, *, older_than_minutes: int) -> int:
    """Return jobs claimed before the deadline to ``pending``. Returns the count."""
    threshold = datetime.now(UTC) - timedelta(minutes=max(1, older_than_minutes))
    result = await session.execute(
        update(PrepJob)
        .where(PrepJob.status == "claimed", PrepJob.claimed_at <= threshold)
        .values(status="pending", claimed_by=None, claimed_at=None)
    )
    count = int(result.rowcount or 0)
    if count:
        log.info("prep.jobs_reaped", count=count, older_than_minutes=older_than_minutes)
    return count


async def run_once(session: AsyncSession, *, worker: str, limit: int) -> dict[str, int]:
    """Claim and drive a batch of jobs. Returns counts for observability."""
    claimed = await claim(session, worker=worker, limit=limit)
    finished = 0
    failed = 0
    for job in claimed:
        run = await pipeline.load_run(session, job.run_id)
        if run is None:
            job.status = "failed"
            job.last_error = f"run {job.run_id} no longer exists"
            failed += 1
            continue
        job.attempts += 1
        try:
            await pipeline.advance(session, run)
        except Exception as exc:  # noqa: BLE001 — a worker must survive any one job
            job.status = "failed"
            job.last_error = str(exc)
            failed += 1
            log.warning("prep.job_failed", job_id=job.id, run_id=run.id, error=str(exc))
            continue

        if run.status in _TERMINAL:
            job.status = "done"
            finished += 1
        elif run.status == "failed":
            job.status = "failed"
            job.last_error = run.error
            failed += 1
        else:
            # Progress made but stages remain — return it for the next cycle.
            job.status = "pending"
            job.next_stage = pipeline.next_stage(run) or "parse"
            job.claimed_by = None
            job.claimed_at = None
    await session.flush()
    return {"claimed": len(claimed), "finished": finished, "failed": failed}
```

- [ ] **Step 4: Add the CLI command**

In `src/ccf/cli.py`, add the import near the other subsystem imports:

```python
from .prep import jobs as prep_jobs
```

and add the command, following the `scheduler_run` pattern already in the file:

```python
@app.command(name="prep-worker")
def prep_worker(
    once: bool = typer.Option(True, "--once/--loop", help="Run one cycle, or loop forever."),
    limit: int | None = typer.Option(None, help="Jobs to claim per cycle."),
    worker: str = typer.Option("prep-worker", help="Worker name recorded on claimed jobs."),
) -> None:
    """Drain queued evidence-preparation jobs."""

    async def _run() -> None:
        settings = get_settings()
        batch = limit if limit is not None else settings.prep_worker_batch_size
        async with session_scope() as session:
            reaped = await prep_jobs.reap_stale(
                session, older_than_minutes=settings.prep_job_stale_after_minutes
            )
        if reaped:
            console.print(f"[yellow]Reaped {reaped} stale job(s)[/yellow]")
        while True:
            async with session_scope() as session:
                stats = await prep_jobs.run_once(session, worker=worker, limit=batch)
            console.print_json(json.dumps(stats))
            if once or stats["claimed"] == 0:
                break

    asyncio.run(_run())
```

- [ ] **Step 5: Add the compose profile and Make target**

In `docker-compose.yml`, add alongside the existing `poller` service:

```yaml
  prep-worker:
    build: .
    container_name: ccf-prep-worker
    profiles: ["prep"]
    depends_on:
      db:       { condition: service_healthy }
      migrator: { condition: service_completed_successfully }
    environment: *ccf_env
    entrypoint: ["sh", "-c"]
    command: ["ccf prep-worker --loop"]
    restart: "unless-stopped"
```

In the `Makefile`, add the target and append `prep-worker` to the `.PHONY` line:

```makefile
prep-worker: ## Drain queued evidence-preparation jobs
	$(COMPOSE) --profile prep up -d prep-worker
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `pytest tests/test_prep_jobs.py -v`
Expected: PASS (7 tests)

- [ ] **Step 7: Verify the CLI registers**

Run: `ccf prep-worker --help`
Expected: the command's help text, listing `--once/--loop`, `--limit`, `--worker`.

- [ ] **Step 8: Verify lint and types**

Run: `ruff check . && mypy src`
Expected: no errors.

- [ ] **Step 9: Commit**

```bash
git add src/ccf/prep/jobs.py src/ccf/cli.py docker-compose.yml Makefile \
        tests/test_prep_jobs.py
git commit -m "feat(prep): add job queue and prep-worker CLI with stale-job reaping"
```

---

### Task 16: Confidence integration, API routes, and documentation

Closes the loop: prepared classifications feed Concord's existing evidence-confidence scorer instead of competing with it, the pipeline gets a REST surface, and the architecture docs stop being wrong.

**Files:**
- Modify: `src/ccf/evidence/confidence.py`
- Create: `src/ccf/api/routes/prep.py`
- Modify: `src/ccf/api/main.py` (register the router)
- Modify: `docs/ARCHITECTURE.md`
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Create: `tests/test_prep_api.py`

**Interfaces:**
- Consumes: everything from Tasks 1–15.
- Produces:
  - `prep_signal(strength: str | None) -> float` in `confidence.py`, folded into `score_evidence`
  - `POST /api/prep/runs` → `{run_id, job_id, status}`
  - `GET /api/prep/runs/{run_id}` → run status with per-stage detail
  - `GET /api/prep/retrieve?control=AC-2&system_id=&limit=` → retrieved units with citations

- [ ] **Step 1: Write the failing test**

Create `tests/test_prep_api.py`:

```python
"""Prep REST surface and confidence-scorer integration."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.db import session_scope
from ccf.evidence.confidence import prep_signal
from ccf.models import Organization
from ccf.models_prep import PrepJob, PrepRun

pytestmark = pytest.mark.usefixtures("fresh_engine")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return int(org.id)


def test_prep_signal_rewards_stronger_evidence_monotonically() -> None:
    assert prep_signal("strong") > prep_signal("moderate") > prep_signal("weak")


def test_prep_signal_is_neutral_when_unclassified() -> None:
    """An unprepared evidence object must not be penalised for lacking a signal."""
    assert prep_signal(None) == 0.0
    assert prep_signal("nonsense") == 0.0


async def test_post_runs_enqueues_and_returns_identifiers() -> None:
    org_id = await _org("prep-api-post")
    async with _client() as client:
        response = await client.post(
            "/api/prep/runs",
            json={"organization_id": org_id, "source_kind": "policy_version", "source_id": 1},
        )
    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "pending"
    async with session_scope() as s:
        assert (
            await s.execute(select(PrepRun).where(PrepRun.id == body["run_id"]))
        ).scalar_one_or_none() is not None
        assert (
            await s.execute(select(PrepJob).where(PrepJob.id == body["job_id"]))
        ).scalar_one_or_none() is not None


async def test_post_runs_rejects_an_unknown_source_kind() -> None:
    org_id = await _org("prep-api-bad-kind")
    async with _client() as client:
        response = await client.post(
            "/api/prep/runs",
            json={"organization_id": org_id, "source_kind": "nonsense", "source_id": 1},
        )
    assert response.status_code == 422


async def test_get_run_reports_every_stage_status() -> None:
    org_id = await _org("prep-api-get")
    async with _client() as client:
        created = (
            await client.post(
                "/api/prep/runs",
                json={"organization_id": org_id, "source_kind": "policy_version", "source_id": 1},
            )
        ).json()
        response = await client.get(f"/api/prep/runs/{created['run_id']}")
    assert response.status_code == 200
    body = response.json()
    assert set(body["stages"]) == {"parse", "screen", "expand", "classify", "embed"}
    assert body["stages"]["parse"] == "pending"


async def test_get_run_returns_404_for_an_unknown_run() -> None:
    async with _client() as client:
        assert (await client.get("/api/prep/runs/999999")).status_code == 404


async def test_retrieve_endpoint_returns_an_empty_list_for_an_empty_corpus() -> None:
    org_id = await _org("prep-api-retrieve")
    async with _client() as client:
        response = await client.get(
            "/api/prep/retrieve", params={"organization_id": org_id, "control": "AC-2"}
        )
    assert response.status_code == 200
    assert response.json()["results"] == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_prep_api.py -v`
Expected: FAIL — `ImportError: cannot import name 'prep_signal' from 'ccf.evidence.confidence'`.

- [ ] **Step 3: Fold the prep signal into the confidence scorer**

In `src/ccf/evidence/confidence.py`, add the function near `band_for`:

```python
#: Contribution of a prepared classification to an evidence object's confidence.
#: Preparation tells us how well a document's own text supports a control, which
#: is independent of provenance — so it adjusts the score rather than replacing
#: any existing signal, and absence is neutral, never a penalty.
_PREP_WEIGHTS = {"strong": 8.0, "moderate": 4.0, "weak": -2.0}


def prep_signal(strength: str | None) -> float:
    """Score contribution from a prepared classification's evidence strength."""
    return _PREP_WEIGHTS.get(strength or "", 0.0)
```

Then, inside `score_evidence`, accept an optional `prep_strength: str | None = None` keyword and add `prep_signal(prep_strength)` to the accumulating score, clamping the total to the function's existing bounds. Follow whatever clamping the function already does — do not introduce a second clamping style.

- [ ] **Step 4: Write the API routes**

Create `src/ccf/api/routes/prep.py`:

```python
"""REST surface for the evidence preparation pipeline.

Preparation is asynchronous by nature, so the write endpoint enqueues and returns
identifiers rather than blocking on a run that may take minutes. Retrieval is
synchronous and read-only.
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ...db import get_session
from ...models_prep import PREP_STAGES
from ...prep import jobs as prep_jobs
from ...prep import pipeline
from ...prep.retriever import retrieve

router = APIRouter(prefix="/api/prep", tags=["prep"])


class PrepRunRequest(BaseModel):
    organization_id: int
    # Constrained here so an unknown kind is a 422 at the edge rather than a
    # failed run discovered minutes later by the worker.
    source_kind: Literal["evidence_version", "policy_version"]
    source_id: int


class PrepRunCreated(BaseModel):
    run_id: int
    job_id: int
    status: str


class PrepRunStatus(BaseModel):
    run_id: int
    status: str
    stages: dict[str, str]
    parser_name: str | None = None
    lines_parsed: int = 0
    lines_above_threshold: int = 0
    units_built: int = 0
    units_classified: int = 0
    units_embedded: int = 0
    error_stage: str | None = None
    error: str | None = None


class RetrievedUnitOut(BaseModel):
    unit_id: int
    content: str
    score: float
    page_numbers: list[int] = Field(default_factory=list)
    section_path: str | None = None
    table_coordinates: dict[str, Any] | None = None
    source_kind: str | None = None
    control_identifiers: list[str] = Field(default_factory=list)
    evidence_strength: str | None = None


class RetrieveResponse(BaseModel):
    control: str
    results: list[RetrievedUnitOut]


@router.post("/runs", response_model=PrepRunCreated, status_code=201)
async def create_prep_run(
    payload: PrepRunRequest, session: AsyncSession = Depends(get_session)
) -> PrepRunCreated:
    """Queue a document for preparation."""
    job = await prep_jobs.enqueue(
        session,
        organization_id=payload.organization_id,
        source_kind=payload.source_kind,
        source_id=payload.source_id,
    )
    return PrepRunCreated(run_id=job.run_id, job_id=job.id, status=job.status)


@router.get("/runs/{run_id}", response_model=PrepRunStatus)
async def get_prep_run(
    run_id: int, session: AsyncSession = Depends(get_session)
) -> PrepRunStatus:
    """Report a run's status, stage by stage."""
    run = await pipeline.load_run(session, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="prep run not found")
    return PrepRunStatus(
        run_id=run.id,
        status=run.status,
        stages={stage: getattr(run, f"stage_{stage}") for stage in PREP_STAGES},
        parser_name=run.parser_name,
        lines_parsed=run.lines_parsed,
        lines_above_threshold=run.lines_above_threshold,
        units_built=run.units_built,
        units_classified=run.units_classified,
        units_embedded=run.units_embedded,
        error_stage=run.error_stage,
        error=run.error,
    )


@router.get("/retrieve", response_model=RetrieveResponse)
async def retrieve_units(
    organization_id: int,
    control: str,
    query: str | None = None,
    system_id: int | None = None,
    limit: int | None = Query(default=None, ge=1, le=50),
    session: AsyncSession = Depends(get_session),
) -> RetrieveResponse:
    """Retrieve prepared evidence supporting a control."""
    found = await retrieve(
        session,
        org_id=organization_id,
        control_identifier=control,
        query_text=query,
        system_id=system_id,
        limit=limit,
    )
    return RetrieveResponse(
        control=control,
        results=[
            RetrievedUnitOut(
                unit_id=unit.unit_id,
                content=unit.content,
                score=unit.score,
                page_numbers=unit.page_numbers,
                section_path=unit.section_path,
                table_coordinates=unit.table_coordinates,
                source_kind=unit.source_kind,
                control_identifiers=unit.control_identifiers,
                evidence_strength=unit.evidence_strength,
            )
            for unit in found
        ],
    )
```

- [ ] **Step 5: Register the router**

In `src/ccf/api/main.py`, import `prep` alongside the other route modules and add `app.include_router(prep.router)` next to the existing `include_router` calls, keeping alphabetical order if the file maintains it.

- [ ] **Step 6: Run tests to verify they pass**

Run: `pytest tests/test_prep_api.py tests/test_evidence_confidence.py -v`
Expected: PASS — the new module's 7 tests plus the existing confidence suite, which must not regress.

- [ ] **Step 7: Update the documentation**

In `docs/ARCHITECTURE.md`, add a subsection under "Compliance operations (subsystems)":

```markdown
- **Evidence preparation** (`/api/prep`, `ccf prep-worker`): uploaded evidence
  and policy versions are parsed into structure-preserving lines (page, heading
  path, table cell), screened for relevance against `ccf.controls` via `ts_rank`,
  expanded into semantically complete units, classified by a governed AI action,
  and embedded into pgvector. Retrieval fuses vector similarity with `ts_rank`
  by reciprocal-rank fusion. Runs are queued in `ccf.prep_jobs` and drained by
  the `prep-worker` compose profile; each stage persists before the next, so a
  failed run resumes at the failed stage.
```

In the same file, correct the "Deferred / planned" list: the entry noting evidence work "needs a worker" is now satisfied for preparation — reword it to scope the remaining gap (expiry reminders and webhooks) rather than deleting the line. Also add `pgvector` to the extensions shown in the Postgres box of the topology diagram, which currently reads `ext: pg_trgm, pgcrypto`.

In `README.md`, add `pgvector/pgvector:pg16` to any statement of the Postgres image requirement, and document the `CCF_PREP_*` settings alongside the existing `CCF_EVIDENCE_*` block.

In `CHANGELOG.md`, add an entry under the current unreleased heading:

```markdown
### Added
- Evidence preparation pipeline: parse (PDF/DOCX/XLSX/PPTX/text), catalog-driven
  relevance screening, context expansion, governed AI classification, and
  pgvector embedding, with hybrid retrieval and a `prep-worker` queue.

### Changed
- Postgres image is now `pgvector/pgvector:pg16` (drop-in for stock PG16).
```

- [ ] **Step 8: Run the full suite**

Run: `pytest -q`
Expected: PASS — the entire suite, confirming nothing regressed across the sixteen tasks.

- [ ] **Step 9: Verify lint and types**

Run: `ruff check . && mypy src`
Expected: no errors.

- [ ] **Step 10: Commit**

```bash
git add src/ccf/evidence/confidence.py src/ccf/api/routes/prep.py \
        src/ccf/api/main.py docs/ARCHITECTURE.md README.md CHANGELOG.md \
        tests/test_prep_api.py
git commit -m "feat(prep): add REST surface, confidence integration, and docs"
```

---

## Deferred, deliberately

Recorded so a reviewer can see these were decided rather than missed:

- **Image OCR** — needs `pytesseract` plus a system Tesseract binary, which changes the container base image. PDF pages with no extractable text are flagged `text_extractable: False` rather than silently dropped.
- **Visio (`.vsdx`)** — rare enough not to earn a dependency in slice one. Raises `UnsupportedMediaType`, which closes the run as `unsupported`.
- **URI-only policy versions** — a `PolicyVersion` with a `uri` and no `body` points at a document Concord does not hold; fetching it is a connector concern, not a parser one. Raises `SourceMissing`.
- **Re-embedding on model change** — `PrepEmbedding.model_name` makes a mixed-model corpus *detectable*, but no backfill command ships in this slice.
- **RLS on prep tables** — org scoping is application-level here, matching how the rest of Concord works today (see ARCHITECTURE.md "Deferred / planned").
