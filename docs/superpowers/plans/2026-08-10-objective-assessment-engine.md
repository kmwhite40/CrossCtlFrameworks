# Objective-Level Assessment Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Evaluate individual 800-53A assessment objectives against evidence retrieved by slice 1, and roll objective verdicts into a *proposed* control finding that an assessor confirms before it becomes a real finding.

**Architecture:** The objectives already exist as sub-clause rows in `ccf.controls` (`control_name IS NULL`), so nothing new is ingested. Per objective: retrieve bounded evidence via slice 1's `retrieve()`, evaluate it with one structured model call, store a proposal with citations. Application code — never the model — rolls objective verdicts into a proposed control finding. On assessor acceptance the proposal projects into the existing `AssessmentControlResult`, so the SAR generator and POA&M auto-creation work unchanged.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy 2.0 async, Alembic, Postgres 16 + pgvector, Typer, structlog, pytest.

**Spec:** [docs/superpowers/specs/2026-08-10-objective-assessment-engine-design.md](../specs/2026-08-10-objective-assessment-engine-design.md)
**Depends on:** slice 1, branch `feat/evidence-prep-spine` (merged or present in the working branch).

## Global Constraints

- **Python:** 3.12, `target-version = "py312"`, `line-length = 100`.
- **Lint:** `ruff check .` selects `["E","F","W","I","UP","B","SIM","N","PL","RUF"]`. Known baseline: **25 pre-existing `PLR0917`** findings in untouched `src/ccf/api/routes/` files — add nothing to it. Note `BLE`/`SLF` are **not** selected, so a `# noqa: BLE001` or `# noqa: SLF001` trips `RUF100`; use a plain comment instead.
- **Types:** `mypy src` runs `strict = true`. Every new function needs complete annotations.
- **Logging:** `from ..logging import get_logger` (this repo's typed structlog wrapper), never `import structlog` directly and never `extra={...}` — reserved `LogRecord` keys like `filename` raise `KeyError`.
- **Tests:** real Postgres, `asyncio_mode = "auto"` — never `@pytest.mark.asyncio`. DB test modules open with `pytestmark = pytest.mark.usefixtures("fresh_engine")`. **Never run two pytest sessions concurrently** — the session fixture drops and recreates the schema.
- **Session:** `autoflush=False` (`src/ccf/db.py:88`). A `DELETE`/`SELECT` issued before pending `session.add()` objects are flushed does not see them — **flush first**. This bit three tasks in slice 1.
- **Schema:** new tables in the `ccf` schema, every one carrying `organization_id`. Migrations are `migrations/versions/00NN_<slug>.py` with `revision`/`down_revision` set explicitly. **Current head is `0054_prep_grants_gin`.**
- **Grants:** every migration adding tables must re-issue `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app` — slice 1 omitted it and needed a follow-up migration.
- **Tenancy:** API endpoints take `Depends(get_principal)` and resolve the org from the principal, following `src/ccf/api/routes/evidence_repo.py`. Never trust a client-supplied `organization_id`. Slice 1 shipped three endpoints that did and it was a cross-tenant leak.
- **Identifiers:** always fold control identifiers through `ccf.prep.screen.normalize_control_identifier` — the catalog mixes `AC-02`, `CP-9` and `AC.L2-3.1.1` forms.
- **AI scope:** a model may only cite evidence that was actually put in front of it. Validate returned citations against the retrieved set, as `ccf.prep.classify` validates control identifiers against screening candidates.
- **Licensing:** independent implementation. Do NOT copy code from the BUSL-licensed ato-bot project.

## A note on this plan's form

Tasks 1–4 carry complete test bodies and complete implementations. **Tasks 5–13 give
each test's name, its docstring, and the exact assertions it must make, but not the
full body** — write the body from the stated assertion, following the conventions in
the neighbouring test files named in each task. This is a deliberate trade-off, not
an oversight: every interface, signature, column name and behavioural rule you need
is specified, and inventing test scaffolding from a precise assertion is safer than
transcribing code that could drift from the models it references.

Where a task says "follow `<file>`", read that file first. The patterns it holds —
transaction boundaries, savepoints, principal handling — were each hardened by a
review cycle in slice 1, and reproducing them from memory is how they get lost.

**Field-name trap:** `ObjectiveEvaluation.confidence` (Task 3) maps onto
`AssessmentObjectiveProposal.model_confidence` (Task 1). The names differ
deliberately — one is a model output, the other a column — so Task 5 must map
explicitly rather than assuming they match.

## File structure

| File | Responsibility |
|---|---|
| `src/ccf/models_assessment_engine.py` | `AssessmentObjectiveProposal`, `AssessmentControlProposal`, `AssessmentJob` + status constants |
| `migrations/versions/0055_assessment_engine.py` | the three tables, indexes, grants |
| `src/ccf/assessment/engine/objectives.py` | `Objective`, `objectives_for` — reads `ccf.controls`, materialises nothing |
| `src/ccf/assessment/engine/evaluate.py` | one structured model call per objective, citation validation |
| `src/ccf/assessment/engine/rollup.py` | objective verdicts → proposed control finding, pure function |
| `src/ccf/assessment/engine/service.py` | run orchestration and `accept_control_proposal` |
| `src/ccf/queue.py` | shared claim / reap / dead-letter helper for both job tables |
| `src/ccf/assessment/engine/jobs.py` | `assessment_jobs` wiring onto the shared helper |
| `src/ccf/api/routes/assessment_engine.py` | REST surface, principal-scoped |

---

### Task 1: Settings, models and migration

**Files:**
- Modify: `src/ccf/config.py`
- Create: `src/ccf/models_assessment_engine.py`
- Create: `migrations/versions/0055_assessment_engine.py`
- Create: `tests/test_assessment_engine_models.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `AssessmentObjectiveProposal`, `AssessmentControlProposal`, `AssessmentJob`; constants `OBJECTIVE_VERDICTS`, `CONTROL_PROPOSAL_FINDINGS`, `PROPOSAL_STATES`, `ASSESSMENT_JOB_STATES`; settings `assessment_engine_enabled`, `assessment_engine_batch_size`, `assessment_engine_max_objectives_per_control`, `assessment_engine_retrieval_limit`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_assessment_engine_models.py`:

```python
"""Assessment-engine proposal tables — round-trip, cascade, and org scoping."""

from __future__ import annotations

import pytest
from sqlalchemy import select, text

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Assessment, Organization, System
from ccf.models_assessment_engine import (
    OBJECTIVE_VERDICTS,
    AssessmentControlProposal,
    AssessmentJob,
    AssessmentObjectiveProposal,
)

pytestmark = pytest.mark.usefixtures("fresh_engine")


async def _assessment(name: str) -> tuple[int, int]:
    """Create an org + system + assessment. Returns (org_id, assessment_id)."""
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name=f"{name}-system")
        s.add(system)
        await s.flush()
        assessment = Assessment(system_id=system.id, name=f"{name}-assessment", kind="self")
        s.add(assessment)
        await s.flush()
        return int(org.id), int(assessment.id)


def test_verdict_vocabulary_is_fixed() -> None:
    assert OBJECTIVE_VERDICTS == (
        "satisfied",
        "not_satisfied",
        "not_applicable",
        "insufficient_evidence",
    )


async def test_control_proposal_defaults_to_draft() -> None:
    org_id, assessment_id = await _assessment("ae-defaults")
    async with session_scope() as s:
        proposal = AssessmentControlProposal(
            organization_id=org_id,
            assessment_id=assessment_id,
            control_identifier="AC-2",
        )
        s.add(proposal)
        await s.flush()
        assert proposal.state == "draft"
        assert proposal.proposed_finding is None
        assert proposal.accepted_at is None


async def test_objective_proposal_records_citations_and_text_hash() -> None:
    org_id, assessment_id = await _assessment("ae-citations")
    async with session_scope() as s:
        control = AssessmentControlProposal(
            organization_id=org_id, assessment_id=assessment_id, control_identifier="AC-2"
        )
        s.add(control)
        await s.flush()
        objective = AssessmentObjectiveProposal(
            organization_id=org_id,
            control_proposal_id=control.id,
            label="AC-02a",
            objective_text="personnel or roles to whom the policy is disseminated are defined;",
            objective_text_sha256="a" * 64,
            verdict="satisfied",
            cited_unit_ids=[11, 12],
            gaps=["no dated review record"],
            contradictions=[],
            rationale="Policy section 3 names the roles.",
            model_confidence=0.81,
        )
        s.add(objective)
        await s.flush()
        assert objective.cited_unit_ids == [11, 12]
        assert objective.gaps == ["no dated review record"]
        assert objective.state == "complete"


async def test_deleting_a_control_proposal_cascades_to_objectives() -> None:
    org_id, assessment_id = await _assessment("ae-cascade")
    async with session_scope() as s:
        control = AssessmentControlProposal(
            organization_id=org_id, assessment_id=assessment_id, control_identifier="CP-9"
        )
        s.add(control)
        await s.flush()
        s.add(
            AssessmentObjectiveProposal(
                organization_id=org_id,
                control_proposal_id=control.id,
                label="CP-09a",
                objective_text="backups are conducted;",
                objective_text_sha256="b" * 64,
                verdict="satisfied",
            )
        )
        await s.flush()
        control_id = int(control.id)

    async with session_scope() as s:
        control = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.id == control_id
                )
            )
        ).scalar_one()
        await s.delete(control)

    async with session_scope() as s:
        remaining = (
            await s.execute(
                select(AssessmentObjectiveProposal).where(
                    AssessmentObjectiveProposal.control_proposal_id == control_id
                )
            )
        ).first()
        assert remaining is None


async def test_assessment_job_defaults() -> None:
    org_id, assessment_id = await _assessment("ae-job")
    async with session_scope() as s:
        control = AssessmentControlProposal(
            organization_id=org_id, assessment_id=assessment_id, control_identifier="AU-2"
        )
        s.add(control)
        await s.flush()
        job = AssessmentJob(organization_id=org_id, control_proposal_id=control.id)
        s.add(job)
        await s.flush()
        assert job.status == "pending"
        assert job.attempts == 0


async def test_server_default_timestamps_are_not_null_in_live_schema() -> None:
    """Slice 1 shipped nullable timestamps the ORM declared non-null. Not again."""
    expected = {
        ("assessment_control_proposals", "created_at"),
        ("assessment_control_proposals", "updated_at"),
        ("assessment_objective_proposals", "created_at"),
        ("assessment_jobs", "created_at"),
        ("assessment_jobs", "updated_at"),
    }
    async with session_scope() as s:
        rows = (
            await s.execute(
                text(
                    "SELECT table_name, column_name, is_nullable "
                    "FROM information_schema.columns "
                    "WHERE table_schema = 'ccf' AND table_name LIKE 'assessment\\_%'"
                )
            )
        ).all()
    nullability = {(t, c): n for t, c, n in rows}
    for key in expected:
        assert nullability.get(key) == "NO", f"{key} must be NOT NULL, got {nullability.get(key)}"


def test_engine_settings_defaults() -> None:
    s = get_settings()
    assert s.assessment_engine_enabled is False
    assert s.assessment_engine_batch_size == 5
    assert s.assessment_engine_max_objectives_per_control == 60
    assert s.assessment_engine_retrieval_limit == 8
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_assessment_engine_models.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.models_assessment_engine'`.

- [ ] **Step 3: Add the settings**

In `src/ccf/config.py`, after the `prep_*` block:

```python
    # ---- Objective-level assessment engine (slice 2)
    # Off by default: like the prep pipeline, this spends money on model calls.
    assessment_engine_enabled: bool = Field(default=False)
    assessment_engine_batch_size: int = Field(default=5)
    # A guard against a pathological catalog row set: no real 800-53A control has
    # anywhere near this many objectives, so exceeding it means the extraction
    # grouped wrongly and should fail loudly rather than fan out model calls.
    assessment_engine_max_objectives_per_control: int = Field(default=60)
    # Passed to ccf.prep.retriever.retrieve as `limit` for each objective.
    assessment_engine_retrieval_limit: int = Field(default=8)
```

- [ ] **Step 4: Write the models**

Create `src/ccf/models_assessment_engine.py`:

```python
"""Objective-level assessment engine — proposal tables.

The engine evaluates individual 800-53A assessment objectives against evidence
retrieved from the preparation pipeline, then rolls the objective verdicts into a
*proposed* control finding. Proposals are inert: nothing here reaches
``AssessmentControlResult`` — and therefore nothing reaches the SAR or an
auto-created POA&M — until an assessor accepts it. A failed control creates real
remediation work, so the model never holds that authority.

The objectives themselves are not stored. They already exist as sub-clause rows in
``ccf.controls`` (``control_name IS NULL``); an objective proposal records the
objective's label and a SHA-256 of its text, so a catalog re-ingest that changes
wording makes a stale proposal detectable rather than silently wrong.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base

#: A model's verdict on one objective.
OBJECTIVE_VERDICTS = ("satisfied", "not_satisfied", "not_applicable", "insufficient_evidence")

#: What the rollup may propose for a control. ``insufficient_evidence`` is
#: proposal-only and is refused by the acceptance path — "the engine could not
#: tell" is not "the control fails", and conflating them manufactures POA&Ms out
#: of missing evidence.
CONTROL_PROPOSAL_FINDINGS = (
    "satisfied",
    "other_than_satisfied",
    "not_applicable",
    "insufficient_evidence",
)

#: Lifecycle of a proposal row. ``stale`` means the catalog objective text changed
#: after evaluation; ``failed`` means the model call could not be completed.
PROPOSAL_STATES = ("draft", "complete", "accepted", "rejected", "failed", "stale")

ASSESSMENT_JOB_STATES = ("pending", "claimed", "done", "failed")


class AssessmentControlProposal(Base):
    """A proposed finding for one control within one assessment."""

    __tablename__ = "assessment_control_proposals"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    assessment_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.assessments.id", ondelete="CASCADE"), index=True
    )
    #: Canonical (unpadded) form, per ccf.prep.screen.normalize_control_identifier.
    control_identifier: Mapped[str] = mapped_column(String(64), index=True)

    state: Mapped[str] = mapped_column(String(16), default="draft", index=True)
    proposed_finding: Mapped[str | None] = mapped_column(String(32))
    rollup_rationale: Mapped[str | None] = mapped_column(Text)
    #: Thresholds in force when this proposal was evaluated, so a later settings
    #: change cannot retroactively reinterpret it.
    config_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    objectives_total: Mapped[int] = mapped_column(Integer, default=0)
    objectives_evaluated: Mapped[int] = mapped_column(Integer, default=0)

    accepted_by: Mapped[str | None] = mapped_column(String(255))
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint(
            "assessment_id", "control_identifier", name="uq_control_proposal_assessment_control"
        ),
        Index("ix_control_proposal_state", "organization_id", "state"),
    )


class AssessmentObjectiveProposal(Base):
    """A model's verdict on one assessment objective, with its citations."""

    __tablename__ = "assessment_objective_proposals"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    control_proposal_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.assessment_control_proposals.id", ondelete="CASCADE"), index=True
    )

    #: e.g. "AC-02a" from ap_acronym, or an ordinal-derived label when sparse.
    label: Mapped[str] = mapped_column(String(64))
    objective_text: Mapped[str] = mapped_column(Text)
    #: Detects a catalog re-ingest that reworded the objective under a stored verdict.
    objective_text_sha256: Mapped[str] = mapped_column(String(64))
    sort_order: Mapped[int] = mapped_column(Integer, default=0)

    state: Mapped[str] = mapped_column(String(16), default="complete")
    verdict: Mapped[str | None] = mapped_column(String(32))
    #: prep_units the model cited. Validated against what retrieval actually
    #: returned — a model cannot cite a passage it was never shown.
    cited_unit_ids: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    #: Ids retrieved and offered to the model, so a reviewer can see what it had.
    retrieved_unit_ids: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    gaps: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    contradictions: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    rationale: Mapped[str | None] = mapped_column(Text)
    model_name: Mapped[str | None] = mapped_column(String(128))
    model_confidence: Mapped[float | None] = mapped_column(Float)
    error: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("control_proposal_id", "label", name="uq_objective_proposal_label"),
        Index("ix_objective_proposal_sort", "control_proposal_id", "sort_order"),
    )


class AssessmentJob(Base):
    """Queue entry driving evaluation of one control proposal."""

    __tablename__ = "assessment_jobs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    control_proposal_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.assessment_control_proposals.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    claimed_by: Mapped[str | None] = mapped_column(String(128))
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    __table_args__ = (Index("ix_assessment_jobs_claimable", "status", "created_at"),)
```

- [ ] **Step 5: Write the migration**

Create `migrations/versions/0055_assessment_engine.py` creating the three tables with columns exactly matching the models above — every `server_default=func.now()` column also `nullable=False` (slice 1 shipped these nullable and needed a fix round), all FKs `ondelete="CASCADE"`, the two unique constraints, and the four indexes. End `upgrade()` with the grant every feature migration re-issues:

```python
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app"
    )
```

Header:

```python
"""Objective-level assessment engine — proposal and job tables.

Proposals are inert until an assessor accepts them, so these tables never feed the
SAR or POA&M creation directly; acceptance projects into assessment_control_results.
Objectives themselves are not stored -- they are read from ccf.controls sub-clause
rows -- so only a label and a SHA-256 of the objective text are kept here.

Revision ID: 0055_assessment_engine
Revises: 0054_prep_grants_gin
Create Date: 2026-08-10
"""
```

with `revision = "0055_assessment_engine"` and `down_revision = "0054_prep_grants_gin"`. `downgrade()` drops the three tables in reverse dependency order.

- [ ] **Step 6: Apply and round-trip the migration**

Run: `.venv/bin/alembic upgrade head && .venv/bin/alembic downgrade -1 && .venv/bin/alembic upgrade head`
Expected: all three succeed. A broken `downgrade()` blocks every future migration.

- [ ] **Step 7: Run tests**

Run: `.venv/bin/pytest tests/test_assessment_engine_models.py -v`
Expected: PASS (7 tests)

- [ ] **Step 8: Verify lint and types**

Run: `.venv/bin/ruff check . && .venv/bin/mypy src`
Expected: no new findings beyond the known 25 `PLR0917`.

- [ ] **Step 9: Commit**

```bash
git add src/ccf/config.py src/ccf/models_assessment_engine.py \
        migrations/versions/0055_assessment_engine.py tests/test_assessment_engine_models.py
git commit -m "feat(assessment): add objective-assessment proposal tables and settings"
```

---

### Task 2: Objective extraction from the catalog

The engine's foundation: the 800-53A objectives are already ingested as sub-clause rows. This task reads them; it materialises nothing.

**Files:**
- Create: `src/ccf/assessment/engine/__init__.py`
- Create: `src/ccf/assessment/engine/objectives.py`
- Create: `tests/test_assessment_objectives.py`

**Interfaces:**
- Consumes: `ccf.models.Control`; `ccf.prep.screen.normalize_control_identifier`.
- Produces:
  - `@dataclass(slots=True) Objective` with `label: str`, `text: str`, `text_sha256: str`, `sort_order: int`
  - `async objectives_for(session: AsyncSession, control_identifier: str) -> list[Objective]`
  - `def objective_sha256(text: str) -> str`
  - `ObjectiveExtractionError(RuntimeError)`

- [ ] **Step 1: Write the failing test**

Create `tests/test_assessment_objectives.py`:

```python
"""Objective extraction — reads ccf.controls sub-clause rows, materialises nothing."""

from __future__ import annotations

import pytest
from sqlalchemy import delete

from ccf.assessment.engine.objectives import (
    ObjectiveExtractionError,
    objective_sha256,
    objectives_for,
)
from ccf.db import session_scope
from ccf.models import Control

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = "ZQ-01"


@pytest.fixture(autouse=True)
async def _catalog_rows():
    """Seed one addressable control plus three sub-clause objective rows.

    Mirrors the real workbook's shape: the parent row carries control_name and a
    bare "Determine if:" objective header; the sub-clause rows carry the actual
    objective text with control_name NULL, and ap_acronym is sparse.
    """
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == _SEQ))
        s.add(
            Control(
                identifier=_SEQ,
                sequence_control=_SEQ,
                control_name="Test Policy And Procedures",
                assessment_objective="Determine if:",
                source_row=1,
            )
        )
        s.add(
            Control(
                identifier=f"{_SEQ}-ao1",
                sequence_control=_SEQ,
                ap_acronym="ZQ-01a",
                assessment_objective="personnel to whom the policy is disseminated are defined;",
                source_row=2,
            )
        )
        s.add(
            Control(
                identifier=f"{_SEQ}-ao2",
                sequence_control=_SEQ,
                assessment_objective="an official to manage the policy is defined;",
                source_row=3,
            )
        )
        s.add(
            Control(
                identifier=f"{_SEQ}-ao3",
                sequence_control=_SEQ,
                assessment_objective="the review frequency is defined;",
                source_row=4,
            )
        )
    yield
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == _SEQ))


async def test_returns_only_sub_clause_rows_in_catalog_order() -> None:
    async with session_scope() as s:
        objectives = await objectives_for(s, _SEQ)
    assert [o.text for o in objectives] == [
        "personnel to whom the policy is disseminated are defined;",
        "an official to manage the policy is defined;",
        "the review frequency is defined;",
    ]
    assert [o.sort_order for o in objectives] == [0, 1, 2]


def test_the_parent_control_row_is_not_an_objective() -> None:
    """The parent row's 'Determine if:' header is a heading, not an objective."""
    # Asserted via the ordering test above: three rows in, three objectives out,
    # and none of them is "Determine if:".


async def test_label_prefers_ap_acronym_then_falls_back_to_ordinal() -> None:
    async with session_scope() as s:
        objectives = await objectives_for(s, _SEQ)
    assert objectives[0].label == "ZQ-01a"
    assert objectives[1].label == "ZQ-01b"
    assert objectives[2].label == "ZQ-01c"


async def test_text_hash_is_stable_and_detects_a_reword() -> None:
    async with session_scope() as s:
        objectives = await objectives_for(s, _SEQ)
    assert objectives[0].text_sha256 == objective_sha256(objectives[0].text)
    assert objective_sha256("a") != objective_sha256("b")


async def test_padded_and_unpadded_identifiers_both_resolve() -> None:
    """The catalog mixes AC-02 and CP-9 forms; both must find the same objectives."""
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == "ZQ-07"))
        s.add(Control(identifier="ZQ-07", sequence_control="ZQ-07", control_name="Padded",
                      assessment_objective="Determine if:", source_row=1))
        s.add(Control(identifier="ZQ-07-ao1", sequence_control="ZQ-07",
                      assessment_objective="a padded-family objective;", source_row=2))
        await s.flush()
        by_padded = await objectives_for(s, "ZQ-07")
        by_unpadded = await objectives_for(s, "ZQ-7")
        await s.execute(delete(Control).where(Control.sequence_control == "ZQ-07"))
    assert len(by_padded) == 1
    assert [o.text for o in by_unpadded] == [o.text for o in by_padded]


async def test_a_control_with_no_sub_clauses_yields_none() -> None:
    async with session_scope() as s:
        assert await objectives_for(s, "ZQ-99-does-not-exist") == []


async def test_absurd_objective_count_raises_rather_than_fanning_out() -> None:
    """A grouping bug must fail loudly, not spawn hundreds of model calls."""
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == "ZQ-08"))
        for n in range(70):
            s.add(
                Control(
                    identifier=f"ZQ-08-ao{n}",
                    sequence_control="ZQ-08",
                    assessment_objective=f"objective number {n};",
                    source_row=n + 1,
                )
            )
        await s.flush()
        with pytest.raises(ObjectiveExtractionError) as exc:
            await objectives_for(s, "ZQ-08")
        await s.execute(delete(Control).where(Control.sequence_control == "ZQ-08"))
    assert "70" in str(exc.value)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_assessment_objectives.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.assessment.engine'`.

- [ ] **Step 3: Write the extraction module**

Create `src/ccf/assessment/engine/__init__.py`:

```python
"""Objective-level assessment engine — evaluate 800-53A objectives against evidence."""
```

Create `src/ccf/assessment/engine/objectives.py`:

```python
"""Read a control's assessment objectives from the catalog Concord already ingests.

The 800-53A objectives are not a separate dataset. They are sub-clause rows in
``ccf.controls``: ``control_name IS NULL``, ``assessment_objective`` carrying the
objective text, grouped by ``sequence_control``. They are the same rows the
preparation pipeline's screen stage deliberately excludes, because they are not
controls anyone can cite -- which is exactly what makes them objectives.

Nothing is materialised. A proposal stores a label and a SHA-256 of the objective
text, so a catalog re-ingest that rewords an objective makes a stored verdict
detectable as stale rather than silently wrong.
"""

from __future__ import annotations

import hashlib
import string
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...config import get_settings
from ...models import Control
from ...prep.screen import normalize_control_identifier


class ObjectiveExtractionError(RuntimeError):
    """The catalog rows for a control are not a plausible objective set."""


@dataclass(slots=True)
class Objective:
    """One assessment objective, as read from the catalog."""

    label: str
    text: str
    text_sha256: str
    sort_order: int


def objective_sha256(text: str) -> str:
    """Hash an objective's text so a later reword is detectable."""
    return hashlib.sha256(text.strip().encode("utf-8")).hexdigest()


def _ordinal_label(control_identifier: str, index: int) -> str:
    """Derive ``AC-02a``-style labels when ``ap_acronym`` is absent.

    ``ap_acronym`` is populated on the first sub-clause row and sparse thereafter
    in the real workbook, so most objectives need a derived label. Past 26 the
    suffix doubles (``aa``, ``ab``) rather than wrapping, so labels stay unique.
    """
    letters = string.ascii_lowercase
    if index < len(letters):
        suffix = letters[index]
    else:
        suffix = letters[index // len(letters) - 1] + letters[index % len(letters)]
    return f"{control_identifier}{suffix}"


async def objectives_for(session: AsyncSession, control_identifier: str) -> list[Objective]:
    """Return a control's assessment objectives in catalog order."""
    canonical = normalize_control_identifier(control_identifier)
    rows = (
        await session.execute(
            select(Control)
            .where(
                Control.control_name.is_(None),
                Control.assessment_objective.is_not(None),
            )
            .order_by(Control.source_row, Control.id)
        )
    ).scalars().all()

    matching = [r for r in rows if normalize_control_identifier(r.sequence_control or "") == canonical]

    limit = get_settings().assessment_engine_max_objectives_per_control
    if len(matching) > limit:
        raise ObjectiveExtractionError(
            f"control {control_identifier} yielded {len(matching)} objectives, "
            f"above the {limit} guard -- extraction almost certainly grouped wrongly"
        )

    objectives: list[Objective] = []
    for index, row in enumerate(matching):
        text = (row.assessment_objective or "").strip()
        if not text:
            continue
        label = row.ap_acronym or _ordinal_label(canonical, index)
        objectives.append(
            Objective(
                label=label,
                text=text,
                text_sha256=objective_sha256(text),
                sort_order=index,
            )
        )
    return objectives
```

**Note on the filter:** `sequence_control` is compared through `normalize_control_identifier` in Python rather than in SQL, because the catalog's stored forms are inconsistent (`AC-02` vs `CP-9`) and no SQL predicate folds them. If profiling later shows this scan matters, add a normalized generated column — do not hand-roll the folding in SQL, where it would drift from `screen.py`.

- [ ] **Step 4: Run tests**

Run: `.venv/bin/pytest tests/test_assessment_objectives.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Verify lint and types**

Run: `.venv/bin/ruff check . && .venv/bin/mypy src`
Expected: clean beyond the known baseline. `ObjectiveExtractionError` ends in `Error`, so no `N818` suppression is needed.

- [ ] **Step 6: Commit**

```bash
git add src/ccf/assessment/engine tests/test_assessment_objectives.py
git commit -m "feat(assessment): read 800-53A objectives from the ingested catalog"
```

---

### Task 3: Per-objective evaluation

The one place a model reasons. Its scope is bounded three ways: it sees a single objective, only the passages retrieval surfaced for that objective, and it may cite nothing else.

**Files:**
- Create: `src/ccf/assessment/engine/evaluate.py`
- Create: `tests/test_assessment_evaluate.py`

**Interfaces:**
- Consumes: `Objective` (Task 2); `ccf.prep.retriever.retrieve` and `RetrievedUnit`; `ccf.ai.gateway.generate_structured`.
- Produces:
  - `@dataclass(slots=True) ObjectiveEvaluation` with `verdict: str`, `cited_unit_ids: list[int]`, `retrieved_unit_ids: list[int]`, `gaps: list[str]`, `contradictions: list[str]`, `rationale: str`, `confidence: float`, `model_name: str | None`
  - `EVALUATION_SCHEMA: dict[str, Any]`
  - `def build_prompt(objective_text: str, units: list[RetrievedUnit]) -> str`
  - `async evaluate_objective(session, *, org_id: int, control_identifier: str, objective: Objective, system_id: int | None) -> ObjectiveEvaluation`

- [ ] **Step 1: Write the failing test**

Create `tests/test_assessment_evaluate.py`:

```python
"""Per-objective evaluation — bounded scope, validated citations, honest gaps."""

from __future__ import annotations

from typing import Any

import pytest

from ccf.ai import gateway
from ccf.assessment.engine.evaluate import (
    EVALUATION_SCHEMA,
    build_prompt,
    evaluate_objective,
)
from ccf.assessment.engine.objectives import Objective, objective_sha256
from ccf.db import session_scope
from ccf.models import Organization
from ccf.prep import retriever
from ccf.prep.retriever import RetrievedUnit

pytestmark = pytest.mark.usefixtures("fresh_engine")


def _objective(text: str = "multifactor authentication is implemented;") -> Objective:
    return Objective(label="IA-2a", text=text, text_sha256=objective_sha256(text), sort_order=0)


def _unit(unit_id: int, content: str) -> RetrievedUnit:
    return RetrievedUnit(
        unit_id=unit_id, content=content, score=0.5, page_numbers=[3],
        section_path="Access Control", table_coordinates=None, source_kind="evidence_version",
        control_identifiers=["IA-2"], evidence_strength="strong",
        lexical_rank=1, vector_rank=1,
    )


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return int(org.id)


def test_schema_constrains_the_verdict_vocabulary() -> None:
    assert EVALUATION_SCHEMA["properties"]["verdict"]["enum"] == [
        "satisfied", "not_satisfied", "not_applicable", "insufficient_evidence",
    ]


def test_prompt_contains_the_objective_and_numbered_passages() -> None:
    prompt = build_prompt("MFA is implemented;", [_unit(7, "Admins use MFA."), _unit(9, "x")])
    assert "MFA is implemented;" in prompt
    assert "[7]" in prompt and "[9]" in prompt


def test_prompt_states_the_model_is_not_deciding_the_finding() -> None:
    prompt = build_prompt("MFA is implemented;", [_unit(7, "Admins use MFA.")])
    lowered = prompt.lower()
    assert "assessor" in lowered
    assert "not" in lowered


async def test_a_citation_outside_the_retrieved_set_is_dropped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A model may not cite a passage it was never shown."""
    org_id = await _org("ae-eval-citation")

    async def _fake_retrieve(*args: Any, **kwargs: Any) -> list[RetrievedUnit]:
        return [_unit(7, "Administrators authenticate with MFA.")]

    async def _fake_structured(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "verdict": "satisfied",
            "cited_unit_ids": [7, 999],
            "gaps": [],
            "contradictions": [],
            "rationale": "Section 2 requires MFA.",
            "confidence": 0.9,
        }

    monkeypatch.setattr(retriever, "retrieve", _fake_retrieve)
    monkeypatch.setattr(gateway, "generate_structured", _fake_structured)
    async with session_scope() as s:
        result = await evaluate_objective(
            s, org_id=org_id, control_identifier="IA-2",
            objective=_objective(), system_id=None,
        )
    assert result.cited_unit_ids == [7]
    assert result.retrieved_unit_ids == [7]


async def test_no_retrieved_evidence_yields_insufficient_without_a_model_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retrieval finding nothing is an honest answer, not an error -- and not
    worth a model call whose input would be empty."""
    org_id = await _org("ae-eval-empty")

    async def _fake_retrieve(*args: Any, **kwargs: Any) -> list[RetrievedUnit]:
        return []

    monkeypatch.setattr(retriever, "retrieve", _fake_retrieve)
    # No gateway patch: any model call would raise.
    async with session_scope() as s:
        result = await evaluate_objective(
            s, org_id=org_id, control_identifier="IA-2",
            objective=_objective(), system_id=None,
        )
    assert result.verdict == "insufficient_evidence"
    assert result.cited_unit_ids == []
    assert any("no evidence" in g.lower() for g in result.gaps)


async def test_objective_text_is_passed_to_retrieval_as_the_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The objective text is a far better query than a bare control id."""
    org_id = await _org("ae-eval-query")
    seen: dict[str, Any] = {}

    async def _fake_retrieve(session: Any, **kwargs: Any) -> list[RetrievedUnit]:
        seen.update(kwargs)
        return [_unit(7, "Admins use MFA.")]

    async def _fake_structured(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {"verdict": "satisfied", "cited_unit_ids": [7], "gaps": [],
                "contradictions": [], "rationale": "ok", "confidence": 0.8}

    monkeypatch.setattr(retriever, "retrieve", _fake_retrieve)
    monkeypatch.setattr(gateway, "generate_structured", _fake_structured)
    async with session_scope() as s:
        await evaluate_objective(
            s, org_id=org_id, control_identifier="IA-2",
            objective=_objective("multifactor authentication is implemented;"),
            system_id=None,
        )
    assert seen["query_text"] == "multifactor authentication is implemented;"
    assert seen["control_identifier"] == "IA-2"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_assessment_evaluate.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.assessment.engine.evaluate'`.

- [ ] **Step 3: Write the evaluation module**

Create `src/ccf/assessment/engine/evaluate.py`:

```python
"""Evaluate one assessment objective against retrieved evidence.

This is the only place in the engine where a model reasons, and its scope is
bounded three ways: it sees a single objective, only the passages retrieval
surfaced for that objective, and it may cite nothing outside that set. What the
verdict *means* for the control is decided later by application code, and whether
it becomes a finding at all is decided by an assessor.

Retrieval finding nothing is not an error. It yields ``insufficient_evidence``
with an explicit gap, which is the honest answer and the one an assessor needs --
and it skips the model call entirely, since there would be nothing to reason over.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ...ai import gateway
from ...config import get_settings
from ...logging import get_logger
from ...prep import retriever
from ...prep.retriever import RetrievedUnit
from .objectives import Objective

log = get_logger(__name__)

PURPOSE = "assessment.evaluate_objective"

EVALUATION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "verdict": {
            "type": "string",
            "enum": ["satisfied", "not_satisfied", "not_applicable", "insufficient_evidence"],
        },
        "cited_unit_ids": {
            "type": "array",
            "items": {"type": "integer"},
            "description": "Passage ids that support the verdict, from those offered.",
        },
        "gaps": {"type": "array", "items": {"type": "string"}},
        "contradictions": {"type": "array", "items": {"type": "string"}},
        "rationale": {"type": "string"},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
    },
    "required": ["verdict", "cited_unit_ids", "rationale", "confidence"],
    "additionalProperties": False,
}

_SYSTEM_PROMPT = (
    "You evaluate a single NIST SP 800-53A assessment objective against evidence "
    "passages drawn from an organization's own documentation. You are not deciding "
    "whether the control passes and you are not writing an assessment finding -- an "
    "assessor does that, later, using your analysis. Judge only whether the passages "
    "you are shown demonstrate that this one objective is met. Cite only the passage "
    "ids you were given. If the evidence does not settle the question, say "
    "insufficient_evidence rather than guessing."
)


@dataclass(slots=True)
class ObjectiveEvaluation:
    """One objective's verdict, with everything needed to review it."""

    verdict: str
    rationale: str
    confidence: float
    cited_unit_ids: list[int] = field(default_factory=list)
    retrieved_unit_ids: list[int] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)
    model_name: str | None = None


def build_prompt(objective_text: str, units: list[RetrievedUnit]) -> str:
    """Build the evaluation prompt for one objective and its retrieved passages."""
    passages = "\n\n".join(
        f"[{u.unit_id}] (page {', '.join(str(p) for p in u.page_numbers) or 'n/a'}"
        f"{f', {u.section_path}' if u.section_path else ''})\n{u.content}"
        for u in units
    )
    return (
        f"Assessment objective:\n{objective_text}\n\n"
        f"Evidence passages:\n{passages}\n\n"
        "Decide whether these passages demonstrate that the objective is met. "
        "Cite the passage ids that support your verdict. List any gap that keeps "
        "the objective from being fully demonstrated, and any passage that "
        "contradicts another. This is analysis for an assessor, not a finding."
    )


async def evaluate_objective(
    session: AsyncSession,
    *,
    org_id: int,
    control_identifier: str,
    objective: Objective,
    system_id: int | None,
) -> ObjectiveEvaluation:
    """Retrieve evidence for one objective and evaluate it."""
    settings = get_settings()
    units = await retriever.retrieve(
        session,
        org_id=org_id,
        control_identifier=control_identifier,
        query_text=objective.text,
        system_id=system_id,
        limit=settings.assessment_engine_retrieval_limit,
    )
    retrieved_ids = [u.unit_id for u in units]

    if not units:
        log.info(
            "assessment.objective_no_evidence",
            control_identifier=control_identifier,
            label=objective.label,
        )
        return ObjectiveEvaluation(
            verdict="insufficient_evidence",
            rationale="No prepared evidence was retrieved for this objective.",
            confidence=0.0,
            retrieved_unit_ids=[],
            gaps=["No evidence retrieved -- nothing in the prepared corpus matched."],
        )

    data = await gateway.generate_structured(
        session,
        org_id,
        prompt=build_prompt(objective.text, units),
        schema=EVALUATION_SCHEMA,
        purpose=PURPOSE,
        system=_SYSTEM_PROMPT,
    )

    # A model may only cite passages it was actually shown.
    offered = set(retrieved_ids)
    cited = [int(c) for c in data.get("cited_unit_ids", []) if int(c) in offered]

    return ObjectiveEvaluation(
        verdict=str(data["verdict"]),
        rationale=str(data.get("rationale", "")),
        confidence=float(data.get("confidence", 0.0)),
        cited_unit_ids=cited,
        retrieved_unit_ids=retrieved_ids,
        gaps=[str(g) for g in data.get("gaps", [])],
        contradictions=[str(c) for c in data.get("contradictions", [])],
    )
```

- [ ] **Step 4: Run tests**

Run: `.venv/bin/pytest tests/test_assessment_evaluate.py -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Verify lint and types**

Run: `.venv/bin/ruff check . && .venv/bin/mypy src`
Expected: clean beyond the known baseline.

- [ ] **Step 6: Commit**

```bash
git add src/ccf/assessment/engine/evaluate.py tests/test_assessment_evaluate.py
git commit -m "feat(assessment): evaluate one objective against retrieved evidence"
```

---

### Task 4: The rollup policy

Application code decides what objective verdicts mean for a control. A pure function, so it is trivially testable and impossible for a model to influence.

**Files:**
- Create: `src/ccf/assessment/engine/rollup.py`
- Create: `tests/test_assessment_rollup.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `@dataclass(slots=True) Rollup` with `finding: str`, `rationale: str`; `def roll_up(verdicts: list[str]) -> Rollup`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_assessment_rollup.py`:

```python
"""Rollup policy — application code, not model output, decides the control finding."""

from __future__ import annotations

import pytest

from ccf.assessment.engine.rollup import roll_up
from ccf.models_assessment_engine import CONTROL_PROPOSAL_FINDINGS


def test_all_satisfied_proposes_satisfied() -> None:
    assert roll_up(["satisfied", "satisfied"]).finding == "satisfied"


def test_any_not_satisfied_proposes_other_than_satisfied() -> None:
    """800-53A is strict: a control is satisfied only when every objective is."""
    assert roll_up(["satisfied", "not_satisfied", "satisfied"]).finding == "other_than_satisfied"


def test_not_satisfied_outranks_insufficient() -> None:
    """A demonstrated failure is a stronger signal than an unanswered question."""
    result = roll_up(["not_satisfied", "insufficient_evidence"])
    assert result.finding == "other_than_satisfied"


def test_insufficient_without_failure_proposes_insufficient() -> None:
    assert roll_up(["satisfied", "insufficient_evidence"]).finding == "insufficient_evidence"


def test_not_applicable_objectives_are_ignored_when_others_are_satisfied() -> None:
    assert roll_up(["satisfied", "not_applicable"]).finding == "satisfied"


def test_all_not_applicable_proposes_not_applicable() -> None:
    assert roll_up(["not_applicable", "not_applicable"]).finding == "not_applicable"


def test_no_objectives_proposes_insufficient_not_satisfied() -> None:
    """A control with no objectives must never be proposed as passing."""
    assert roll_up([]).finding == "insufficient_evidence"


def test_every_outcome_is_in_the_declared_vocabulary() -> None:
    for verdicts in ([], ["satisfied"], ["not_satisfied"], ["not_applicable"],
                     ["insufficient_evidence"]):
        assert roll_up(verdicts).finding in CONTROL_PROPOSAL_FINDINGS


def test_rationale_names_the_deciding_counts() -> None:
    rationale = roll_up(["satisfied", "not_satisfied", "insufficient_evidence"]).rationale
    assert "not_satisfied" in rationale


def test_an_unknown_verdict_raises_rather_than_being_ignored() -> None:
    """Silently dropping an unrecognised verdict could turn a failure into a pass."""
    with pytest.raises(ValueError, match="unknown objective verdict"):
        roll_up(["satisfied", "probably_fine"])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_assessment_rollup.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.assessment.engine.rollup'`.

- [ ] **Step 3: Write the rollup**

Create `src/ccf/assessment/engine/rollup.py`:

```python
"""Roll objective verdicts into a proposed control finding.

Deliberately a pure function over a list of verdict strings: the policy that turns
analysis into a proposed finding is application code, and a model cannot reach it.

NIST SP 800-53A semantics are strict -- a control is satisfied only when every one
of its objectives is satisfied -- so the default policy is unanimity, not a
threshold. ``insufficient_evidence`` is a proposal-only outcome: it means the
engine could not tell, which is different from the control failing, and conflating
them would manufacture POA&Ms out of missing evidence.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...models_assessment_engine import OBJECTIVE_VERDICTS


@dataclass(slots=True)
class Rollup:
    """A proposed control finding and why the policy reached it."""

    finding: str
    rationale: str


def roll_up(verdicts: list[str]) -> Rollup:
    """Apply the assessment policy to one control's objective verdicts."""
    unknown = [v for v in verdicts if v not in OBJECTIVE_VERDICTS]
    if unknown:
        raise ValueError(f"unknown objective verdict(s): {sorted(set(unknown))}")

    total = len(verdicts)
    counts = {v: verdicts.count(v) for v in OBJECTIVE_VERDICTS}
    summary = (
        f"{total} objective(s): "
        + ", ".join(f"{n} {v}" for v, n in counts.items() if n)
        if total
        else "0 objectives"
    )

    if total == 0:
        return Rollup(
            finding="insufficient_evidence",
            rationale=f"{summary} -- a control with no objectives cannot be proposed as satisfied.",
        )
    if counts["not_satisfied"]:
        return Rollup(
            finding="other_than_satisfied",
            rationale=f"{summary} -- 800-53A requires every objective to be satisfied.",
        )
    if counts["insufficient_evidence"]:
        return Rollup(
            finding="insufficient_evidence",
            rationale=f"{summary} -- evidence did not settle every objective.",
        )
    if counts["not_applicable"] == total:
        return Rollup(finding="not_applicable", rationale=f"{summary} -- all objectives N/A.")
    return Rollup(finding="satisfied", rationale=f"{summary} -- every applicable objective met.")
```

- [ ] **Step 4: Run tests**

Run: `.venv/bin/pytest tests/test_assessment_rollup.py -v`
Expected: PASS (10 tests)

- [ ] **Step 5: Verify lint and types**

Run: `.venv/bin/ruff check . && .venv/bin/mypy src`
Expected: clean beyond the known baseline.

- [ ] **Step 6: Commit**

```bash
git add src/ccf/assessment/engine/rollup.py tests/test_assessment_rollup.py
git commit -m "feat(assessment): add the objective-to-control rollup policy"
```

---

### Task 5: Control-proposal orchestration

Evaluates every objective of one control and rolls them up. One pathological objective must not fail the control.

**Files:**
- Create: `src/ccf/assessment/engine/service.py`
- Create: `tests/test_assessment_service.py`

**Interfaces:**
- Consumes: `objectives_for` (T2), `evaluate_objective`/`ObjectiveEvaluation` (T3), `roll_up` (T4), models (T1).
- Produces:
  - `async open_control_proposal(session, *, assessment_id: int, control_identifier: str) -> AssessmentControlProposal` — derives `organization_id` from `Assessment → System → Organization`, never from a caller argument; normalises the identifier; idempotent on `(assessment_id, control_identifier)`.
  - `async evaluate_control_proposal(session, proposal: AssessmentControlProposal) -> AssessmentControlProposal`
  - `ProposalError(RuntimeError)`

- [ ] **Step 1: Write the failing test**

Create `tests/test_assessment_service.py` with these tests (fixtures follow `tests/test_assessment_objectives.py`'s catalog seeding and `tests/test_assessment_engine_models.py`'s `_assessment` helper; monkeypatch `ccf.assessment.engine.service.evaluate_objective`):

```python
async def test_open_derives_org_from_the_assessment_not_an_argument() -> None:
    """A caller cannot name someone else's organization."""
    # open_control_proposal takes no organization_id parameter at all; assert the
    # created proposal's organization_id equals the assessment's system's org.

async def test_open_is_idempotent_on_assessment_and_control() -> None:
    # Calling twice returns the same row, not a duplicate (unique constraint).

async def test_open_normalizes_the_control_identifier() -> None:
    # open(..., "ZQ-01") and open(..., "ZQ-1") resolve to one proposal.

async def test_evaluate_writes_one_objective_proposal_per_catalog_objective() -> None:
    # 3 seeded sub-clause rows -> 3 AssessmentObjectiveProposal rows, ordered,
    # with labels ZQ-01a/b/c and objectives_total == objectives_evaluated == 3.

async def test_evaluate_rolls_up_and_stores_the_config_snapshot() -> None:
    # verdicts satisfied/satisfied/not_satisfied -> proposed_finding
    # "other_than_satisfied"; config_snapshot carries retrieval_limit.

async def test_one_failing_objective_does_not_fail_the_control() -> None:
    """A per-objective savepoint: objective 2 raises, 1 and 3 still persist."""
    # objective 2's proposal is state="failed" with error set; the control
    # proposal still reaches state="complete" with a rolled-up finding derived
    # from the objectives that did evaluate.

async def test_evaluate_is_idempotent_on_rerun() -> None:
    # Re-running deletes prior objective proposals first -- 3 rows, not 6.

async def test_a_reworded_objective_marks_the_proposal_stale() -> None:
    # Evaluate, then change the catalog row's assessment_objective text, then
    # re-check: the stored objective proposal's text_sha256 no longer matches
    # and the control proposal is marked state="stale".
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_assessment_service.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.assessment.engine.service'`.

- [ ] **Step 3: Implement**

`open_control_proposal` resolves the org with a single joined query:

```python
row = (
    await session.execute(
        select(System.organization_id, System.id)
        .join(Assessment, Assessment.system_id == System.id)
        .where(Assessment.id == assessment_id)
    )
).first()
if row is None:
    raise ProposalError(f"assessment {assessment_id} not found")
organization_id, system_id = int(row[0]), int(row[1])
```

`evaluate_control_proposal`:
1. Set `state="draft"`, snapshot `{"retrieval_limit": settings.assessment_engine_retrieval_limit, "max_objectives": settings.assessment_engine_max_objectives_per_control}` into `config_snapshot`.
2. **Flush, then delete** prior `AssessmentObjectiveProposal` rows for this proposal — `autoflush=False` means a delete issued before the flush matches nothing, the bug that bit slice 1's classify and embed stages. Follow `src/ccf/prep/classify.py`'s comment and ordering.
3. `objectives = await objectives_for(session, proposal.control_identifier)`; set `objectives_total`.
4. Per objective, inside `async with session.begin_nested():`, call `evaluate_objective` and add a proposal row. On exception, roll back that savepoint and add a row with `state="failed"`, `error=str(exc)`, `verdict=None`; log at warning with `control_identifier` and `label`.
5. Roll up **only** the objectives that produced a verdict; set `proposed_finding`, `rollup_rationale`, `objectives_evaluated`, `state="complete"`.

Add `async check_staleness(session, proposal) -> bool` recomputing each stored objective's `objective_text_sha256` against the live catalog, setting `state="stale"` on mismatch.

- [ ] **Step 4–6: Run tests, verify lint/types, commit**

```bash
.venv/bin/pytest tests/test_assessment_service.py -v      # 8 pass
.venv/bin/ruff check . && .venv/bin/mypy src
git add src/ccf/assessment/engine/service.py tests/test_assessment_service.py
git commit -m "feat(assessment): orchestrate per-control objective evaluation"
```

---

### Task 6: Acceptance — projection into `AssessmentControlResult`

The human gate. Until this runs, nothing the engine produced can reach a SAR or a POA&M.

**Files:**
- Modify: `src/ccf/assessment/engine/service.py`
- Create: `tests/test_assessment_acceptance.py`

**Interfaces:**
- Consumes: T1 models, `AssessmentControlResult` from `ccf.models`.
- Produces: `async accept_control_proposal(session, proposal_id: int, *, accepted_by: str) -> AssessmentControlResult`; `AcceptanceRefused(ProposalError)`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_assessment_acceptance.py`:

```python
async def test_acceptance_projects_objectives_into_the_existing_shape() -> None:
    """objective_findings must match what ccf.assessment.sar already renders."""
    # Each entry is exactly {"label": str, "text": str, "finding": str} -- the
    # same keys ccf/assessment/seed.py::_objective_findings produces for CMMC.

async def test_acceptance_sets_the_control_finding() -> None:
    # AssessmentControlResult.finding == proposal.proposed_finding.

async def test_acceptance_records_actor_and_timestamp() -> None:
    # proposal.state == "accepted", accepted_by set, accepted_at not None.

async def test_an_insufficient_evidence_proposal_cannot_be_accepted() -> None:
    """'The engine could not tell' must never become a finding."""
    # raises AcceptanceRefused; no AssessmentControlResult row is created.

async def test_a_stale_proposal_cannot_be_accepted() -> None:
    # raises AcceptanceRefused.

async def test_accepting_twice_does_not_duplicate_the_result_row() -> None:
    # uq_assess_ctrl on (assessment_id, control_id) -- second call updates.

async def test_the_generated_sar_renders_the_projected_objectives() -> None:
    """The whole point of reusing AssessmentControlResult."""
    # Call ccf.assessment.sar.generate_sar_docx over the assessment and assert
    # the objective label and text appear in the document body.
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_assessment_acceptance.py -v`
Expected: FAIL — `ImportError: cannot import name 'accept_control_proposal'`.

- [ ] **Step 3: Implement**

Refuse when `proposal.proposed_finding == "insufficient_evidence"`, when `state != "complete"`, or when `state == "stale"`. Otherwise upsert one `AssessmentControlResult` keyed `(assessment_id, control_id=proposal.control_identifier)` — that pair carries `UniqueConstraint("assessment_id", "control_id", name="uq_assess_ctrl")`, so re-acceptance must update rather than insert. Write:

```python
result.objective_findings = [
    {"label": o.label, "text": o.objective_text, "finding": o.verdict or "not_assessed"}
    for o in objectives  # ordered by sort_order
]
result.finding = proposal.proposed_finding
result.nist_id = proposal.control_identifier
result.assessor_note = proposal.rollup_rationale
result.reviewed = True
result.reviewer = accepted_by
```

Then set `proposal.state = "accepted"`, `accepted_by`, `accepted_at = datetime.now(UTC)`.

**Read `src/ccf/assessment/sar.py` before writing the projection** and confirm the keys it reads from `objective_findings` — if they differ from `{label, text, finding}`, match the renderer, and say so in your report.

- [ ] **Step 4–6: Run tests, verify lint/types, commit**

```bash
.venv/bin/pytest tests/test_assessment_acceptance.py -v   # 7 pass
.venv/bin/ruff check . && .venv/bin/mypy src
git add src/ccf/assessment/engine/service.py tests/test_assessment_acceptance.py
git commit -m "feat(assessment): accept a proposal into the existing result store"
```

---

### Task 7: Shared queue helper

Slice 1's queue semantics cost three fix rounds and an adversarial review. Extract them once so two queues cannot drift.

**Files:**
- Create: `src/ccf/queue.py`
- Create: `tests/test_queue_helper.py`

**Interfaces:**
- Consumes: nothing.
- Produces, generic over a job model class with the columns `id, organization_id, status, attempts, claimed_at, claimed_by, last_error, created_at`:
  - `async claim_jobs(session, model, *, worker: str, limit: int) -> list[Any]`
  - `async reap_stale_jobs(session, model, *, older_than_minutes: int, max_attempts: int) -> dict[str, int]` returning `{"requeued": n, "dead_lettered": n}`
  - `DEAD_LETTER_REASON: str`

- [ ] **Step 1: Write the failing test**

Create `tests/test_queue_helper.py`, exercising the helper against **`PrepJob`** (an existing table, so no new schema is needed to test it):

```python
async def test_claim_marks_jobs_and_records_the_worker() -> None: ...
async def test_a_claimed_job_is_not_claimed_twice() -> None: ...
async def test_claim_increments_attempts_atomically() -> None: ...
async def test_reap_returns_stale_claimed_jobs_to_pending() -> None: ...
async def test_reap_leaves_a_freshly_claimed_job_alone() -> None: ...
async def test_reap_dead_letters_at_the_attempt_cap_with_a_legible_error() -> None: ...
async def test_two_concurrent_claimers_never_take_the_same_job() -> None:
    """SKIP LOCKED under real contention -- two sessions, asyncio.gather, 20 jobs,
    assert zero overlap and zero lost."""
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_queue_helper.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.queue'`.

- [ ] **Step 3: Implement**

Lift the logic verbatim from `src/ccf/prep/jobs.py`'s `claim` and `reap_stale`, parameterised by model class. Preserve exactly: `SELECT ... FOR UPDATE SKIP LOCKED`, the atomic `UPDATE` that sets `status`, `claimed_by`, `claimed_at` **and** increments `attempts` in one statement, the `attempts < cap` / `attempts >= cap` split for requeue vs dead-letter, and `last_error` truncation. Docstring must record why each property exists — a future reader must not "simplify" any of them away.

- [ ] **Step 4–6: Run tests, verify lint/types, commit**

```bash
.venv/bin/pytest tests/test_queue_helper.py -v            # 7 pass
.venv/bin/ruff check . && .venv/bin/mypy src
git add src/ccf/queue.py tests/test_queue_helper.py
git commit -m "feat(queue): extract the shared claim/reap/dead-letter helper"
```

---

### Task 8: `assessment_jobs` on the shared helper

**Files:**
- Create: `src/ccf/assessment/engine/jobs.py`
- Create: `tests/test_assessment_jobs.py`

**Interfaces:**
- Consumes: `ccf.queue` (T7), `service` (T5/T6), `AssessmentJob` (T1).
- Produces: `async enqueue_control(session, *, assessment_id: int, control_identifier: str) -> AssessmentJob`; `async run_once(session, *, worker: str, limit: int) -> dict[str, int]`; `async reap(session) -> dict[str, int]`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_assessment_jobs.py`. Include an autouse isolation fixture scoped to this file's own `aejobs-%` organizations — the queue is global and the schema resets per session, not per test, which broke slice 1's job tests. Tests:

```python
async def test_enqueue_opens_a_proposal_and_a_pending_job() -> None: ...
async def test_run_once_drives_a_job_to_done() -> None: ...
async def test_a_failing_job_records_a_durable_last_error() -> None:
    """Roll back before recording, so an aborted transaction cannot lose it."""
async def test_one_job_failing_does_not_strand_the_rest_of_the_batch() -> None:
    """5 jobs across 5 orgs, job 2 raises: the other 4 still reach done."""
async def test_the_claim_is_committed_before_evaluation_begins() -> None:
    """Read the job from an independent session inside a patched evaluator."""
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_assessment_jobs.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.assessment.engine.jobs'`.

- [ ] **Step 3: Implement**

Mirror `src/ccf/prep/jobs.py`'s `run_once` structure exactly, because its transaction boundaries are the hard-won part: `await session.commit()` immediately after `claim_jobs` returns — **before** any evaluation — and again after each job's outcome via a `_drive_one` helper. A job that raises is recorded `failed` **after** a `session.rollback()`, so `last_error` survives an aborted transaction.

- [ ] **Step 4–6: Run tests, verify lint/types, commit**

```bash
.venv/bin/pytest tests/test_assessment_jobs.py -v         # 5 pass
.venv/bin/ruff check . && .venv/bin/mypy src
git add src/ccf/assessment/engine/jobs.py tests/test_assessment_jobs.py
git commit -m "feat(assessment): queue control evaluation on the shared helper"
```

---

### Task 9: Move `prep_jobs` onto the shared helper — **GATED**

**This task may be abandoned. That is a valid outcome, not a failure.**

**Files:**
- Modify: `src/ccf/prep/jobs.py`

**Gate:** after refactoring, `tests/test_prep_jobs.py` must pass **completely unchanged** — no edited assertions, no adjusted fixtures, no new tolerances. If it does not, `git checkout src/ccf/prep/jobs.py`, report that the gate failed and why, and move on. Two queue implementations drifting is recoverable; regressing crash-recovery semantics that took three fix rounds and an adversarial review to harden is not.

- [ ] **Step 1: Record the baseline**

Run: `.venv/bin/pytest tests/test_prep_jobs.py -v` and note the count and every test name.

- [ ] **Step 2: Refactor**

Replace `prep/jobs.py`'s `claim` and `reap_stale` bodies with calls to `ccf.queue.claim_jobs` / `reap_stale_jobs`, passing `PrepJob`. Do not touch `run_once`, `_drive_one`, `enqueue`, or the transaction boundaries.

- [ ] **Step 3: Run the gate**

Run: `.venv/bin/pytest tests/test_prep_jobs.py -v`
Expected: identical count, all passing, file unmodified (`git diff --stat tests/test_prep_jobs.py` empty).

- [ ] **Step 4: Decide**

Passed → continue. Failed → `git checkout src/ccf/prep/jobs.py`, record the failure in the report, skip to Task 10.

- [ ] **Step 5: Full suite and commit**

```bash
.venv/bin/pytest -q                                       # run alone
.venv/bin/ruff check . && .venv/bin/mypy src
git add src/ccf/prep/jobs.py
git commit -m "refactor(prep): move prep_jobs onto the shared queue helper"
```

---

### Task 10: Worker CLI

**Files:**
- Modify: `src/ccf/cli.py`, `src/ccf/config.py`, `docker-compose.yml`, `Makefile`
- Create: `tests/test_assessment_worker_cli.py`

**Interfaces:**
- Produces: `ccf assessment-worker [--once/--loop] [--limit N] [--worker NAME]`; settings `assessment_worker_poll_interval_seconds` (default 30), `assessment_worker_reap_interval_seconds` (default 300), `assessment_job_stale_after_minutes` (default 60), `assessment_job_max_attempts` (default 5).

- [ ] **Step 1: Write the failing test**

```python
def test_worker_is_absent_when_the_engine_is_disabled() -> None:
    """assessment_engine_enabled=False -> clean exit, clear message, no work."""

def test_worker_help_lists_the_expected_options() -> None: ...

async def test_the_reaper_runs_inside_the_loop_not_once_at_startup() -> None:
    """Slice 1 shipped a worker that reaped only at startup, silently disabling
    the dead-letter net. Assert a job becoming stale AFTER startup is reaped."""
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_assessment_worker_cli.py -v`
Expected: FAIL — no such command.

- [ ] **Step 3: Implement**

Model on `ccf prep-worker`'s `_drain_loop` in `src/ccf/cli.py` — reap **inside** the loop on its own interval, sleep between empty cycles, gate on `assessment_engine_enabled`. Add a `compose` service under the `assessment` profile with `CCF_ASSESSMENT_ENGINE_ENABLED: "true"` set on that service only, plus a `Makefile` target.

- [ ] **Step 4–6: Run tests, verify lint/types, commit**

```bash
.venv/bin/pytest tests/test_assessment_worker_cli.py -v
.venv/bin/ccf assessment-worker --help
.venv/bin/ruff check . && .venv/bin/mypy src
git add src/ccf/cli.py src/ccf/config.py docker-compose.yml Makefile \
        tests/test_assessment_worker_cli.py
git commit -m "feat(assessment): add the assessment-worker CLI and compose profile"
```

---

### Task 11: REST surface

**Files:**
- Create: `src/ccf/api/routes/assessment_engine.py`
- Modify: `src/ccf/api/main.py`
- Create: `tests/test_assessment_engine_api.py`

**Interfaces:**
- `POST /api/assessment-engine/proposals` — body `{assessment_id, control_identifier}`; enqueues; **no `organization_id` field at all**, since the org derives from the assessment and is checked against the principal.
- `GET /api/assessment-engine/proposals/{id}` — proposal with its objectives, verdicts and citations.
- `POST /api/assessment-engine/proposals/{id}/accept` — projects into `AssessmentControlResult`.

Every endpoint takes `Depends(get_principal)`. Registration in `main.py` is gated on `settings.assessment_engine_enabled`, matching how `prep.router` is mounted.

- [ ] **Step 1: Write the failing test**

```python
async def test_post_enqueues_and_returns_identifiers() -> None: ...
async def test_get_returns_objectives_with_citations_and_page_numbers() -> None: ...
async def test_accept_projects_into_the_result_store() -> None: ...
async def test_endpoints_are_absent_when_the_engine_is_disabled() -> None: ...
async def test_unauthenticated_access_is_refused() -> None: ...
async def test_an_org_a_principal_cannot_read_an_org_b_proposal() -> None:
    """404, not 403 -- do not confirm another tenant's ids exist."""
async def test_an_org_a_principal_cannot_accept_an_org_b_proposal() -> None: ...
async def test_an_org_a_principal_cannot_enqueue_against_an_org_b_assessment() -> None:
    """The laundering shape from slice 1: a foreign assessment_id must 404."""
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_assessment_engine_api.py -v`
Expected: FAIL — 404 on every route.

- [ ] **Step 3: Implement**

Follow `src/ccf/api/routes/evidence_repo.py` for principal handling and its 404-not-403 convention. Resolve the proposal's org from the row and compare against `principal.org_id`; when `principal.org_id` is `None` (auth disabled) fall through, matching `src/ccf/api/routes/prep.py`'s `_scoped_organization_id` precedent — and document that caveat in the module docstring.

- [ ] **Step 4–6: Run tests, verify lint/types, commit**

```bash
.venv/bin/pytest tests/test_assessment_engine_api.py -v   # 8 pass
.venv/bin/ruff check . && .venv/bin/mypy src
git add src/ccf/api/routes/assessment_engine.py src/ccf/api/main.py \
        tests/test_assessment_engine_api.py
git commit -m "feat(assessment): add the principal-scoped assessment-engine API"
```

---

### Task 12: End-to-end test

**Files:**
- Create: `tests/test_assessment_engine_e2e.py`

Proves the slice works against real data, with only the two model-gateway boundaries stubbed. Slice 1 shipped an "end-to-end" test whose fixture pre-marked four stages complete; this one must not.

- [ ] **Step 1: Write the test**

```python
async def test_a_real_assessment_produces_accepted_findings_with_citations() -> None:
    """Catalog objectives -> prepared evidence -> proposals -> acceptance -> SAR."""
    # 1. Seed a control with 2 sub-clause objectives and a populated search_vector.
    # 2. Run slice 1's pipeline over a real EvidenceVersion so prep_units exist
    #    (reuse tests/test_prep_pipeline_e2e.py's approach; patch only
    #    gateway.generate_structured and gateway.embed).
    # 3. Create an Assessment over that system.
    # 4. enqueue_control(...) then run_once(...) -- nothing pre-marked.
    # 5. Assert: one AssessmentControlProposal, two AssessmentObjectiveProposals
    #    in order, each cited_unit_id resolving to a real prep_unit, and each
    #    cited unit's page_numbers non-empty -- the citation chain end to end.
    # 6. accept_control_proposal(...); assert an AssessmentControlResult exists
    #    with objective_findings of length 2 and the rolled-up finding.
    # 7. Generate the SAR and assert both objective labels appear in it.
```

- [ ] **Step 2–4: Run, verify, commit**

```bash
.venv/bin/pytest tests/test_assessment_engine_e2e.py -v
.venv/bin/pytest -q                                       # run alone
git add tests/test_assessment_engine_e2e.py
git commit -m "test(assessment): end-to-end from catalog objective to SAR"
```

---

### Task 13: Documentation

**Files:**
- Modify: `docs/ARCHITECTURE.md`, `README.md`, `CHANGELOG.md`, `src/ccf/models_assessment_engine.py`

**Document what was built, not what this plan predicted.** Verify each statement against the code before writing it — slice 1's final review found three documentation claims that were false.

- [ ] **Step 1: Write the docs**

Cover: the engine reads objectives from `ccf.controls` sub-clause rows and materialises nothing; proposals are inert until accepted, and acceptance is what reaches the SAR and POA&M path; `insufficient_evidence` is proposal-only and cannot be accepted; the rollup is application code with 800-53A's unanimity rule; `CCF_ASSESSMENT_ENGINE_ENABLED` is off by default because the worker spends money on model calls; the auth-disabled caveat, in the `README` block where an operator configuring the engine will meet it; and that `assessment_*` tables carry **no RLS** — isolation is application-layer, as for the prep tables.

Record the Task 9 outcome honestly: whether `prep_jobs` moved onto the shared helper or the gate failed and two implementations remain.

Also state the standing follow-up: neither slice 1's classification nor this slice's evaluation routes through `ai_actions.run_action`, so there is no `ai_action_runs` audit trail for AI-generated content. Do not claim otherwise anywhere.

- [ ] **Step 2–3: Verify and commit**

```bash
.venv/bin/pytest -q                                       # run alone
git add docs/ARCHITECTURE.md README.md CHANGELOG.md src/ccf/models_assessment_engine.py
git commit -m "docs(assessment): document the objective assessment engine"
```

---

## Deferred, deliberately

Recorded so a reviewer sees these were decided rather than missed:

- **No `ai_action_runs` audit trail** for evaluation calls — the same gap slice 1 has for classification. Both should be wired in one pass; splitting it would leave the audit story half-built either way.
- **Objectives are not materialised.** A `text_sha256` mismatch marks a proposal stale; there is no re-evaluation command yet.
- **No dissent path, closure questions, remediation drafting or calibration** — slices S3–S6.
- **No RLS on `assessment_*` tables**, matching the prep tables. Documented rather than silently inherited.
- **The rollup policy has no per-family or per-control overrides.** 800-53A unanimity is the correct default; overrides are a real requirement only once an organization's assessment policy demands them.
