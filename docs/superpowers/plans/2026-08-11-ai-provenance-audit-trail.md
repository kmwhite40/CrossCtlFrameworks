# AI Provenance & Audit Trail Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every AI-generated classification and objective verdict an `ai_action_runs` record with citations, and stamp the accepting assessor onto it — so "which model produced this, from what evidence, and who accepted it" is one query.

**Architecture:** No new tables. A single `record_ai_run` helper writes into the existing `ai_action_*` tables; the classify and evaluate stages call it after their model call, inside the savepoint that already protects them. Acceptance stamps `reviewer`/`disposition`/`decided_at` onto the linked runs. Execution is **not** rerouted through `ai_actions.run_action` — that function takes an entity rather than a prompt, and gating 98 objectives per control behind approval is unusable.

**Tech Stack:** Python 3.12, SQLAlchemy 2.0 async, Alembic, Postgres 16, pytest.

**Spec:** [docs/superpowers/specs/2026-08-11-ai-provenance-audit-trail-design.md](../specs/2026-08-11-ai-provenance-audit-trail-design.md)
**Depends on:** slices 1 and 2, both on `feat/evidence-prep-spine`.

## A note on this plan's form

Task 1 carries a complete test body and implementation. Tasks 2–6 give each test's name, docstring and exact assertions but not full bodies — write them from the assertions, following the conventions in the neighbouring test files each task names. Every interface, column name and behavioural rule you need is specified.

## Global Constraints

- **Python:** 3.12, `line-length = 100`. **Ruff** selects `["E","F","W","I","UP","B","SIM","N","PL","RUF"]`; `BLE`/`SLF` are **not** selected, so a `# noqa: BLE001` trips `RUF100`. Known baseline: **25 pre-existing `PLR0917`** across ten untouched `src/ccf/api/routes/` files — add nothing to it.
- **Types:** `mypy src` is `strict = true`.
- **Logging:** `from ..logging import get_logger` (adjust depth per module); never `import structlog`; never `extra={...}` — reserved `LogRecord` keys raise `KeyError`.
- **Tests:** real Postgres, `asyncio_mode = "auto"` — never `@pytest.mark.asyncio`. DB modules open with `pytestmark = pytest.mark.usefixtures("fresh_engine")`. **Never run two pytest sessions concurrently** — the session fixture drops and recreates the schema.
- **Session:** `autoflush=False` (`src/ccf/db.py:88`) — flush before any delete or select that must see pending adds.
- **Migrations:** `migrations/versions/00NN_<slug>.py`, explicit `revision`/`down_revision`. **Current head is `0055_assessment_engine`.** Every table- or column-adding migration re-issues `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app`.
- **Tenancy:** `organization_id` is derived from the run or proposal being recorded, never from a caller argument.
- **Provenance must never fail a stage.** `record_ai_run` returns `None` on failure; the caller stores a NULL run id and continues. Losing an audit row is bad; failing a control's evaluation because its audit row would not insert is worse.
- **Do not change** prompts, JSON schemas, citation validation, the rollup policy, the human gate, or any transaction boundary. Those are load-bearing and were each hardened by a review cycle.
- **Licensing:** independent implementation; no code from the BUSL-licensed ato-bot project.

## File structure

| File | Responsibility |
|---|---|
| `src/ccf/ai_actions/provenance.py` | `CitationRef`, `record_ai_run` — recording only, deliberately not in `service.py` |
| `migrations/versions/0056_objective_proposal_ai_run.py` | `assessment_objective_proposals.ai_action_run_id` + grant |
| `src/ccf/models_assessment_engine.py` | the new FK column |
| `src/ccf/prep/classify.py` | call `record_ai_run`, store the id |
| `src/ccf/assessment/engine/evaluate.py` + `service.py` | call `record_ai_run`, store the id |
| `src/ccf/assessment/engine/service.py` | acceptance stamps the linked runs |
| `src/ccf/api/routes/ai_actions.py` | list pipeline-recorded runs |

---

### Task 1: `record_ai_run` and the FK column

**Files:**
- Create: `src/ccf/ai_actions/provenance.py`
- Modify: `src/ccf/models_assessment_engine.py`
- Create: `migrations/versions/0056_objective_proposal_ai_run.py`
- Create: `tests/test_ai_provenance.py`

**Interfaces:**
- Consumes: `AiActionRun`, `AiActionInput`, `AiActionOutput`, `AiActionCitation` from `ccf.models_ai_actions`; `get_settings().ai_store_prompts`.
- Produces:
  - `@dataclass(slots=True) CitationRef` with `source_type: str`, `source_id: str`, `label: str | None = None`, `note: str | None = None`
  - `PIPELINE_RUN_STATUS = "recorded"`
  - `async record_ai_run(session, *, action_key: str, entity_type: str, entity_id: str, organization_id: int, provider: str, model: str | None, prompt: str, output: dict[str, Any], citations: list[CitationRef], actor: str | None = None) -> AiActionRun | None`
  - `AssessmentObjectiveProposal.ai_action_run_id: Mapped[int | None]`

- [ ] **Step 1: Write the failing test**

Create `tests/test_ai_provenance.py`:

```python
"""Provenance recording for pipeline AI calls.

These runs are recorded, not approval-gated: they document what a model produced
so an assessor's later acceptance can be attributed. See
src/ccf/ai_actions/provenance.py for why they do not go through run_action.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from ccf.ai_actions.provenance import PIPELINE_RUN_STATUS, CitationRef, record_ai_run
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization
from ccf.models_ai_actions import (
    AiActionCitation,
    AiActionInput,
    AiActionOutput,
    AiActionRun,
)

pytestmark = pytest.mark.usefixtures("fresh_engine")


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return int(org.id)


async def _record(org_id: int, **overrides: object) -> int:
    kwargs: dict[str, object] = {
        "action_key": "classify_evidence_unit",
        "entity_type": "prep_unit",
        "entity_id": "42",
        "organization_id": org_id,
        "provider": "openai",
        "model": "gpt-test",
        "prompt": "Classify this passage.",
        "output": {"verdict": "satisfied", "confidence": 0.8},
        "citations": [
            CitationRef(source_type="prep_unit", source_id="42", label="p. 3, Access Control")
        ],
        "actor": None,
    }
    kwargs.update(overrides)
    async with session_scope() as s:
        run = await record_ai_run(s, **kwargs)  # type: ignore[arg-type]
        assert run is not None
        await s.flush()
        return int(run.id)


async def test_records_a_run_with_model_and_provider() -> None:
    org_id = await _org("prov-basic")
    run_id = await _record(org_id)
    async with session_scope() as s:
        run = (await s.execute(select(AiActionRun).where(AiActionRun.id == run_id))).scalar_one()
        assert run.action_key == "classify_evidence_unit"
        assert run.entity_type == "prep_unit"
        assert run.entity_id == "42"
        assert run.organization_id == org_id
        assert run.provider == "openai"
        assert run.summary.get("model") == "gpt-test"


async def test_pipeline_runs_are_recorded_not_pending_review() -> None:
    """A distinct status, so an operator can tell these from approval-gated runs."""
    org_id = await _org("prov-status")
    run_id = await _record(org_id)
    async with session_scope() as s:
        run = (await s.execute(select(AiActionRun).where(AiActionRun.id == run_id))).scalar_one()
        assert run.status == PIPELINE_RUN_STATUS == "recorded"
        assert run.mutation_applied is False
        assert run.reviewer is None
        assert run.decided_at is None


async def test_input_and_output_hashes_are_recorded() -> None:
    org_id = await _org("prov-hashes")
    run_id = await _record(org_id)
    async with session_scope() as s:
        run = (await s.execute(select(AiActionRun).where(AiActionRun.id == run_id))).scalar_one()
        assert run.input_hash and len(run.input_hash) == 64
        assert run.output_hash and len(run.output_hash) == 64


async def test_the_same_prompt_and_output_hash_identically() -> None:
    org_id = await _org("prov-stable")
    first = await _record(org_id)
    second = await _record(org_id)
    async with session_scope() as s:
        runs = (
            await s.execute(
                select(AiActionRun).where(AiActionRun.id.in_([first, second]))
            )
        ).scalars().all()
    assert runs[0].input_hash == runs[1].input_hash
    assert runs[0].output_hash == runs[1].output_hash


async def test_a_different_prompt_hashes_differently() -> None:
    org_id = await _org("prov-differs")
    first = await _record(org_id)
    second = await _record(org_id, prompt="A different prompt entirely.")
    async with session_scope() as s:
        runs = {
            r.id: r
            for r in (
                await s.execute(
                    select(AiActionRun).where(AiActionRun.id.in_([first, second]))
                )
            ).scalars().all()
        }
    assert runs[first].input_hash != runs[second].input_hash


async def test_one_citation_row_per_reference_with_its_label() -> None:
    org_id = await _org("prov-citations")
    run_id = await _record(
        org_id,
        citations=[
            CitationRef(source_type="prep_unit", source_id="7", label="p. 3, Access Control"),
            CitationRef(source_type="prep_unit", source_id="9", label="p. 4, Audit"),
        ],
    )
    async with session_scope() as s:
        rows = (
            await s.execute(
                select(AiActionCitation).where(AiActionCitation.run_id == run_id)
            )
        ).scalars().all()
    assert sorted(r.source_id for r in rows) == ["7", "9"]
    assert all(r.source_type == "prep_unit" for r in rows)
    assert any("Access Control" in (r.label or "") for r in rows)


async def test_the_output_payload_is_stored() -> None:
    org_id = await _org("prov-output")
    run_id = await _record(org_id)
    async with session_scope() as s:
        out = (
            await s.execute(select(AiActionOutput).where(AiActionOutput.run_id == run_id))
        ).scalar_one()
    assert out.payload.get("verdict") == "satisfied"


async def test_the_prompt_body_is_withheld_when_ai_store_prompts_is_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """IA-10: the hash still proves what ran, without retaining the prompt text."""
    monkeypatch.setenv("CCF_AI_STORE_PROMPTS", "false")
    get_settings.cache_clear()
    try:
        org_id = await _org("prov-noprompt")
        run_id = await _record(org_id, prompt="Sensitive customer policy text.")
        async with session_scope() as s:
            inp = (
                await s.execute(select(AiActionInput).where(AiActionInput.run_id == run_id))
            ).scalar_one()
            run = (
                await s.execute(select(AiActionRun).where(AiActionRun.id == run_id))
            ).scalar_one()
        assert "Sensitive customer policy text." not in str(inp.payload)
        assert inp.hash and len(inp.hash) == 64
        assert run.input_hash == inp.hash
    finally:
        get_settings.cache_clear()


async def test_the_prompt_body_is_stored_when_ai_store_prompts_is_true(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CCF_AI_STORE_PROMPTS", "true")
    get_settings.cache_clear()
    try:
        org_id = await _org("prov-prompt")
        run_id = await _record(org_id, prompt="Classify this passage.")
        async with session_scope() as s:
            inp = (
                await s.execute(select(AiActionInput).where(AiActionInput.run_id == run_id))
            ).scalar_one()
        assert "Classify this passage." in str(inp.payload)
    finally:
        get_settings.cache_clear()


async def test_a_recording_failure_returns_none_rather_than_raising() -> None:
    """Losing an audit row must never fail the stage that produced real work."""
    async with session_scope() as s:
        run = await record_ai_run(
            s,
            action_key="classify_evidence_unit",
            entity_type="prep_unit",
            entity_id="1",
            organization_id=987654321,  # no such organization -> FK violation
            provider="openai",
            model="gpt-test",
            prompt="x",
            output={},
            citations=[],
        )
    assert run is None


async def test_the_objective_proposal_carries_an_ai_action_run_fk() -> None:
    """The column Task 3 populates must exist and be nullable."""
    from ccf.models_assessment_engine import AssessmentObjectiveProposal

    column = AssessmentObjectiveProposal.__table__.c.ai_action_run_id
    assert column.nullable is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_ai_provenance.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.ai_actions.provenance'`.

- [ ] **Step 3: Write the provenance helper**

Create `src/ccf/ai_actions/provenance.py`:

```python
"""Record what a pipeline AI call did, without routing it through run_action.

``ccf.ai_actions.service.run_action`` takes an *entity* and builds its own prompt,
then gates the result behind human approval. The preparation and assessment
pipelines cannot use it: their prompts are deliberately bounded (one passage, or
one objective plus only the passages retrieval returned) and their outputs are
schema-validated with citations checked against those exact candidates -- and that
boundedness is the safety property. Gating each call behind approval is also
unusable at 98 objectives for a single control.

So this module records provenance and nothing else. It writes the same
``ai_action_*`` rows an approval-gated run would, with ``status="recorded"`` to
distinguish them, so one query over one table answers "which model produced this
verdict, from what evidence, and who accepted it". Acceptance fills in the
reviewer half.

Recording must never fail the work it documents: every failure returns ``None``
and is logged, leaving the caller to store a NULL run id and carry on.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..logging import get_logger
from ..models_ai_actions import (
    AiActionCitation,
    AiActionInput,
    AiActionOutput,
    AiActionRun,
)

log = get_logger(__name__)

#: Distinguishes a pipeline-recorded run from one awaiting human approval.
PIPELINE_RUN_STATUS = "recorded"

#: Bumped when a pipeline's prompt construction changes materially, so runs
#: recorded under different prompt shapes stay distinguishable.
PROMPT_VERSION = "v1"


@dataclass(slots=True)
class CitationRef:
    """One piece of evidence a model was shown and cited."""

    source_type: str
    source_id: str
    label: str | None = None
    note: str | None = None


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical(payload: dict[str, Any]) -> str:
    """Stable JSON so the same output always hashes the same."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


async def record_ai_run(
    session: AsyncSession,
    *,
    action_key: str,
    entity_type: str,
    entity_id: str,
    organization_id: int,
    provider: str,
    model: str | None,
    prompt: str,
    output: dict[str, Any],
    citations: list[CitationRef],
    actor: str | None = None,
) -> AiActionRun | None:
    """Record one pipeline AI call. Returns ``None`` if recording failed."""
    settings = get_settings()
    input_hash = _sha256(prompt)
    output_hash = _sha256(_canonical(output))

    try:
        run = AiActionRun(
            organization_id=organization_id,
            action_key=action_key,
            entity_type=entity_type,
            entity_id=entity_id,
            status=PIPELINE_RUN_STATUS,
            provider=provider,
            prompt_version=PROMPT_VERSION,
            input_hash=input_hash,
            output_hash=output_hash,
            actor=actor,
            mutation_applied=False,
            summary={"model": model, "citation_count": len(citations)},
        )
        session.add(run)
        await session.flush()

        # IA-10: the hash proves what ran even when the prompt itself is not retained.
        payload: dict[str, Any] = {"prompt_sha256": input_hash, "model": model}
        if settings.ai_store_prompts:
            payload["prompt"] = prompt
        session.add(
            AiActionInput(
                run_id=run.id,
                entity_type=entity_type,
                entity_id=entity_id,
                payload=payload,
                hash=input_hash,
            )
        )
        session.add(
            AiActionOutput(
                run_id=run.id,
                content=_canonical(output),
                uncited=not citations,
                payload=output,
                hash=output_hash,
            )
        )
        for citation in citations:
            session.add(
                AiActionCitation(
                    run_id=run.id,
                    source_type=citation.source_type,
                    source_id=citation.source_id,
                    label=citation.label,
                    note=citation.note,
                )
            )
        await session.flush()
        return run
    except Exception as exc:
        log.warning(
            "ai.provenance_record_failed",
            action_key=action_key,
            entity_type=entity_type,
            entity_id=entity_id,
            error=str(exc),
        )
        return None
```

**Note on the broad `except`:** it is deliberate and the module docstring explains why — provenance must never fail the work it documents. Do not add `# noqa: BLE001`; `BLE` is not in this repo's ruff selection and the pragma would trip `RUF100`.

- [ ] **Step 4: Add the FK column to the model**

In `src/ccf/models_assessment_engine.py`, inside `AssessmentObjectiveProposal`, beside `model_confidence`:

```python
    #: Provenance for the model call that produced this verdict. Nullable:
    #: historical rows predate provenance recording, and a recording failure
    #: must leave a usable NULL rather than block the verdict.
    ai_action_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.ai_action_runs.id", ondelete="SET NULL"), index=True
    )
```

Ensure `models_assessment_engine.py` imports `models_ai_actions` so the FK target is registered — follow whatever `models_prep.py` does for the identical FK, and say in your report which mechanism you used.

- [ ] **Step 5: Write the migration**

Create `migrations/versions/0056_objective_proposal_ai_run.py` adding the nullable `ai_action_run_id` `BigInteger` column with an FK to `ccf.ai_action_runs.id` `ON DELETE SET NULL` plus its index, ending `upgrade()` with:

```python
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app")
```

`revision = "0056_objective_proposal_ai_run"`, `down_revision = "0055_assessment_engine"`. `downgrade()` drops the index then the column.

- [ ] **Step 6: Round-trip the migration**

Run: `.venv/bin/alembic upgrade head && .venv/bin/alembic downgrade -1 && .venv/bin/alembic upgrade head`
Expected: all three succeed.

- [ ] **Step 7: Run tests**

Run: `.venv/bin/pytest tests/test_ai_provenance.py -v`
Expected: PASS (11 tests)

- [ ] **Step 8: Verify lint and types, then commit**

```bash
.venv/bin/ruff check . && .venv/bin/mypy src
git add src/ccf/ai_actions/provenance.py src/ccf/models_assessment_engine.py \
        migrations/versions/0056_objective_proposal_ai_run.py tests/test_ai_provenance.py
git commit -m "feat(ai): record provenance for pipeline AI calls"
```

---

### Task 2: Classification provenance

**Files:**
- Modify: `src/ccf/prep/classify.py`
- Modify: `tests/test_prep_classify.py`

**Interfaces:**
- Consumes: `record_ai_run`, `CitationRef` (Task 1).
- Produces: `PrepClassification.ai_action_run_id` populated on every successful classification.

The classify stage calls `gateway.generate_structured`. It needs the resolved provider and model — slice 2 added `generate_structured_resolved` returning `StructuredResult(data, model)`; check whether it also exposes the provider, and if not, resolve it the same way `gateway.embed` does. Report what you found.

Record with `action_key="classify_evidence_unit"` (already in the registry), `entity_type="prep_unit"`, `entity_id=str(unit.id)`, and one `CitationRef(source_type="prep_unit", source_id=str(unit.id))` — a classification's evidence is the unit itself.

**The call must sit inside the existing per-unit savepoint**, so a provenance failure rolls back only the provenance write.

- [ ] **Step 1: Write the failing tests** in `tests/test_prep_classify.py`:

```python
async def test_classification_records_an_ai_action_run() -> None:
    """action_key, entity ref, provider and model are recorded; the FK is set."""
    # Assert PrepClassification.ai_action_run_id is not None, and the linked
    # AiActionRun has action_key "classify_evidence_unit", entity_type
    # "prep_unit", entity_id == str(unit.id), status "recorded", and
    # summary["model"] equal to the fake gateway's model.

async def test_a_provenance_failure_does_not_fail_the_classification() -> None:
    """Monkeypatch record_ai_run to raise; the classification still persists."""
    # Assert the PrepClassification row exists with ai_action_run_id IS NULL,
    # the run reaches stage_classify == "complete", and nothing raised.
```

- [ ] **Step 2: Run to verify failure** — `.venv/bin/pytest tests/test_prep_classify.py -v`; expected FAIL on the missing run.

- [ ] **Step 3: Implement**, storing `run.id if run is not None else None` on the `PrepClassification`.

- [ ] **Step 4: Run tests; Step 5: lint, types, commit**

```bash
.venv/bin/pytest tests/test_prep_classify.py -v
.venv/bin/ruff check . && .venv/bin/mypy src
git add src/ccf/prep/classify.py tests/test_prep_classify.py
git commit -m "feat(prep): record provenance for evidence classification"
```

---

### Task 3: Objective-evaluation provenance

**Files:**
- Modify: `src/ccf/assessment/engine/evaluate.py`, `src/ccf/assessment/engine/service.py`
- Modify: `tests/test_assessment_evaluate.py`, `tests/test_assessment_service.py`

**Interfaces:**
- Consumes: Task 1's helper; the `ai_action_run_id` column.
- Produces: `ObjectiveEvaluation.ai_action_run_id: int | None`, populated onto `AssessmentObjectiveProposal`.

`evaluate_objective` already has the retrieved units, so it can build citations with real labels. Record with `action_key="evaluate_assessment_objective"`, `entity_type="assessment_objective"`, `entity_id=objective.label`, and **one `CitationRef` per cited unit** — `source_type="prep_unit"`, `source_id=str(unit_id)`, and `label` carrying page numbers and section path, e.g. `"p. 3, 4 — Access Control > Account Management"`, so a citation is legible without a join.

Cite only the units the model actually cited (the already-validated `cited_unit_ids`), not everything retrieved.

`service.py` stores `evaluation.ai_action_run_id` onto the proposal, **inside the existing per-objective savepoint**.

Register an `ActionDef("evaluate_assessment_objective", …)` in `src/ccf/ai_actions/registry.py` with `requires_approval=False`, `citation_required=True`, `allowed_mutation=None`, so the registry describes it. It is recorded, not dispatched — say so in the description text.

- [ ] **Step 1: Write the failing tests:**

```python
# tests/test_assessment_evaluate.py
async def test_evaluation_records_a_run_with_one_citation_per_cited_unit() -> None:
    """Two cited units -> two AiActionCitation rows, labels carrying page and section."""

async def test_only_cited_units_are_recorded_as_citations() -> None:
    """A retrieved-but-uncited unit must not appear as a citation."""

async def test_no_evidence_still_records_a_run_marked_uncited() -> None:
    """insufficient_evidence is a real outcome and must be auditable too."""
    # Assert a run exists with zero citations and AiActionOutput.uncited is True.

# tests/test_assessment_service.py
async def test_the_objective_proposal_links_to_its_run() -> None:
async def test_a_provenance_failure_leaves_the_verdict_intact_with_a_null_run_id() -> None:
```

- [ ] **Step 2–5: verify failure, implement, run, lint/types, commit**

```bash
git add src/ccf/assessment/engine/evaluate.py src/ccf/assessment/engine/service.py \
        src/ccf/ai_actions/registry.py tests/test_assessment_evaluate.py \
        tests/test_assessment_service.py
git commit -m "feat(assessment): record provenance for objective evaluation"
```

---

### Task 4: Acceptance stamps the reviewer

This is the half that makes the audit answerable — without it the record shows what a model produced but not who took responsibility.

**Files:**
- Modify: `src/ccf/assessment/engine/service.py`
- Modify: `tests/test_assessment_acceptance.py`

**Interfaces:**
- Produces: on acceptance, every `AiActionRun` linked to that control's objective proposals gets `reviewer`, `disposition="accepted"`, `decided_at`, `mutation_applied=True`.

- [ ] **Step 1: Write the failing tests:**

```python
async def test_before_acceptance_no_linked_run_is_stamped() -> None:
    """reviewer, disposition, decided_at all NULL; mutation_applied False."""

async def test_acceptance_stamps_every_linked_run() -> None:
    """Each run gets reviewer == accepted_by, disposition 'accepted',
    a decided_at, and mutation_applied True."""

async def test_a_proposal_with_a_null_run_id_still_accepts() -> None:
    """A provenance failure must not block acceptance."""

async def test_a_refused_acceptance_stamps_nothing() -> None:
    """An insufficient_evidence proposal is refused and leaves runs unstamped."""
```

- [ ] **Step 2–5: verify failure, implement, run, lint/types, commit**

Collect the non-NULL `ai_action_run_id` values for the proposal's objectives and issue one bulk `UPDATE` — mind `autoflush=False` and flush before selecting if any pending writes must be visible.

```bash
git add src/ccf/assessment/engine/service.py tests/test_assessment_acceptance.py
git commit -m "feat(assessment): stamp the accepting assessor onto linked AI runs"
```

---

### Task 5: The auditor's query

**Files:**
- Modify: `src/ccf/api/routes/ai_actions.py`
- Create: `tests/test_ai_provenance_audit.py`

**Interfaces:**
- Produces: `GET /api/ai-actions?status=recorded` listing pipeline runs, principal-scoped exactly as that module already scopes its other endpoints.

**This task is the slice's acceptance criterion.** If the auditor's question cannot be answered in one query, the design has not delivered.

- [ ] **Step 1: Write the failing tests:**

```python
async def test_one_query_answers_model_evidence_and_reviewer() -> None:
    """The whole point of the slice.

    Run slice 2's end-to-end flow, accept, then issue ONE query over
    ai_action_runs joined to ai_action_citations and assert it yields, per
    objective: the model name, every cited prep_unit id with its label, the
    accepting reviewer, and decided_at. Assert on the joined result, not by
    reading the pipeline tables.
    """

async def test_every_citation_source_id_resolves_to_a_real_prep_unit() -> None:
    """A citation pointing at nothing is worse than no citation."""

async def test_the_listing_endpoint_returns_pipeline_runs() -> None:
async def test_an_org_a_principal_cannot_list_org_b_runs() -> None:
    """Tenant scoping on the listing, asserted as an attack: 
    org B's runs must not appear in org A's response body."""
```

- [ ] **Step 2–5: verify failure, implement, run, lint/types, commit**

```bash
git add src/ccf/api/routes/ai_actions.py tests/test_ai_provenance_audit.py
git commit -m "feat(api): expose pipeline AI runs for audit"
```

---

### Task 6: Documentation

**Files:** `docs/ARCHITECTURE.md`, `README.md`, `CHANGELOG.md`, and the module docstrings in `src/ccf/prep/classify.py` and `src/ccf/assessment/engine/evaluate.py`.

**Verify every statement against the code before writing it.** Slice 1's final review found three false documentation claims, and slice 2's docs had to be corrected mid-slice.

- [ ] **Step 1: Rewrite the audit-trail claims**

Those documents currently describe the missing audit trail as a **gap**. It becomes a described capability plus a deliberate choice:

- Both pipeline paths now record an `ai_action_runs` row with model, provider, prompt version, and input/output hashes, one `ai_action_citations` row per cited passage, and a link from the pipeline table.
- Acceptance stamps `reviewer`, `disposition` and `decided_at`, so one query answers model, evidence and reviewer.
- These runs carry `status="recorded"`, distinguishing them from approval-gated runs.
- Execution deliberately does **not** route through `ai_actions.run_action`: it takes an entity rather than a prompt, the pipelines' bounded prompts and candidate-validated citations are the safety property, and per-call approval is unusable at 98 objectives per control. State this as a design decision with its reason — not as a limitation.
- **Historical rows are not retrofitted.** Evidence prepared before this slice keeps a NULL run id. Say so plainly.
- When `ai_store_prompts` is false, the prompt body is withheld and only its SHA-256 is retained.

- [ ] **Step 2: Verify and commit**

```bash
.venv/bin/pytest -q            # run alone
git add docs/ARCHITECTURE.md README.md CHANGELOG.md src/ccf/prep/classify.py \
        src/ccf/assessment/engine/evaluate.py
git commit -m "docs(ai): document pipeline AI provenance and the run_action decision"
```

---

## Deferred, deliberately

- **No guardrail evaluation** — that belongs to `run_action`'s model and needs per-call policy this slice does not define.
- **No approval gating of pipeline calls** — acceptance is the human gate, and it guards the authoritative write.
- **No retrofit of historical rows**, documented rather than silently absent.
- **No provenance for the screen or embed stages** — screening is deterministic full-text ranking with no model call, and embeddings produce vectors rather than assertions. Neither makes a claim an auditor would challenge.
