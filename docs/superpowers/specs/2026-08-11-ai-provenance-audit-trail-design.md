# AI Provenance & Audit Trail — Design

**Date:** 2026-08-11
**Status:** Approved (design), pending implementation plan
**Slice:** 3 of the ATO Bot capability delta
**Depends on:** slice 1 (evidence prep spine) and slice 2 (objective assessment engine), both on `feat/evidence-prep-spine`

## Context

Slices 1 and 2 put two model calls into Concord's critical path. Evidence
classification tags a prepared passage with the controls it supports. Objective
evaluation decides whether an assessment objective is met, and an accepted
verdict becomes a finding in a Security Assessment Report and can auto-create a
POA&M.

Neither leaves an audit record. Both call `ccf.ai.gateway.generate_structured`
directly, so nothing is written to `ai_action_runs`, and
`PrepClassification.ai_action_run_id` has been NULL since the column was created.
Until slice 2's final fix wave, `model_name` was NULL too — so a verdict destined
for a FedRAMP citation had no persisted record of *any* model having produced it.

Both slices' final reviews ranked this the top follow-up. This slice closes it.

### Why not simply route through `ai_actions.run_action`

That is what slice 1's and slice 2's documentation called for, and it is the
wrong target. Reading the code settles it:

`run_action(session, *, action_key, entity_type, entity_id, org_id, actor)` takes
an **entity reference, not a prompt**. It resolves its own context, constructs its
own prompt, and applies `_effective_requires_approval`, which — with
`ai_require_human_approval` defaulting to `True` — gates every run behind human
approval before it may mutate.

That is a different execution model from what the pipelines need, in two ways
that matter:

- **The pipelines' prompts are deliberately bounded**, and that boundedness is
  the safety property. Classification sees one passage and may only choose from
  the controls screening surfaced. Evaluation sees one objective and only the
  passages retrieval returned, and may cite nothing else. `run_action` builds its
  prompt from an entity; it cannot express those constraints without absorbing
  them, which would mean rewriting the safe stages around a less safe interface.
- **Approval gating per call is unusable here.** AC-4 has 98 objectives. Stopping
  each for human approval defeats the pipeline, and it is redundant: acceptance
  is already the human gate, and it is the one that guards the authoritative
  write.

So this slice records provenance without rerouting execution. The documentation
in slices 1 and 2 changes from describing a gap to describing a deliberate,
explained choice.

## Goals

1. Every AI-generated classification and objective verdict has an
   `ai_action_runs` row recording model, provider, prompt version, and input and
   output hashes.
2. Every cited passage is an `ai_action_citations` row.
3. Both pipeline tables link to their run via the FK columns.
4. Acceptance stamps the reviewer and disposition onto the linked runs, so
   "which model produced this, from what evidence, and who accepted it" is one
   query against one table.

## Non-goals

- **No guardrail evaluation.** That belongs to `run_action`'s model and needs
  per-call policy this slice does not define.
- **No approval gating of pipeline calls.** Acceptance is the human gate.
- **No retrofit.** Evidence already prepared keeps NULL run ids. Documentation
  says so rather than implying coverage that does not exist.
- No changes to prompts, schemas, citation validation, or the rollup policy.

## Architecture

No new tables. The `ai_action_*` tables already carry everything needed.

```
classify stage ──┐                        ┌── AiActionRun (action_key, provider, model,
                 │                        │      prompt_version, input_hash, output_hash)
                 ├─→ record_ai_run(...) ──┼── AiActionInput   (the unit / the objective)
                 │                        ├── AiActionOutput  (the structured verdict)
evaluate stage ──┘                        └── AiActionCitation (one per cited prep_unit)
                                                    │
   PrepClassification.ai_action_run_id ─────────────┤  (exists, always NULL today)
   AssessmentObjectiveProposal.ai_action_run_id ────┘  (new column, migration 0056)
```

### `record_ai_run` — one helper, two callers

New module `src/ccf/ai_actions/provenance.py`, deliberately **not** in
`service.py`, so no future reader mistakes it for the approval-gated `run_action`
path. Its docstring must state that distinction explicitly.

```python
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
) -> AiActionRun | None
```

`CitationRef` is a small dataclass of `source_type`, `source_id`, `label`, `note`
— for a prep unit, the label carries its page numbers and section path, so the
citation is legible without a join.

`input_hash` and `output_hash` are SHA-256 over the prompt and the canonicalised
output, giving replay-detection without storing prompt text when
`ai_store_prompts` is disabled. That setting already exists and must be honoured:
when false, `AiActionInput.payload` records the hash and metadata but not the
prompt body.

### Status vocabulary

`AiActionRun.status` defaults to `"pending_review"`, which would be misleading
here — these runs are not queued for approval. Pipeline-recorded runs use
`"recorded"`, a distinct value so an operator can tell the two apart at a glance.
`mutation_applied` stays `False` until acceptance, which is truthful: nothing
authoritative has been written before then.

### Acceptance stamps the loop closed

`AiActionRun` already has `reviewer`, `disposition` and `decided_at`, unused on
this path. When `accept_control_proposal` runs, every run linked to that control's
objective proposals gets `reviewer`, `disposition="accepted"`, `decided_at`, and
`mutation_applied=True`.

This is the half that makes the audit answerable. Without it, the record shows
what a model produced but not that a human took responsibility for it.

## Error handling

**A provenance-write failure is logged and the stage continues.** It runs inside
the savepoint that already protects each unit and each objective, so a failure
rolls back only the provenance write. Losing an audit record is bad; failing a
control's evaluation because its audit row would not insert is worse, and the
stage's own output remains durable and re-runnable.

`record_ai_run` returns `None` on failure so the caller stores a NULL run id
rather than propagating. The failure is logged at **warning** with the entity
reference, matching how the pipelines log provider faults.

## Multi-tenancy

`AiActionRun.organization_id` is derived from the run or proposal being recorded,
never from a caller argument. The `ai_action_*` tables are pre-existing and
already RLS-backed; this slice adds no new tenancy surface. The `/api/ai-actions`
listing gains a filter for `status="recorded"` so pipeline runs are visible
without changing that endpoint's existing scoping.

## Testing

- **Classification:** a run row exists with the right `action_key`, provider,
  model and hashes; `PrepClassification.ai_action_run_id` is populated; the input
  payload omits the prompt body when `ai_store_prompts` is false.
- **Evaluation:** one citation row per cited `prep_unit`, with page numbers and
  section path in the label; `AssessmentObjectiveProposal.ai_action_run_id`
  populated.
- **Citations match reality:** every `AiActionCitation.source_id` resolves to a
  real `prep_units` row — the same chain slice 2's end-to-end test asserts.
- **Acceptance stamp:** after accepting, every linked run has `reviewer`,
  `disposition="accepted"`, `decided_at` and `mutation_applied=True`; before
  acceptance, none does.
- **Failure isolation:** force `record_ai_run` to raise and assert the
  classification and the objective proposal still persist with a NULL run id, the
  stage completes, and a warning is logged. Confirm this test fails if the
  provenance call is moved outside its savepoint.
- **Auditor's query:** one query over `ai_action_runs` joined to citations returns
  model, evidence and reviewer for an accepted control. This is the acceptance
  criterion for the whole slice — if it cannot be expressed in one query, the
  design has not delivered.
- **No regression:** slice 1's and slice 2's existing suites pass unchanged.

## Migration

`0056_objective_proposal_ai_run` adds `assessment_objective_proposals.ai_action_run_id`
(nullable `BigInteger`, FK to `ccf.ai_action_runs.id`, `ON DELETE SET NULL`,
indexed), and re-issues `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN
SCHEMA ccf TO ccf_app` as every feature migration in this repo does.

Nullable because historical rows have no run, and because a provenance failure
must leave a usable NULL rather than block the write.

## Documentation

`docs/ARCHITECTURE.md`, `README.md`, `CHANGELOG.md` and both slices' module
docstrings currently describe the missing audit trail as a gap. They change to
describe what exists — provenance recorded for both paths, the acceptance stamp,
and the deliberate choice not to route through `run_action`, with the reason.
They must also state plainly that historical rows are not retrofitted.
