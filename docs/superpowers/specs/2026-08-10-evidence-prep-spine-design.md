# Evidence Preparation & Retrieval Spine — Design

**Date:** 2026-08-10
**Status:** Approved (design), pending implementation plan
**Slice:** 1 of the ATO Bot capability delta

## Context

[ATO Bot](https://github.com/DrDeathLabs/ato-bot) is a source-available platform for
NIST SP 800-53 control assessment. A review of its architecture against Concord
found that most of its surface — policy-governed AI, SSP composition, OSCAL export,
POA&M flow, continuous monitoring, RBAC and audit — already exists in Concord, in
several cases more maturely. Concord's typed AI action registry
(`src/ccf/ai_actions/registry.py`), with per-action approval gates, citation
requirements and constrained mutations, is stronger than ATO Bot's equivalent.

What Concord genuinely lacks is the layer underneath all of it: a way to turn an
uploaded PDF or Word policy into control-tagged, retrievable, traceable passages.
Concord can store an evidence file and hash it, but it cannot read it. Every
downstream ATO Bot capability — objective-level assessment, closure guidance,
dissent, calibration — depends on that layer existing first.

This spec covers that layer only.

### Licensing constraint

ATO Bot is licensed under **Business Source License 1.1**. Its Additional Use
Grant expressly forbids including the work "as a material feature of another
commercial cybersecurity, GRC, compliance, assessment, authorization, risk
management, or security operations product." Concord is proprietary and
commercially marketed, so **no ATO Bot source may be copied into Concord**
without a separate commercial license from DrDeathLabs.

ATO Bot has been used here only as a reference for problem decomposition — which
stages a pipeline needs and why — which is not a protectable expression. Every
line of the implementation described below is original work built on Concord's
own interfaces. If a code-level lift was ever intended, that decision needs to go
to legal before implementation starts.

## Goals

1. Parse evidence and policy documents into line-level records that preserve
   source structure — page, heading path, table, row, column, cell.
2. Identify which passages are plausibly relevant to which 800-53A controls,
   cheaply enough to run over whole document libraries.
3. Expand relevant lines into semantically complete evidence units.
4. Classify units by artifact type and evidence strength, with provenance.
5. Make units retrievable by control, with citations back to page and cell.

## Non-goals

Explicitly out of scope for this slice, each planned as its own later spec:
objective-level assessment, closure question generation, remediation artifact
generation and validation, AI dissent, calibration harness, synthetic evidence,
project-context assistant. This spec builds only the substrate they share.

## Approach

**Graft onto Concord's existing spines.** The pipeline is a new module, but every
seam plugs into machinery Concord already has. Roughly a third of ATO Bot's
pipeline surface therefore does not need writing at all.

Two approaches were rejected. Porting the pipeline as a self-contained subsystem
with its own control corpus, LLM client and quality scorer would fork Concord
into two AI paths and two evidence-quality scores, and is also the version most
exposed to the BUSL problem. A retrieval-only slice that indexes existing
`PolicyVersion.body` text would ship in about a week but cannot read a PDF, which
is the format most real evidence arrives in.

## The five non-duplication decisions

These are the substance of "integrate, do not duplicate."

**1. Screening reads Concord's control catalog, not a keyword corpus.**
ATO Bot hand-maintains a keyword dictionary spanning twenty control families
(`app/services/ingestion/corpus.py`) and has since layered an LLM screener on top
of it. Concord's ETL already ingests the full 800-53A Rev 5 catalog into
`ccf.controls`, with a GIN-indexed `search_vector` plus `description`,
`discussion` and `assessment_objective` per control. Screening becomes a
`ts_rank` join against data Concord already owns. This is cheaper than an LLM
screen, needs no dictionary maintenance, and stays current automatically when the
workbook is re-ingested.

**2. Classification is a registered AI action. [PARTIALLY BUILT — corrected 2026-08-10]**
The `ActionDef("classify_evidence_unit", …)` described below **does** exist —
`src/ccf/ai_actions/registry.py:88` — and `classify.py`'s own
`ACTION_KEY = "classify_evidence_unit"` matches it. But registering the
action was only half of this decision, and the other half was never wired
up: `run_stage_classify` (`src/ccf/prep/classify.py`) calls
`ccf.ai.gateway.generate_structured` directly and never calls
`ccf.ai_actions.run_action`, so `ACTION_KEY` is used only as a `purpose=`
string passed to the gateway — the registered `ActionDef` itself is never
looked up or invoked for a classification. No `ai_action_runs` row is ever
created, and consequently there is no citation record, no guardrail
evaluation, no review state, and no `ai_require_human_approval` gate for a
classification. `PrepClassification.ai_action_run_id` and `.model_name` are
always `NULL` as a result. Wiring `run_stage_classify` through
`ai_actions.run_action` (the way the rest of this decision already
describes) is tracked as explicit follow-up work (see "Open follow-ups"
below), not yet done.

**3. Embeddings go through `ccf.ai.gateway`.**
A new `embed()` method on `AIProvider` in `src/ccf/ai/providers/base.py`, reusing
the encrypted per-org credential store rather than adding Voyage or Ollama
clients.

Two constraints discovered while reading the provider layer shape this.
**Anthropic has no embeddings endpoint** — it directs users to third-party
embedding providers — so `embed()` cannot be a required abstract method that all
adapters implement meaningfully. It is therefore a concrete method on the base
class that raises `ProviderError` by default, alongside a
`supports_embeddings: bool = False` class attribute; `OpenAIProvider` overrides
both. A new `prep_embed_provider` setting lets an org running Anthropic for
generation point embeddings at OpenAI, resolved independently of the generation
provider. Second, **there is no `stub` provider class** despite
`Settings.ai_provider` defaulting to `"stub"` — `build_provider` knows only
`anthropic` and `openai` and raises otherwise. Tests therefore inject a fake
adapter by monkeypatching, following the pattern already used in
`tests/test_ai_gateway.py`, rather than relying on a stub that does not exist.

**4. No new document table.**
A polymorphic `(source_kind, source_id)` pair points at either `EvidenceVersion`
or `PolicyVersion`. Bytes resolve through `ccf.evidence.storage.get_backend()`
for evidence and through `uri` or inline `body` for policy.

**5. Evidence strength feeds the existing scorer. [NOT BUILT — corrected 2026-08-10]**
This was the design intent, but the shipped implementation does not do this
either: `src/ccf/evidence/confidence.py` gained `prep_signal()` and
`score_evidence(..., prep_strength=...)`, matching the design and covered by
unit tests, but `score_object()` — the only production caller of
`score_evidence()` in the scoring path — never passes `prep_strength`, so the
adapter is dead code with no live caller. `prep_classifications.evidence_strength`
does not currently reach the confidence scorer at all. Wiring
`score_object()` (or its caller) to look up and pass the relevant
`PrepClassification.evidence_strength` is tracked as explicit follow-up work
(see "Open follow-ups" below), not yet done.

## Architecture

New module `src/ccf/prep/`, new models file `src/ccf/models_prep.py`, tables in
the `ccf` schema. No existing module is refactored; five are extended.

```
EvidenceVersion ─┐
                 ├─→ prep_runs ──→ parse → screen → expand → classify → embed
PolicyVersion  ──┘   (source_kind,   │       │        │         │         │
                      source_id)     ▼       ▼        ▼         ▼         ▼
                                prep_lines prep_   prep_    prep_      prep_
                                          screens  units  classifications embeddings
                                                              │
                                                    ai_action_runs (existing)
                                                    [NOT WIRED -- corrected 2026-08-10:
                                                     the ActionDef is registered but
                                                     run_stage_classify never calls
                                                     ai_actions.run_action, so no row is
                                                     ever written here. See decision #2.]
```

Module layout:

```
src/ccf/prep/
  __init__.py
  parsers/
    base.py         ParsedCell / ParsedBlock / ParsedPage / ParsedDocument
    dispatcher.py   media_type → parser
    pdf.py  docx.py  xlsx.py  pptx.py  text.py
  pipeline.py       stage orchestration + resumption
  screen.py         catalog-driven lexical screen
  expand.py         context expansion
  classify.py       LLM classification via ai.gateway directly [not yet
                    routed through ai_actions -- corrected 2026-08-10, see
                    decision #2]
  embed.py          embedding via ai.gateway
  retriever.py      hybrid lexical + vector retrieval
  jobs.py           DB-backed job queue
```

### Stages

Each stage persists its full output before the next begins, and records its own
status on `prep_runs`. A failure sets `error_stage` and `error` and stops; a
resumed run restarts at the failed stage rather than re-parsing.

**parse** — dispatch by media type to a parser returning a `ParsedDocument`
(pages → blocks → cells, carrying `heading_path`, `table_id`, `row_index`,
`col_index`, `cell_label`). Flattened into `prep_lines`.

**screen** — for each line, rank against `ccf.controls.search_vector` using
`ts_rank`, with `pg_trgm` similarity as a tiebreak for identifier-like tokens.
Produces a `relevance_score`, a `candidate_controls` array and an
`above_threshold` flag. Threshold is configurable per run and snapshotted into
`config_snapshot`. Deliberately inclusive: false positives are cheap here and
resolved downstream, false negatives are unrecoverable.

**expand** — for each above-threshold line, build a semantically complete unit,
preferring in order: the same logical block; the same table row plus inherited
column headers; the same section; a fixed window of `prep_expand_window` lines
either side within the same page; the trigger line alone. Records
`source_line_ids` for traceback.

**classify** — batched calls over units, using `gateway.generate_structured`
directly with a JSON schema, **not** routed through `ai_actions.run_action`
despite the `classify_evidence_unit` `ActionDef` being registered for it
[corrected 2026-08-10, see decision #2]. Returns control identifiers,
`artifact_type` (policy / procedure / technical implementation / testing evidence
/ management approval), `evidence_strength`, and `model_confidence`.

**embed** — units to `Vector(1024)` via the gateway, batched, with `model_name`
recorded so a model change is detectable rather than silent.

pgvector columns require a fixed dimension, so 1024 is fixed in the schema rather
than configurable. `prep_embed_dimensions` is a **validation** setting, not a
column width: on resolve, the embed stage asserts the provider's model emits
vectors of that width and fails the stage with a clear error on mismatch, rather
than writing truncated or rejected vectors. Moving to a different width is a
migration, deliberately.

### Worker

`ccf.prep_jobs` is a claim-based queue (`SELECT … FOR UPDATE SKIP LOCKED`) drained
by a new `ccf prep-worker` Typer command, deployed as a docker-compose profile
mirroring the existing `poller` and `scheduler` services. Stale jobs left in
`running` past a configurable age are reaped back to `pending` on worker start,
so a crashed container does not strand work. No Redis, no Celery, no new runtime
service type.

## Data model

All tables in schema `ccf`, all org-scoped for multi-tenancy, following existing
SQLAlchemy 2.0 `Mapped` conventions.

| Table | Key columns |
|---|---|
| `prep_runs` | `source_kind` (`evidence_version`\|`policy_version`), `source_id`, `organization_id`, `status`, `stage_parse`/`stage_screen`/`stage_expand`/`stage_classify`/`stage_embed`, `config_snapshot` JSONB, counters, `error_stage`, `error` |
| `prep_lines` | `run_id`, `line_number`, `page_number`, `section_path`, `block_id`, `block_type`, `table_id`, `row_index`, `col_index`, `cell_label`, `content` |
| `prep_screens` | `line_id`, `run_id`, `relevance_score`, `candidate_controls` JSONB, `above_threshold`, `method` |
| `prep_units` | `run_id`, `trigger_line_id`, `source_line_ids` JSONB, `content`, `page_numbers` JSONB, `section_path`, `table_coordinates` JSONB, `token_count`, `search_vector` TSVECTOR |
| `prep_classifications` | `unit_id`, `control_identifiers` JSONB, `artifact_type`, `evidence_strength`, `model_confidence`, `ai_action_run_id` FK |
| `prep_embeddings` | `unit_id`, `model_name`, `embedding` `Vector(1024)` |
| `prep_jobs` | `run_id`, `status`, `attempts`, `claimed_at`, `claimed_by`, `next_stage` |

`control_identifiers` holds `ccf.controls.identifier` values rather than integer
FKs, matching how `EvidenceObject.control_id` already tags controls, and keeping
classifications durable across catalog re-ingest.

Status vocabularies, fixed here so they are not reinvented per table.
`prep_runs.status`: `pending` · `running` · `complete` · `failed` · `unsupported`
· `orphaned`. Each `stage_*` column: `pending` · `running` · `complete` ·
`failed` · `skipped`. `prep_jobs.status`: `pending` · `claimed` · `done` ·
`failed`. All are `String(32)` with an application-level check rather than a
Postgres enum, matching the convention `AssessmentControlResult.finding` already
follows — enum changes need a migration, and these vocabularies will grow as
later slices land.

Traceability chain: `prep_units.source_line_ids → prep_lines → page_number +
section_path + table cell`. Every retrieved passage cites a page and, where the
source was tabular, a specific cell.

## Retrieval

```python
async def retrieve(
    session, *, org_id: int, control_identifier: str,
    system_id: int | None = None, k: int = 8,
) -> list[RetrievedUnit]
```

Fuses pgvector cosine distance against `prep_embeddings.embedding` with `ts_rank`
over `prep_units.search_vector`, combined by reciprocal-rank fusion, filtered by
org, system and source kind. Hybrid rather than pure vector because control
identifiers, product names and hostnames are exact-match tokens that embeddings
handle poorly, while paraphrased policy language is exactly what lexical search
misses. Default `k` follows the existing `ai_max_context_docs` setting.

## Error handling

Parser failure on a single document fails that run only, recording `error_stage`
and `error`; the queue continues. Unsupported media types (images, Visio) are
recorded with status `unsupported` rather than failing — they are a known gap, not
an error. Provider failures during classify or embed are retried with backoff and,
on exhaustion, leave the run resumable at that stage with prior stages intact.
A run whose source `EvidenceVersion` has been deleted is closed as `orphaned`.
Stale `running` jobs are reaped on worker start.

## Scope boundaries

**In:** PDF (PyMuPDF), DOCX, XLSX, PPTX, plain text.

**Deferred, with rationale:** OCR for images requires `pytesseract` and a system
Tesseract binary, which would change the container base image; Visio (`vsdx`) is
rare enough not to earn its place in the first slice. Both are recorded as
`unsupported` so the gap is visible in the data rather than silent.

## Infrastructure changes

- `docker-compose.yml`: `postgres:16-alpine` → `pgvector/pgvector:pg16`
- `.github/workflows/ci.yml` line 17: `postgres:16` → `pgvector/pgvector:pg16`
- New migration: `CREATE EXTENSION IF NOT EXISTS vector`, alongside the existing
  `pg_trgm` and `pgcrypto` in `migrations/versions/0001_baseline.py`
- New dependencies: `pymupdf`, `python-pptx`, `pgvector`
- New settings (prefix `CCF_`): `prep_enabled`, `prep_screen_threshold`,
  `prep_expand_window`, `prep_embed_provider`, `prep_embed_model`,
  `prep_embed_dimensions`, `prep_worker_batch_size`,
  `prep_job_stale_after_minutes`

The pgvector image is a drop-in for stock PG16 — same major version, same data
directory layout — so the swap needs no data migration.

## Testing

Against real Postgres, following the existing `tests/conftest.py` pattern.

- **Parsers:** one fixture document per format, asserting structure preservation —
  a known table cell resolves to the correct `row_index`/`col_index`/`cell_label`,
  and a known heading resolves to the correct `section_path`.
- **Resumption:** force a stage-3 failure, resume, assert stages 1–2 are not
  re-executed and their rows are unchanged.
- **Screening:** a fixture policy line about multi-factor authentication surfaces
  `IA-2` from the seeded catalog above threshold; an unrelated line does not.
- **Expansion:** a line inside a table expands to include inherited column
  headers; a line inside a paragraph expands to the block, not the page.
- **Classification and embedding:** run against a fake adapter injected by
  monkeypatching `build_provider`, per `tests/test_ai_gateway.py`. No network
  access in CI.
- **Retrieval:** on a fixture set, hybrid fusion ranks the correct unit above what
  either lexical or vector alone achieves.
- **Traceability:** every unit returned by `retrieve` resolves back to a page
  number and, for tabular sources, a cell.

## Open follow-ups

Two items from the final whole-branch review (2026-08-10), both accuracy
corrections against documentation that claimed more than was built — see the
corrected decisions #2 and #5 above:

- **Wire classification through `ccf.ai_actions.run_action`**, as decision #2
  originally specified, so a classification gets a citation record, guardrail
  evaluation, review state, and the `ai_require_human_approval` gate like
  every other governed AI action. Not started.
- **Wire `prep_classifications.evidence_strength` into the evidence confidence
  scorer**, as decision #5 originally specified — `prep_signal()` and
  `score_evidence(prep_strength=...)` exist and are tested, but no production
  caller passes `prep_strength`. Not started.

Neither blocks production use of the pipeline itself (parse → screen → expand
→ classify → embed → retrieve all function without them); they are gaps
between this design's stated intent and what shipped, not gaps in the pipeline's
own operation.

Later slices in the program, in dependency order: objective-level assessment
engine; closure and remediation loop; generated-artifact validation; AI
dissent path; calibration harness with synthetic evidence.
