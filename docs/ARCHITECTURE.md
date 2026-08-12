# Concord — Architecture


## Service topology

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Concord service (single container image)                                │
│                                                                         │
│   FastAPI (landing @ /, HTMX app @ /dashboard + /*, REST @ /api,        │
│            OpenAPI @ /docs, /metrics, /*z)                               │
│   Typer CLI  (ingest, stats, show, search, serve)                       │
│   Alembic migrator (alembic upgrade head)                               │
│   ETL (openpyxl → staged insert → tsvector refresh)                     │
│   Document/report generators (python-docx, openpyxl): SSP, SAR,         │
│            custom reports (xlsx/docx/csv/json), OSCAL export             │
└──────────────┬─────────────────────────────────────────┬────────────────┘
               │                                         │
   OIDC (planned; local auth live)                  OTLP (planned)
               │                                         │
               ▼                                         ▼
     IdP (Okta/Entra/Auth0)                       OpenTelemetry collector
                                                   → Prom / Grafana / Loki

                    ┌────────────────────────────┐
                    │ Postgres 16                │
                    │                            │
                    │  schemas:                  │
                    │    ccf        reference +  │
                    │               operational  │
                    │    ccf_raw    staging      │
                    │    ccf_audit  provenance + │
                    │               quarantine   │
                    │  ext: pg_trgm, pgcrypto,   │
                    │       pgvector             │
                    └────────────────────────────┘
```

The FastAPI service serves its own server-rendered marketing **landing page**
at `/` (Jinja, `landing.html`) as the public front door; the HTMX application
lives at `/dashboard` and the rest of the `/*` routes. The Concord brand logo
ships as a static asset under `static/img/` (used for the topbar mark, landing
hero, and favicon). `web/landing/` is a **separate, optional** Next.js 14
marketing site retained for standalone hosting — it is independent of the
FastAPI service.

## Request path

1. Request hits FastAPI → `metrics_middleware` records method/route/status
   and duration on `ccf_http_requests_total` + `ccf_http_request_duration_seconds`.
2. Route handler pulls an async SQLAlchemy session via `get_session` dep.
3. UI routes render Jinja2 templates; REST routes return Pydantic v2 JSON.
4. `/metrics` scrape exposes Prometheus text format.
5. Writes: `audit_middleware` records every successful mutation (POST/PUT/PATCH/
   DELETE → 2xx/3xx) to `ccf.audit_log` as a **tamper-evident SHA-256 hash
   chain** (`prev_hash` → `row_hash` over the redacted request body), attributed
   to the authenticated `Principal` (else the `X-Actor` header, else
   `CCF_AUDIT_DEFAULT_ACTOR`). Exposed at `/api/audit` + `/audit`; integrity is
   re-checkable via `/api/audit/verify`.
6. Auth (opt-in via `CCF_AUTH_ENABLED`): `auth_gate_middleware` resolves a
   `Principal` from an HMAC-signed session cookie or API token and gates
   non-public paths (`/` and `/static`, `/login`, `/docs`, health remain
   public); REST gets 401, browser routes redirect to `/login`. `require_role`
   enforces RBAC and queries are org-scoped for multi-tenancy.

## ETL path (new in 0.2)

```
xlsx path
  → sha256
  → ccf_audit.workbook_versions  (content-addressed; dedup by sha)
  → ccf.ingestion_runs (fk → workbook_versions; status='running')
  → validate SP.800-53Ar5_assessment headers against contracts/headers.v1_1.json
       ├─ required header missing ⇒ HeaderContractError → status='failed'
       └─ added headers           ⇒ log.info("ingest.header_drift")
  → sheet "SP.800-53Ar5_assessment"
       ├─ rows without identifier  ⇒ ccf_audit.rejected_rows(rule="missing_identifier")
       ├─ upsert ccf.controls
       ├─ normalize ccf.framework_mappings (tall table, one row per non-null mapping)
       └─ snapshot ccf_audit.control_history + ccf_audit.mapping_history (per version)
  → every other sheet
       └─ land in ccf.worksheets / ccf.worksheet_rows (JSONB payload)
  → refresh ccf.controls.search_vector
  → close run (status='succeeded', stats={sheets:{…}, sha256:…})
```

Design intent:
- Content-addressed ingest means `ccf ingest` of the same workbook twice is
  cheap (still creates a run, but no new `workbook_versions` row).
- `control_history` + `mapping_history` are append-only; they carry every
  prior payload so `/diff?a=<sha>&b=<sha>` can compute added/changed/removed.
- Rejects are visible in `/quarantine` — never silently dropped.

## Compliance operations (subsystems)

Built on the reference catalog + operational tables:

- **Live SPRS scoring** (`/scoring`, `/api/scoring`): the 110 CMMC L2 practices
  are seeded as `scoring_controls`; per-system `scoring_statuses` drive a live
  SPRS computation (start 110, deduct 5/3/1, partial 3/5, SSP-gating, floor
  −203) that recomputes on every control state change.
- **SSP builder** (`/ssp`, `/api/ssp`): per-project `ssp_projects` +
  `ssp_control_entries` (seedable per platform: M365 / Azure / AWS GovCloud)
  render a FedRAMP-style `.docx` via `ccf.ssp` (python-docx).
- **CMMC L2 assessment workflow** (`/assessments`, `/api/assessments`):
  per-assessment `assessment_control_results` capture examine/interview/test
  notes and `[a]/[b]` determination findings; produces a Security Assessment
  Report `.docx` (`ccf.assessment.sar`) and auto-creates one POA&M per
  other-than-satisfied finding.
- **Custom report builder** (`/reports`, `/api/reports/build`): scoped by
  org / system / baseline / family / crosswalk, exported as **xlsx, docx, csv,
  or json** (`ccf.reporting`).
- **OSCAL export** (`/api/oscal/*`): OSCAL 1.1 component-definition + SSP JSON.
- **Evidence preparation** (`/api/prep`, `ccf prep-worker`): uploaded evidence
  and policy versions are parsed into structure-preserving lines (page, heading
  path, table cell), screened for relevance against `ccf.controls` via
  `ts_rank` (threshold 0.72, empirically derived against the fully-ingested
  5,430-row 800-53A catalog — the margin between the highest-scoring
  boilerplate line and the lowest-scoring genuine match was only ~0.03, so a
  future catalog re-ingest may require re-deriving it), expanded into
  semantically complete units, classified, and embedded into pgvector.
  `run_stage_classify` calls `ccf.ai.gateway.generate_structured_resolved` (the
  resolved-model variant, not the plain `generate_structured`, since the
  provenance record below needs the model name back) and records every call
  with `ccf.ai_actions.provenance.record_ai_run`: an `ai_action_runs` row
  (provider, model, prompt version, input/output SHA-256 hashes) carrying
  `status="recorded"` — distinguishing it from an approval-gated `run_action`
  run — one `ai_action_citations` row for the unit, and a link back on
  `PrepClassification.ai_action_run_id`. Classification deliberately does not
  route through `ccf.ai_actions.run_action`: that function takes an entity and
  builds its own prompt, whereas classification's prompt is already bounded to
  one passage plus only the candidate controls screening surfaced, and that
  boundedness — not per-call approval — is the safety property. An `ActionDef`
  for `classify_evidence_unit` *is* registered in `ccf.ai_actions.registry` for
  discoverability, even though nothing dispatches through it. Recording never
  fails the classification it documents: `record_ai_run` writes inside its own
  savepoint and returns `None` on failure, leaving `ai_action_run_id` `NULL`
  rather than losing the classification. Evidence classified before this
  recording existed keeps a `NULL` `ai_action_run_id` permanently — historical
  rows are not retrofitted. When `CCF_AI_STORE_PROMPTS` is false, only the
  prompt's SHA-256 is retained, not its text. `GET /api/ai-actions?status=recorded`
  lists these runs, principal-scoped like every other endpoint in that router.
  Screening
  collapses candidates to base control identifiers (`AC-6(2)` → `AC-6`, and,
  since the real catalog is not consistently formatted, also folds zero-padded
  spellings like `AC-06` to the same canonical `AC-6`) so one control's
  enhancements cannot occupy every candidate slot; a consequence is that
  classification always cites a base control, never an enhancement. Retrieval
  fuses three rankers by reciprocal-rank fusion: lexical `ts_rank`, pgvector
  cosine similarity, and a classifier-tagged boost (`1/(k+1)`) for units the
  classifier already linked to the queried control, with a deterministic
  score-then-`unit_id` tiebreak so repeated identical queries return
  identically ordered results. Runs are queued in `ccf.prep_jobs` and drained
  by the `prep-worker` compose profile, which commits each job independently
  (not the whole claimed batch) and rolls back before recording a failed job's
  error, so one job's crash — including a raw DBAPI error, not only a plain
  Python exception — cannot roll back another job's already-completed work or
  strand the rest of a claimed batch in the same cycle; a job stuck `claimed`
  past `prep_job_stale_after_minutes` is reaped back to `pending`, and one that
  keeps crashing is dead-lettered once it hits `prep_job_max_attempts`. Each
  stage persists before the next, so a failed run resumes at the failed stage.
  `POST /api/prep/runs` and `GET /api/prep/retrieve` derive their organization
  from the authenticated principal, not from anything the caller supplies — a
  scoped principal's own organization always overrides an `organization_id` in
  the request; only an unscoped/admin principal's request uses the supplied
  value, mirroring `users.py::create_user`'s existing convention for a NOT-NULL
  `organization_id`. With `CCF_AUTH_ENABLED=false` (the default), every
  principal is unscoped, so the supplied `organization_id` is trusted
  outright — true of the whole app in that mode, not specific to prep. The
  seven `prep_*` tables carry a `tenant_isolation` RLS policy (migration
  `0060`, 2026-08-12 RLS-coverage design), matching 121 of Concord's 135
  `ccf` tables — but as defence in depth, not the primary control: every prep
  query still filters by `organization_id` in application code
  (`ccf.prep.retriever._base_filters` and equivalent per-stage filters), and
  `claim()` is **still, intentionally, unscoped by organization**, since one
  worker drains every organization's jobs by design. That claim path runs
  through `ccf.db.session_scope()`, which leaves the tenant GUC unset and the
  bootstrap (table-owning) role in effect — exactly what every policy in this
  schema treats as bypass — so RLS protects these tables only on the request
  path, not on the worker/CLI path; the application-level guards
  (`ccf.prep.sources.resolve_source_organization_id`, `ccf.prep.pipeline`'s
  per-stage organization reconciliation) are what actually protect that path,
  verified by `tests/test_prep_tenant_isolation.py` and (for the GUC
  mechanism itself) `tests/test_rls_worker_guc_bypass.py`. See
  `models_prep.py` for the same note next to the table definitions.
- **Objective-level assessment engine** (`/api/assessment-engine`,
  `ccf assessment-worker`, `ccf.assessment.engine`): evaluates individual NIST
  SP 800-53A assessment objectives — not whole controls — against evidence the
  prep pipeline already retrieved, then rolls the objective verdicts into a
  *proposed* control finding. The objectives are not a separate dataset: they
  are the sub-clause rows in `ccf.controls` (`control_name IS NULL`,
  `assessment_objective` populated) that prep's screen stage deliberately
  excludes because they aren't controls anyone can cite — which is exactly
  what makes them objectives. **Nothing is materialised**: a proposal
  (`AssessmentObjectiveProposal`) stores only the objective's label and a
  SHA-256 of its text, so a catalog re-ingest that rewords an objective makes
  a stored verdict detectable as `stale` rather than silently wrong. The
  rollup (`ccf.assessment.engine.rollup`) is a pure function of objective
  verdicts, applying 800-53A's unanimity rule — a control is satisfied only
  when every objective is — as application code; a model cannot reach it.
  `insufficient_evidence` is a proposal-only outcome, both at the objective
  level (no retrieved evidence, or the model could not settle the question)
  and as a rollup result: it means the engine could not tell, which is not the
  same as the control failing, so the acceptance path refuses to write it as a
  finding — conflating the two would manufacture a POA&M out of missing
  evidence. **Proposals are inert.** Nothing here reaches
  `AssessmentControlResult` — and therefore nothing reaches the SAR generator
  or an auto-created POA&M, both of which read only `AssessmentControlResult`
  — until an assessor calls
  `POST /api/assessment-engine/proposals/{id}/accept`, which also refuses a
  `stale` proposal or one that never reached `complete`. Evaluation is queued
  (`ccf.assessment_jobs`, drained by the `assessment-worker` compose profile)
  because evaluating one control means calling a model once per objective,
  too slow for a request cycle; retrieval and acceptance are synchronous.
  `CCF_ASSESSMENT_ENGINE_ENABLED` is **off by default** — like the prep
  pipeline, the worker spends money on model calls — and gates both
  `app.include_router(assessment_engine.router)` (disabled means a plain 404,
  the routes absent from `/openapi.json`, not a 200 that merely confirms they
  exist) and `ccf assessment-worker` (exits immediately without draining
  anything). Like prep classification above, `ccf.assessment.engine.evaluate`
  calls `ccf.ai.gateway.generate_structured_resolved` and records every
  evaluation with `ccf.ai_actions.provenance.record_ai_run` — an
  `ai_action_runs` row, one `ai_action_citations` row per passage the model
  actually cited (`cited_unit_ids`, not everything retrieval offered), and a
  link back on `AssessmentObjectiveProposal.ai_action_run_id` (migration
  0056) — and, for the same reason as classification, deliberately does not
  route through `ccf.ai_actions.run_action`: the prompt is already bounded to
  one objective plus only the passages retrieval returned for it, and its
  citations are validated against that exact set, which is the safety
  property; per-call approval is also unusable at up to 98 objectives for a
  single control. An `ActionDef` for `evaluate_assessment_objective` *is*
  registered in `ccf.ai_actions.registry`, same as classification's. Retrieval
  finding nothing for an objective is not an error and skips the model call
  entirely, but still records a run, with the sentinel `provider="none"`,
  `model=None`, and zero citations (`AiActionOutput.uncited=True`);
  `provider` is a NOT NULL column, so a query that counts runs by
  `provider IS NOT NULL` would wrongly count these no-model runs as if a
  model had run. `POST /api/assessment-engine/proposals/{id}/accept` stamps
  `reviewer`, `disposition="accepted"`, `decided_at`, and
  `mutation_applied=True` onto every `AiActionRun` linked to the accepted
  control's objectives (a `NULL` `ai_action_run_id` — a recording failure —
  is skipped, not an error), so one query over `ai_action_runs` joined to
  `ai_action_citations` answers which model produced a verdict, from what
  evidence, and who accepted it (`tests/test_ai_provenance_audit.py`).
  Historical proposals predate this column and keep a `NULL`
  `ai_action_run_id` permanently — historical rows are not retrofitted.
  The three `assessment_control_proposals` / `assessment_objective_proposals`
  / `assessment_jobs` tables carry a `tenant_isolation` RLS policy (migration
  `0060`, 2026-08-12 RLS-coverage design), the same as the `prep_*` tables —
  but as defence in depth, not the primary control: every route and service
  function still filters by `organization_id` in application code (derived
  from `Assessment -> System -> Organization`, never from a caller-supplied
  id), and the job claim is **still, intentionally, unscoped**, since one
  worker drains every organization's queue by design. That claim path runs
  through `ccf.db.session_scope()`, which leaves the tenant GUC unset and the
  bootstrap (table-owning) role in effect — exactly what every policy in this
  schema treats as bypass — so RLS protects these three tables only on the
  request path, not on the worker/CLI path; the application-level guard
  (`ccf.assessment.engine.jobs.enqueue_reevaluation`'s `result_org_id`
  check) is what actually protects that path, verified by
  `tests/test_assessment_engine_api.py::test_create_proposal_app_check_rejects_cross_tenant_assessment_indep_of_rls`
  and (for the GUC mechanism itself) `tests/test_rls_worker_guc_bypass.py`.
  `systems`, `assessments`, and `assessment_control_results` — the tables the
  accepted finding actually lands in — do carry the `tenant_isolation` RLS
  policy, enforced on every path since they have no worker/CLI bypass of this
  kind. See `models_assessment_engine.py` for the same RLS and AI-action
  notes next to the table definitions.
- **RLS coverage** (migration `0060`, 2026-08-12 RLS-coverage design): 121 of
  the 135 tables in the `ccf` schema carry a `tenant_isolation` policy —
  every tenant-owned table has one. The remaining fourteen are global
  reference data with no tenant dimension and are named explicitly rather
  than exempted by omission: `controls`, `frameworks`, `control_families`,
  `framework_mappings`, `worksheets`, `worksheet_rows`, `ingestion_runs`,
  `catalog_sources`, `catalog_checks`, `scoring_controls`,
  `statement_templates`, `ksis`, `ai_action_definitions`, and
  `alembic_version` — none carries an `organization_id` column.
  `tests/test_rls_registry_no_gap.py` asserts both sides of this split live
  against the schema, so a future tenant-owned table added without a policy
  fails CI immediately rather than shipping unnoticed. **RLS here is defence
  in depth, not a replacement for application-level scoping** — every route,
  service function, and worker still derives and checks `organization_id` in
  code, and this slice removes none of those checks. The one place RLS
  provides no protection at all is the prep and assessment-engine worker
  processes' own job-claim queries, which run unscoped by design (one worker
  drains every organization's queue in a single query) — see "Evidence
  preparation" and "Objective-level assessment engine" above for that
  exception named alongside the application-level check that actually
  covers it.
- **Calibration harness** (`/api/assessment-engine/proposals/{id}/reject`,
  `/api/assessment-engine/calibration`, `ccf calibration-snapshot`,
  `ccf.assessment.engine.{service,calibration}`): completes the acceptance
  gate's other outcome and measures how often the engine's proposed findings
  match assessors' decisions. `POST .../reject` (body `{corrected_finding,
  note}`) is `accept`'s sibling: `reject_control_proposal` sets
  `state="rejected"`, records `corrected_finding`, `rejected_by`,
  `rejected_at`, `rejection_note` (migration `0057`), and mirrors acceptance's
  `AiActionRun` stamping (`reviewer`, `disposition="rejected"`, `decided_at`)
  on every run linked to the control's objectives — except `mutation_applied`
  stays `False`, because nothing authoritative was written. **It never writes
  `AssessmentControlResult`**: a rejected proposal produces no finding, and
  writing the engine's wrong answer into the SAR with an assessor's name
  attached is exactly what this path exists to prevent. `RejectionRefused`
  (409, not 500) blocks rejecting an already-`accepted` or already-`rejected`
  proposal (both terminal), a `corrected_finding` outside
  `CORRECTED_FINDINGS` — **`insufficient_evidence` is deliberately excluded**,
  because it is a proposal-only state describing what the engine could not
  tell, and an assessor correcting a verdict is asserting what is true, not
  declining to say — and a blank `note`, which is required: a rejection
  without a reason tells calibration the engine was wrong but not how, and
  "how" is what makes the metric actionable.

  `ccf.assessment.engine.calibration.compute_metrics` is a query over rows
  that already exist — accepted proposals are agreement, rejected ones with a
  `corrected_finding` are disagreement — with no new pipeline. It reports
  `decided`, `agreed`, `agreement_rate`, and, critically, **two error
  directions that are never averaged into one figure**: `missed_findings`
  (proposed `satisfied`, corrected to `other_than_satisfied` — a control
  passes that should not, a missed finding in an authorization package, the
  number to watch) and `false_alarms` (the reverse — wasted remediation
  effort, annoying but not dangerous). Collapsing the two into a single
  accuracy number would hide exactly the number worth watching;
  `agreement_rate` is reported alongside them, never instead of them. Any
  other corrected pair (e.g. a correction to `not_applicable`) counts as
  `other_disagreements`. `by_family` groups the same split by control-family
  prefix (`control_family`, folded through
  `ccf.prep.screen.normalize_control_identifier` first so `AC-02` and `AC-2`
  land in one bucket) so a model reliable on one family and unreliable on
  another is visible as that, not averaged away. Zero decided proposals
  yields `decided=0, agreement_rate=0.0` from the function, but
  `GET /api/assessment-engine/calibration` reports the field as `null`
  ("no decisions recorded yet"), not `0.0` ("always wrong") — those are
  different statements. **Nothing is retrofitted**: proposals decided before
  this reject path existed carry no recorded disagreement at all, so the
  first snapshot's `decided` count starts at zero and a low early count is
  expected, not a sign anything is wrong.

  `CalibrationSnapshot` (migration `0057`) stores one measurement plus a
  `config_fingerprint` — a SHA-256 over `prep_screen_threshold`, the rollup
  policy identity (`ROLLUP_POLICY_VERSION`), and the evaluation model name.
  Two snapshots are comparable only if all three are unchanged;
  `compare_snapshots` reports differing fingerprints as `{"comparable":
  False, "reason": "configuration changed between snapshots", ...}` rather
  than computing a delta — a distinct outcome, not a misleading number. This
  is not hypothetical: `prep_screen_threshold` (default 0.72) was derived
  once against one catalog snapshot with a measured margin of only ~0.03 (see
  "Evidence preparation" above), so it will be re-derived, and that
  re-derivation must read as an explained configuration change, not
  unexplained drift. `ccf calibration-snapshot <organization_id> [--model]`
  computes and stores one snapshot, gated on `CCF_ASSESSMENT_ENGINE_ENABLED`
  like the other engine commands. Both `POST .../reject` and
  `GET .../calibration` derive their organization from `Depends(get_principal)`
  — never a body or query argument — matching `evidence_repo.py`'s
  convention; a foreign tenant's proposal 404s (never 403), and an unscoped
  principal (`CCF_AUTH_ENABLED=false`, which has no single organization to
  report on) gets a 400 from `/calibration` rather than a guess.

  Deliberately out of scope: no synthetic evidence generation, no automatic
  threshold tuning (the harness measures; a human decides), no CI gate
  failing a build on a metric change (that needs the baseline this slice
  exists to produce first), and no calibration over objective-level
  verdicts — only control-level findings, since objective verdicts are not
  individually accepted or rejected today and so have no ground truth to
  compare against.

- **Closure & remediation loop** (`ccf.assessment.engine.service`, `.jobs`,
  `/api/poams`, `/api/assessment-engine/proposals?source_poam_id={id}`):
  closes the loop the calibration harness measures but does not act on.
  `accept_control_proposal` now creates a POA&M for an accepted
  `other_than_satisfied` finding (`satisfied`, `not_applicable`, and the
  unreachable-via-acceptance `insufficient_evidence` create none), keyed on
  `source_ref = f"assessment_control_result:{result.id}"` — found and left
  alone on a repeat acceptance, never overwritten, so a human's edit to the
  POA&M survives a re-acceptance. The write runs inside `begin_nested()` and
  logs a warning rather than raising on failure: `AsyncSession.rollback()`
  is not savepoint-scoped and would otherwise discard the caller's own
  already-good acceptance, the same trap slice 3 hit with `record_ai_run`.
  Closing an assessment-sourced POA&M (`PATCH /api/poams/{id}` or
  `POST /api/poams/{id}/close`, on any transition into `closed` from a
  non-closed status) enqueues a re-evaluation of the control it remediated;
  a scan-sourced or profile-gap POA&M's `source_ref` never matches the
  convention above and enqueues nothing. The re-evaluation is a second,
  distinct `AssessmentControlProposal` carrying `source_poam_id` (migration
  `0058`) — not a reuse of the accepted first-pass row — which required
  replacing the flat `uq_control_proposal_assessment_control` constraint
  with two partial unique indexes: `uq_control_proposal_first_pass` scopes
  first-pass idempotency to `source_poam_id IS NULL` rows, and
  `uq_control_proposal_source_poam` caps re-evaluation at one proposal per
  POA&M — a database invariant, not just an application-level check, so
  "closing a POA&M twice enqueues one re-evaluation" cannot be lost to a
  race. The existing worker (`ccf assessment-worker` /
  `ccf.assessment.engine.jobs.run_once`) drives a re-evaluation job
  unmodified — it already writes no `AssessmentControlResult`. **The engine
  never retires its own finding**: a passing re-evaluation surfaces as a new
  proposal for a human to accept, exactly like a first pass; the original
  `AssessmentControlResult` from the earlier acceptance is untouched
  regardless of the re-evaluation's outcome, and auto-closing on a passing
  re-test would let the model that raised a finding also decide it is
  resolved, routing around the ISSM-08/09 closure gate below. This is
  deliberately asymmetric with `ccf.ingest.scanners.reconcile_findings`
  (`src/ccf/ingest/scanners.py:397`), which *does* auto-close a POA&M absent
  from the latest scan: a vulnerability missing from a scan is direct
  evidence the weakness is gone, while a model re-reading prose evidence is
  an opinion about a control, and the two warrant different levels of
  trust. `GET /api/assessment-engine/proposals?source_poam_id={id}` lists
  the re-evaluation(s) for one POA&M, deriving its organization from the
  named POA&M's own `system_id -> organization_id` rather than trusting a
  query argument directly — a foreign tenant's POA&M id 404s, never 403.
  Not retrofitted: findings accepted before this slice get no POA&M created
  retroactively, and the closure gate (ISSM-08/09: all milestones complete,
  or dated closure evidence, plus a separation-of-duties `Approval` when
  auth is enabled — `poams.py::_require_closure_gate`) is unchanged — this
  slice observes the transition to `closed`, it does not widen the path to
  it. No email: no SMTP/SES/SendGrid transport exists anywhere in
  `src/ccf`; delivery stays in-app `Notification` rows plus outbound
  webhooks. No overdue escalation or reminders for either a POA&M or a
  re-evaluation proposal sitting unaddressed.

  The standing debt list this slice does not close:
  `prep_screen_threshold`'s narrow margin (this slice gives the means to
  evaluate a change to it, not the change itself); screening's base-control
  collapse, meaning a citation can never name a specific enhancement, only
  its base control; re-preparing the same evidence source through a new prep
  run does not collapse against the prior run's retrievable units (each
  run's own stages clean up after themselves, but nothing scopes retrieval
  to the latest run for one source), so passages can duplicate across runs;
  a scanned PDF page with no extractable text is skipped with only a log
  line (`prep.parse.pdf_page_not_extractable`), no persisted marker;
  `AssessmentJob` enqueue de-duplication (`enqueue_control`) is a
  SELECT-then-INSERT check, not a database constraint — a partial unique
  index over `(control_proposal_id) WHERE status IN ('pending', 'claimed')`
  would close the race a concurrent double-enqueue can still hit today; the
  two competing legacy POA&M-from-findings paths
  (`src/ccf/api/routes/assessments.py:205`'s `POST
  /{assessment_id}/poams-from-findings` and the inline duplicate in
  `src/ccf/api/routes/ui.py`'s `POST /assessments/{assessment_id}/poams`)
  remain unreconciled — this slice's bridge adds a third, distinct
  `source_ref` convention (`assessment_control_result:{id}`) rather than
  touching either, `assessments.py:205` already keys its own idempotency on
  `source_ref = f"assessment:{id}"`, and `ui.py`'s still dedupes on POAM
  title alone, which collides across two systems assessing the same
  control; and migration `0058` (like `0057` before it) re-issues its
  `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO
  ccf_app` as a bare statement, without the `IF EXISTS (SELECT 1 FROM
  pg_roles WHERE rolname = 'ccf_app')` guard migration `0054` establishes as
  the repo standard for exactly this GRANT.

- **Recovery closure** (`ccf.governance.control_tests`, `.conmon`,
  2026-08-12 recovery-closure design): a control test recovering from
  `fail`/`warn` to `pass` (`record_result`, delegated to by both the manual
  UI/API run action and the scheduler's `run_due`) resolves the remediation
  `Task` `_alert_on_failure` opened, and conmon's own scan resolves the Task
  its `_upsert_task` opened when a control implementation returns to
  `healthy`. Neither path auto-closes the POA&M it opened. A `Task` is an
  internal work item with a free status vocabulary and no gate; a `POAM` has
  the ISSM-08/09 closure gate (`api/routes/poams.py::_require_closure_gate`:
  all milestones complete, or dated closure evidence, plus a
  separation-of-duties `Approval` when auth is enabled) — closing one
  asserts, in an authorization package, that a weakness is remediated, and a
  single passing control test or a single healthy scan is not that
  assertion. This is deliberately asymmetric with
  `ccf.ingest.scanners.reconcile_findings` (`src/ccf/ingest/scanners.py:397`),
  which *does* auto-close a POA&M absent from the latest scan, for the same
  reason the assessment engine's closure loop above already documents: a
  vulnerability missing from a scan is direct evidence the weakness is gone,
  where a control test passing once, or a scan reporting a control healthy
  once, is weaker evidence that may cover only part of what the POA&M
  describes. Instead the POA&M gains a dated, id-stamped observation note
  (`remediation_plan`, the same append pattern `scanners.py:410-412` uses
  for its own closure note) and a `Notification` via `governance.bus.notify`
  — the same mechanism `_alert_on_failure` and `conmon.scan` already use for
  "needs a human's attention," queryable and markable-read through the
  existing `/api/notifications` endpoint. Both paths act only on the
  Task/POA&M they themselves created, identified by the same
  `dedupe_key`/`source_ref` the opening code uses, and only while still in
  the state auto-creation left them — a human's edit to any other field
  survives untouched. One interaction worth naming: conmon's own
  `assess_health` treats an open `high`/`critical`-severity POA&M as its own
  at-risk signal, and the POA&M opened for an `overdue` control is
  `severity="high"` — so a control that ever went overdue cannot report
  `healthy` again until a human closes that POA&M, even once the original
  overdue cause is fixed. That is a correct consequence of never
  auto-closing, not a bug. Not retrofitted: Tasks and POA&Ms already open
  when this shipped are untouched; only transitions observed afterward are
  acted on.

- **AI dissent path** (`ccf.assessment.engine.evaluate`, `.calibration`,
  `CCF_ASSESSMENT_DISSENT_ENABLED`, migration `0059`): runs an independent
  second model call — a challenger — against a verdict where being wrong is
  expensive. Self-reported `model_confidence` (`AssessmentObjectiveProposal
  .model_confidence`) is a weak error signal on its own: a model confidently
  wrong is exactly the failure the calibration harness above measures after
  the fact, from an assessor's rejection, and the expensive direction is a
  `satisfied` verdict on a control that is not — a missed finding in an
  authorization package. This tries to catch that before an assessor ever
  sees it, without waiting for a rejection to exist.

  **Satisfied-only, named and versioned as a policy**
  (`DISSENT_CHALLENGE_POLICY_VERSION`, currently `"v1"`): only a `satisfied`
  verdict is challenged. Challenging every objective doubles model calls —
  AC-4 alone has 98 — and a `not_satisfied` or `insufficient_evidence`
  verdict is the cheap error direction (wasted remediation effort, or the
  engine already declining to conclude) rather than the expensive one. The
  challenger sees the *same* retrieved passages the primary call saw, never a
  fresh retrieval — contesting which evidence was retrieved is a different
  problem and would confound the measurement.

  **Disagreement is never averaged, majority-voted, or tie-broken.** When the
  challenger reaches a different, cited verdict, the objective's own `verdict`
  column is overwritten to `insufficient_evidence` — a third, neutral outcome
  that is neither reviewer's opinion — and the challenger's own verdict and
  rationale are retained separately on `challenger_verdict` /
  `challenger_rationale`, so the disagreement itself is not destroyed by
  being resolved one way or the other. `insufficient_evidence` already does
  everything this needs with no further code change: the rollup
  (`rollup.py`) already forces the whole control to `insufficient_evidence`
  on any such objective, `accept_control_proposal` already refuses to accept
  it, and the calibration harness already excludes it from
  `CORRECTED_FINDINGS`. The bar for escalation is any *credible* disagreement
  — a differing verdict with at least one citation — never a confidence
  threshold: gating on the challenger's self-reported confidence would make
  the escalation depend on exactly the signal this slice exists because it
  is not trusted. An **agreeing** challenge is recorded too, not just a
  disagreeing one — `challenger_verdict` populated, the objective's own
  `verdict` unchanged — so "not challenged" (`challenger_verdict IS NULL`)
  stays distinguishable from "challenged and agreed."

  `AssessmentControlProposal.dissent_count` (migration `0059`, `NOT NULL`,
  default `0`, reset to `0` at the top of every `evaluate_control_proposal`
  rerun) counts how many of a control's objectives were contested, so a
  reviewer sees it without a join; `GET /api/assessment-engine/proposals/
  {id}` surfaces it alongside each objective's `challenger_verdict` /
  `challenger_rationale`. The three challenger columns on
  `assessment_objective_proposals` are all nullable, all `NULL` for an
  un-challenged objective by design (never a sentinel), and
  `challenger_ai_action_run_id` is a `NULL`-on-delete FK to
  `ai_action_runs.id` — the challenger's own call is recorded through
  `ccf.ai_actions.provenance.record_ai_run` under its own
  `action_key="challenge_assessment_objective"`, exactly like the primary
  verdict's own recording, and deliberately not through the approval-gated
  `run_action`, for the same reasons the primary evaluation isn't (see
  "Objective-level assessment engine" above).

  **Failure isolation.** A challenger failure — a provider error, a timeout,
  a malformed response — must never fail the evaluation: the primary verdict
  is the deliverable, the challenge is an enhancement. The challenger call
  runs inside its own `begin_nested()` savepoint, nested one level deeper
  than the per-objective savepoint `ccf.assessment.engine.service` already
  wraps each objective's evaluation in, and a bare `except Exception` — never
  a manual `session.rollback()`, which is not savepoint-scoped and would
  unwind the caller's already-good primary verdict, the same trap
  `record_ai_run` itself guards against — leaves the objective with its
  primary verdict, `NULL` challenger columns, and a warning log
  (`assessment.challenger_failed`). A `NULL` `challenger_verdict` therefore
  means either "not challenged" or "challenged, but the challenge failed" —
  the two are distinguishable only in the logs, never from this column
  alone.

  **`CCF_ASSESSMENT_DISSENT_ENABLED`** defaults to `false`: like the prep and
  assessment engines above, this spends real money on model calls, doubling
  them on the passing subset, and a deployment must opt in. With it unset,
  `evaluate_objective` never attempts a second call regardless of verdict.
  Enabling it **changes what calibration is measuring**, exactly as much as
  `prep_screen_threshold`, the rollup policy, or the model name do:
  `ccf.assessment.engine.calibration.config_fingerprint` folds in both
  `CCF_ASSESSMENT_DISSENT_ENABLED` and `DISSENT_CHALLENGE_POLICY_VERSION`, so
  toggling dissent between two snapshots makes `compare_snapshots` report
  `{"comparable": false, ...}` rather than an unexplained shift in
  `missed_findings` — this is in fact how the slice is meant to be evaluated:
  the calibration harness answers whether dissent actually reduces missed
  findings, or only throughput. Not retrofitted: objectives evaluated before
  this slice, and any objective evaluated with the flag off, carry no
  dissent record at all.

## Schemas

See `docs/DATA_MODEL.md` for the full ERD.

## Observability

- Structured logs: `structlog` JSON or console (by `CCF_LOG_JSON`).
- Metrics: Prometheus at `/metrics` (text format). Expected scrape interval
  15–30 s.
- Health: `/healthz` (process), `/readyz` (DB SELECT 1), `/livez` (planned).
- Traces: OTEL planned; the spans exist (see `etl.pipeline`) but the
  exporter is not wired.

## Security posture (today)

- Non-root container (`USER 10001`), tini PID 1, HEALTHCHECK.
- Trivy + pip-audit + CycloneDX SBOM in CI.
- Rate limiting: `slowapi` default `120/minute` per remote IP.
- Header contract enforced at ingest.
- **Authentication & RBAC** (opt-in via `CCF_AUTH_ENABLED`): PBKDF2-HMAC-SHA256
  passwords, `secrets` API tokens, HMAC-signed session cookies, `require_role`
  RBAC, and org-scoped multi-tenancy.
- **Tamper-evident audit**: `audit_log` is a SHA-256 hash chain with
  `/api/audit/verify`. Append-only grants + pgaudit remain in the P1 roadmap.

## Deferred / planned

- OIDC / IdP federation (local auth + RBAC are live; see `docs/THREAT_MODEL.md`).
- Postgres role split (`ccf_migrator` / `ccf_etl` / `ccf_app` / `ccf_ro`).
- RLS for multi-tenant (app-level org scoping is live today).
- Evidence expiry reminders + webhooks (evidence *preparation* now has a
  worker — `prep-worker`, see "Evidence preparation" above; expiry reminders
  and webhooks are the remaining gap).
- OSCAL *import* (export is live at `/api/oscal/component-definition/{id}`).
