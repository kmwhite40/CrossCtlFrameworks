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
  seven `prep_*` tables deliberately carry no row-level-security policies
  (unlike 110 of Concord's 131 `ccf` tables) — every prep query filters by
  `organization_id` in application code instead (`ccf.prep.retriever._base_filters`
  and equivalent per-stage filters), the same pattern the worker already
  relies on (`claim()` is intentionally unscoped, since one worker drains
  every organization's jobs). See `models_prep.py` for the same note next to
  the table definitions.
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
  / `assessment_jobs` tables deliberately carry no row-level-security
  policies, the same exemption as the `prep_*` tables and for the same
  reason: every route and service function filters by `organization_id` in
  application code instead (derived from `Assessment -> System ->
  Organization`, never from a caller-supplied id), and the job claim is
  intentionally unscoped, since one worker drains every organization's queue.
  `systems`, `assessments`, and `assessment_control_results` — the tables the
  accepted finding actually lands in — do carry the `tenant_isolation` RLS
  policy. See `models_assessment_engine.py` for the same RLS and AI-action
  notes next to the table definitions.

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
