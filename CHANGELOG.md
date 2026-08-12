# Changelog

All notable changes to Concord will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added — RLS coverage for the engine tables
- **121 of the 135 tables in the `ccf` schema now carry a `tenant_isolation`
  RLS policy** (migration `0060`) — up from 110. The eleven added:
  `prep_runs`, `prep_lines`, `prep_screens`, `prep_units`,
  `prep_classifications`, `prep_embeddings`, `prep_jobs`, `assessment_jobs`,
  `calibration_snapshots`, `assessment_control_proposals`,
  `assessment_objective_proposals` — every table slices 1–6 added with no
  database backstop, filtered by application-level `organization_id` checks
  alone until now. The remaining fourteen — `controls`, `frameworks`,
  `control_families`, `framework_mappings`, `worksheets`, `worksheet_rows`,
  `ingestion_runs`, `catalog_sources`, `catalog_checks`, `scoring_controls`,
  `statement_templates`, `ksis`, `ai_action_definitions`, `alembic_version`
  — are global reference data with no `organization_id` column and stay
  unpolicied for that reason, named explicitly rather than exempted by
  omission.
- **Both `ENABLE` and `FORCE ROW LEVEL SECURITY`**: the owning role (`ccf`)
  bypasses its own policy without `FORCE`, which would have produced a
  policy that exists, reports as enabled, and is bypassed on exactly the
  connections the application uses. `relforcerowsecurity`, not merely
  `relrowsecurity`, is asserted by every new test.
- **Defence in depth, not a replacement**: no application-level
  organization check was removed. **RLS protects these tables only on the
  request path** — every CLI command and both worker drain loops go through
  `ccf.db.session_scope()`, which leaves the tenant GUC unset (`src/ccf/db.py:98`,
  "CLI/ETL run unscoped (bypass)"), and the prep and assessment-engine
  workers' own job-claim queries remain deliberately unscoped by
  organization (one worker drains every organization's queue by design) —
  so on that path RLS provides no protection at all, and the pre-existing
  application-level ownership checks are what actually protect it, now
  verified independently of RLS by `tests/test_rls_worker_guc_bypass.py`.
- **A registry test** (`tests/test_rls_registry_no_gap.py`) asserts, live
  against the schema, that no tenant-owned table lacks a policy and that the
  fourteen tables with neither a tenant column nor a policy are exactly the
  named global-reference-data allow-list — so a future table added without a
  policy fails CI immediately.
- **Standing debt this slice does not close**: scoping the workers
  themselves (per-tenant claim loops, or an explicit privileged role) is a
  separate, larger question, filed as debt rather than attempted here;
  migrations `0057` and `0058` still lack the `IF EXISTS (SELECT 1 FROM
  pg_roles WHERE rolname = 'ccf_app')` GRANT guard that `0054` establishes
  as the repo standard (`0060` carries it, but does not retrofit the two
  before it); and `ccf.prep.jobs`'s enqueue-time ownership check
  (`resolve_source_organization_id`) is now partly redundant with RLS on the
  API path, but not on the worker path where RLS does not apply — it wants
  a direct worker-path test of its own, not just the API-path coverage
  `tests/test_prep_tenant_isolation.py` already has.

### Added — AI dissent path
- **A `satisfied` verdict can now be challenged** by an independent second
  model call before an assessor ever sees it (`CCF_ASSESSMENT_DISSENT_ENABLED`,
  **disabled by default**). Only `satisfied` is challenged — the expensive
  error direction is a missed finding, not a false alarm — and the
  challenger sees the exact same retrieved passages the primary call saw,
  never a fresh retrieval.
- **Disagreement is never averaged, majority-voted, or tie-broken.** A
  challenger reaching a different, cited verdict flips the objective to
  `insufficient_evidence` (both verdicts retained on
  `AssessmentObjectiveProposal.challenger_verdict` /
  `.challenger_rationale`) and increments
  `AssessmentControlProposal.dissent_count`; the existing rollup already
  forces the whole control to `insufficient_evidence` on any such objective,
  and `accept_control_proposal` already refuses to accept it — no rollup
  code change required. The bar is any *credible* disagreement — a differing
  verdict with at least one citation — never a confidence threshold.
- **Failure isolation:** a challenger failure (provider error, timeout,
  malformed response) never fails the evaluation — the primary verdict
  persists, the challenger columns stay `NULL`, and a warning is logged.
  Runs inside its own `begin_nested()` savepoint, nested inside the
  per-objective savepoint the evaluation already uses.
- **Migration `0059`** adds `dissent_count` (`NOT NULL`, default `0`) to
  `assessment_control_proposals` and four nullable columns to
  `assessment_objective_proposals`: `primary_verdict` (the primary call's
  own verdict, preserved because `verdict` itself is overwritten on a
  genuine disagreement), `challenger_verdict`, `challenger_rationale`, and
  `challenger_ai_action_run_id` (`FK -> ai_action_runs.id`,
  `ON DELETE SET NULL`). Recorded through
  `ccf.ai_actions.provenance.record_ai_run` under its own
  `action_key="challenge_assessment_objective"`, the same pipeline-provenance
  path the primary verdict uses, not the approval-gated `run_action`.
- **Calibration is fingerprint-aware of dissent:** `config_fingerprint` now
  folds in `CCF_ASSESSMENT_DISSENT_ENABLED` and
  `DISSENT_CHALLENGE_POLICY_VERSION` (naming and versioning the
  "satisfied-only" policy), so two snapshots taken with dissent toggled
  between them compare as **not comparable**, never as an unexplained shift
  in `missed_findings`. This is how the slice gets evaluated: the
  calibration harness answers whether dissent reduces missed findings, or
  only throughput.
- `GET /api/assessment-engine/proposals/{id}` surfaces `dissent_count` on
  the proposal and `challenger_verdict` / `challenger_rationale` on each
  objective.
- Not retrofitted: objectives evaluated before this slice, or with the flag
  off, carry no dissent record — a `NULL` `challenger_verdict` means either
  "not challenged" or "challenged but the challenge itself failed,"
  distinguishable only in the logs (`assessment.challenger_failed`), never
  from this column alone.

### Added — closure & remediation loop
- **An accepted other-than-satisfied finding now creates a POA&M**, closing
  the dead end where `accept_control_proposal`'s own docstring promised an
  auto-created POA&M that no caller ever actually triggered. Idempotent on
  `source_ref = f"assessment_control_result:{result.id}"` — a repeat
  acceptance finds and leaves alone any existing POA&M rather than
  duplicating or overwriting it. The write is isolated in a `begin_nested()`
  savepoint and logs a warning rather than raising on failure, so a derived
  POA&M write can never cost an assessor their already-accepted finding.
- **Closing an assessment-sourced POA&M enqueues a re-evaluation** of the
  control it remediated (`assessment_control_proposals.source_poam_id`,
  migration `0058`, plus a constraint swap — `uq_control_proposal_first_pass`
  and `uq_control_proposal_source_poam` replace the old flat unique
  constraint — that lets the re-evaluation proposal coexist with the
  first-pass row it re-evaluates). A scan-sourced or profile-gap POA&M
  enqueues nothing; closing the same POA&M twice enqueues exactly one job.
  Reuses the existing `assessment-worker` queue and `AssessmentJob`
  unchanged. `GET /api/assessment-engine/proposals?source_poam_id={id}`
  lists the result, deriving its organization from the named POA&M rather
  than trusting the query argument — a foreign tenant's POA&M id 404s,
  never 403.
- **The engine never retires its own finding**: a passing re-evaluation
  produces a new proposal for a human to accept, exactly like a first-pass
  evaluation — never an auto-close. Deliberately asymmetric with the
  scanner's own auto-close-on-absence behavior (`ccf.ingest.scanners`),
  documented as such: a vulnerability missing from a scan is direct
  evidence the weakness is gone, while a model re-reading prose evidence is
  an opinion about a control.
- Not retrofitted: findings accepted before this slice get no POA&M created
  retroactively. The closure gate (ISSM-08/09) is unchanged.

### Added — calibration harness (reject path + agreement metrics)
- **An assessor can now reject a proposed finding**, completing the
  acceptance gate's other outcome. `POST
  /api/assessment-engine/proposals/{id}/reject` (body `{corrected_finding,
  note}`) calls `reject_control_proposal`, which sets `state="rejected"` and
  records `corrected_finding`, `rejected_by`, `rejected_at`, `rejection_note`
  (four new nullable columns on `assessment_control_proposals`, migration
  `0057`). It mirrors acceptance's `AiActionRun` stamping — `reviewer`,
  `disposition="rejected"`, `decided_at` — on every run linked to the
  control's objectives, so the audit trail records disagreement as
  faithfully as agreement; `mutation_applied` stays `False`, because nothing
  authoritative was written. **It never writes `AssessmentControlResult`**:
  a rejected proposal produces no finding, and writing the engine's wrong
  answer into the SAR with a human's name attached is exactly what this
  guards against. Rejection refuses (`RejectionRefused`, surfacing as 409)
  an already-`accepted` or already-`rejected` proposal (both terminal), a
  `corrected_finding` outside `satisfied` / `other_than_satisfied` /
  `not_applicable` — **`insufficient_evidence` is deliberately excluded**,
  since it is a proposal-only state and an assessor correcting a verdict
  asserts what is true, not declining to say — and a blank `note`, which is
  required.
- **Calibration measures agreement between proposed and assessor-decided
  findings** (`ccf.assessment.engine.calibration`), as a query over rows
  that already exist — no new pipeline. `compute_metrics` reports `decided`,
  `agreed`, `agreement_rate`, and, deliberately never averaged into that one
  figure, **the two error directions separately**: `missed_findings`
  (proposed `satisfied`, corrected to `other_than_satisfied` — a control
  passes that should not, the number to watch in an authorization package)
  and `false_alarms` (the reverse — wasted remediation effort). Any other
  corrected pair counts as `other_disagreements`. `by_family` splits the
  same metrics by control-family prefix, folded through
  `ccf.prep.screen.normalize_control_identifier` so `AC-02` and `AC-2` land
  in one bucket. `GET /api/assessment-engine/calibration` returns these for
  the caller's own organization (derived from `Depends(get_principal)`,
  never a query argument; 400 for an unscoped principal, since there is no
  single organization to report on), reporting `agreement_rate` as `null`
  — "no decisions recorded yet" — rather than `0.0` when `decided` is zero,
  since those are different statements. **Nothing is retrofitted**:
  proposals decided before this reject path existed carry no recorded
  disagreement, so the first snapshot's `decided` count starts at zero — a
  low early count is expected, not a sign anything is wrong.
- **`calibration_snapshots`** (migration `0057`) stores a point-in-time
  measurement plus a `config_fingerprint` — a SHA-256 over
  `prep_screen_threshold`, the rollup policy version
  (`ROLLUP_POLICY_VERSION`), and the evaluation model name. Two snapshots
  are comparable only if all three are unchanged; `compare_snapshots`
  reports differing fingerprints as **not comparable**, not as drift — not
  hypothetical, since `prep_screen_threshold` (default 0.72) was derived
  once with a measured margin of only ~0.03 and will be re-derived, and that
  re-derivation must read as an explained configuration change rather than
  an unexplained accuracy shift. `ccf calibration-snapshot
  <organization_id> [--model]` computes and stores one snapshot, gated on
  `CCF_ASSESSMENT_ENGINE_ENABLED` like the other engine commands.
- **Deliberately out of scope this slice**: no synthetic evidence
  generation, no automatic threshold tuning (the harness measures; a human
  decides), no CI gate failing a build on a metric change (that needs the
  baseline this slice exists to produce first), and no calibration over
  objective-level verdicts (only control-level findings — objective
  verdicts have no individual accept/reject today, so no ground truth to
  compare against). The standing debt list this slice does not close:
  `prep_screen_threshold`'s narrow margin; screening's base-control
  collapse (a citation can never name a specific enhancement); re-preparing
  the same evidence source through a new prep run does not collapse against
  an earlier run's retrievable units, so passages can duplicate across
  runs; a scanned PDF page with no extractable text is skipped with only a
  log line, no persisted marker; and `AssessmentJob` enqueue
  de-duplication is a best-effort SELECT-then-INSERT check, not a database
  constraint — a partial unique index would close the remaining race.

### Added — AI provenance and audit trail for pipeline AI calls
- **Every AI-generated classification and objective verdict now records an
  audit trail.** `ccf.prep.classify` and `ccf.assessment.engine.evaluate` each
  call `ccf.ai_actions.provenance.record_ai_run` after every model call: an
  `ai_action_runs` row (provider, model, prompt version, input/output SHA-256
  hashes) carrying `status="recorded"` — distinguishing it from an
  approval-gated `run_action` run — one `ai_action_citations` row per cited
  passage, and a link back from the pipeline table
  (`PrepClassification.ai_action_run_id`, already present but unused since
  migration 0052; `AssessmentObjectiveProposal.ai_action_run_id`, added by
  migration 0056). Both pipelines deliberately do **not** route through
  `ccf.ai_actions.run_action`: that function takes an entity and builds its
  own prompt, whereas these pipelines' prompts are already bounded — one
  passage, or one objective plus only the passages retrieval returned for it
  — and their citations are validated against those exact candidates, which
  is the safety property that per-call approval would not add; approval
  gating is also unusable at up to 98 objectives for a single control.
  `ActionDef`s for both `classify_evidence_unit` and
  `evaluate_assessment_objective` are registered in `ccf.ai_actions.registry`
  for discoverability, even though nothing dispatches through them.
  **Recording never fails the work it documents**: `record_ai_run` writes
  inside its own savepoint and returns `None` on failure, leaving the
  pipeline row's `ai_action_run_id` `NULL` rather than losing the
  classification or verdict. The no-evidence evaluation path — retrieval
  found nothing, so no model was called — still records a run, with the
  sentinel `provider="none"`, `model=None`, and zero citations
  (`AiActionOutput.uncited=True`); `provider` is a NOT NULL column, so a
  naive `COUNT(*) WHERE provider IS NOT NULL` would wrongly count these
  no-model runs as if a model had run. When `CCF_AI_STORE_PROMPTS` is false,
  the prompt body is withheld and only its SHA-256 is retained.
  `POST /api/assessment-engine/proposals/{id}/accept` stamps `reviewer`,
  `disposition="accepted"`, `decided_at`, and `mutation_applied=True` onto
  every `AiActionRun` linked to the accepted control's objectives (a `NULL`
  `ai_action_run_id` — a recording failure — is skipped, not an error), so one
  query over `ai_action_runs` joined to `ai_action_citations` answers which
  model produced a verdict, from what evidence, and who accepted it —
  exercised end-to-end by `tests/test_ai_provenance_audit.py`.
  `GET /api/ai-actions?status=recorded` lists pipeline-recorded runs,
  principal-scoped like every other endpoint in that router. **Historical
  rows are not retrofitted**: evidence classified and objectives evaluated
  before this change keep a `NULL` `ai_action_run_id` permanently. Deferred,
  deliberately: guardrail evaluation (belongs to `run_action`'s model and
  needs its own per-call policy this slice does not define), per-call
  approval gating of pipeline calls (acceptance is the human gate here, and
  it guards the authoritative write), and provenance for the screen/embed
  stages (screening is deterministic full-text ranking with no model call;
  embeddings produce vectors, not assertions — neither makes a claim an
  auditor would challenge).

### Added — objective-level assessment engine
- **Objective-level assessment engine** (`ccf.assessment.engine`, migration
  0055, `/api/assessment-engine`, `ccf assessment-worker`) — evaluates
  individual NIST SP 800-53A assessment objectives, not whole controls,
  against evidence the prep pipeline retrieved, then rolls the verdicts into a
  *proposed* control finding. The objectives are not a separate dataset: they
  are the sub-clause rows in `ccf.controls` (`control_name IS NULL`) that
  prep's screen stage already excludes, and **nothing is materialised** — a
  proposal stores only the objective's label and a SHA-256 of its text, so a
  catalog re-ingest that rewords an objective makes a stored verdict
  detectable as `stale` rather than silently wrong. The rollup
  (`ccf.assessment.engine.rollup`) applies 800-53A's unanimity rule as a pure
  function of objective verdicts — a model cannot reach it.
  `insufficient_evidence` is a proposal-only outcome at both the objective and
  control level: it means the engine could not tell, which is not the same as
  the control failing, so `POST /api/assessment-engine/proposals/{id}/accept`
  refuses to accept it (and refuses a `stale` or incomplete proposal too).
  **Proposals are inert** — nothing here reaches `AssessmentControlResult`,
  and therefore nothing reaches the SAR generator or an auto-created POA&M,
  until that acceptance call. Evaluation is queued (`ccf.assessment_jobs`,
  drained by the `assessment-worker` compose profile) since evaluating one
  control means a model call per objective; `CCF_ASSESSMENT_ENGINE_ENABLED` is
  **off by default** — the worker spends money on model calls — and gates
  both the router (a disabled deployment gets a plain 404, not a 200 that
  merely confirms the routes exist) and `ccf assessment-worker` (exits
  immediately). Every evaluation records its own AI provenance via
  `ccf.ai_actions.provenance.record_ai_run` rather than routing through
  `ccf.ai_actions.run_action` — see "AI provenance and audit trail for
  pipeline AI calls" below for the full design and what it now answers. The
  three new proposal/job tables carry no row-level-security policies, the same
  exemption as the `prep_*` tables; `systems`, `assessments`, and
  `assessment_control_results` — where an accepted finding actually lands —
  do carry the `tenant_isolation` RLS policy.

### Changed — evidence preparation queue
- `ccf.prep.jobs`'s `claim()`/`reap_stale()` now delegate to the shared
  `ccf.queue.claim_jobs`/`reap_stale_jobs` primitive (extracted for, and now
  shared with, the assessment engine's own job queue) instead of
  reimplementing the `SELECT FOR UPDATE SKIP LOCKED` claim and
  requeue/dead-letter logic locally, so the two queues cannot drift.
  `tests/test_prep_jobs.py` is unchanged and passes unmodified. One
  observable side effect: the shared helper renamed the prep queue's
  structured-log events from `prep.jobs_claimed` / `prep.jobs_reaped` /
  `prep.jobs_dead_lettered` to `queue.jobs_claimed` / `queue.jobs_reaped` /
  `queue.jobs_dead_lettered` — anyone with external log-based alerting on the
  old event names needs to repoint it.

### Added — continuous authorization
- **Assurance query layer** (`ccf/queries/`) — a registry of deterministic,
  parameterized query templates over the authorization data (no AI): expired
  evidence, evidence expiring soon, controls failing across N systems, overdue
  POA&Ms, external grants expiring soon, high-risk AI agents. Each template has a
  typed param schema and a tenant-scoped SQL runner; the same template + params
  always yields the same answer. API `GET /api/queries`,
  `POST /api/queries/{key}/run|export` (CSV); a `/queries` UI (pick → parameterize
  → results table → download CSV) in the Insights nav; `query_templates_health`
  reliability check runs every template to catch schema drift.
- **External collaboration portal** (`ccf/portal/`, `models_portal.py`,
  migration 0036, `docs/portal.md`) — scoped, expiring, token-authenticated,
  fully-audited external access for customers/assessors/vendors with no internal
  account and no cross-tenant leakage. A bearer-token grant carries an expiry, a
  revoke flag, and an explicit allow-list of shared packages/evidence; the service
  is the single authorization boundary (resolve → clamp the session to the grant's
  tenant → return only shared artifacts → audit every access). API
  `POST/GET /api/admin/portal/grants` (+ `/{id}/revoke`), token-authed
  `GET /api/portal/session` + `POST /api/portal/comments`, and a standalone
  `/portal` HTML view. All 7 tables RLS-isolated (share join-tables via a subquery
  against their parent grant's org). Reliability checks
  `external_access_scope_integrity` (fails on any cross-tenant share),
  `external_grant_expiration`, `external_portal_audit_completeness`.
- **Concord-on-Concord self-assurance** (`ccf/self_assurance/`,
  `models_self_assurance.py`, migration 0035, `docs/self-assurance.md`) — Concord
  continuously assesses itself: a seeded *Concord Platform* system whose controls
  (RLS, audit hash-chain, migrations, supply chain, AI guardrails) are evidenced by
  the platform's own reliability checks, versioned + confidence-scored in the
  evidence repository, and exportable as an authorization package (diffable +
  replayable). Reuses the pack runtime (`concord-self-assurance` pack), evidence
  confidence, and package export — no bespoke engine. API
  `POST/GET /api/admin/self-assurance/init|run|status|package`; CLI `ccf self-assess
  init|run|status|export-package`; `/admin/self-assurance` UI.
- **Compliance pack runtime** (`ccf/packs/`, `models_packs.py`, migration 0034) —
  a local-first runtime for framework/control/evidence/rule packs (JSON manifests
  bundled under `ccf/packs/bundled/`; ships `ai-agent-governance`, `nist-ssdf-genai`,
  `concord-self-assurance`). Validate → install (idempotent, materializes controls/
  mappings/evidence-requirements/rules) → per-system **coverage** → conformance
  **tests**; packs can never create cross-tenant data. API `GET /api/packs`,
  `POST /validate|/install`, `/{key}` `/{key}/upgrade|/coverage|/test`; CLI
  `ccf packs list|validate|install|coverage|test`; `/packs` UI;
  `installed_pack_integrity` reliability check.
- **AI agent governance** (`ccf/ai_governance/`, `models_ai_agents.py`,
  migration 0033) — inventory AI agents as privileged non-human actors with their
  autonomy, data access, tools, and system/vendor/policy/control mappings. Pure
  risk scorer (autonomy, regulated/production access, external action, oversight,
  monitoring coverage → 0-100 + rating) runs on create/update; approval workflow,
  monitoring events, incidents, and audited kill-switch. Agents become nodes in
  the assurance graph (agent→system/vendor/control/risk edges), with
  `GET /api/ai-agents/{id}/assurance-impact`. API `GET/POST /api/ai-agents*`;
  CLI `ccf ai-agents list|create|risk-assess|approve|kill-switch`; `/ai-agents`
  UI; `ai_agent_governance` reliability check (unapproved production access,
  high-risk-without-monitoring, overdue review).
- **Typed agentic GRC action layer** (`ccf/ai_actions/`, `models_ai_actions.py`,
  migration 0032) — AI executes *typed*, auditable actions (draft POA&M
  remediation, propose control test, find evidence for a control, draft
  questionnaire answer, …) rather than free-form chat. Optional and **disabled by
  default**: a deterministic, citation-first stub provider runs locally with no AI
  credentials. Every run stores input/output hashes + citations; **authoritative
  mutations happen only on human approval**, gated by guardrails (no cross-tenant
  retrieval, no uncited citation-required mutation, no trust package without
  provenance). API `GET/POST /api/ai-actions*`, review queue, approve/reject,
  guardrail-violations; CLI `ccf ai-actions list|run|review-queue|approve|reject`;
  `ai_disabled_safe_default` / `ai_guardrail_violations` / `ai_action_review_backlog`
  reliability checks.
- **Authorization package provenance, diff & replay** (`ccf/packages/`,
  `models_packages.py`, migration 0031) — persists the normalized *facts*
  (per-KSI/control/evidence/dependency/risk/POA&M/readiness) a package was
  generated from, so two packages can be **diffed** (added/removed/changed by
  fact type) and a package can be **replayed** against the live DB to detect drift
  (read-only — never mutates authoritative state). Assessor-facing **delta memo**.
  API: `GET/POST /api/authorization-packages`, `/{id}`, `/{id}/provenance`,
  `/{id}/diff/{other}`, `POST /{id}/replay`, and
  `GET /api/fedramp/20x/systems/{id}/authorization-delta`. CLI `ccf package
  list|diff|replay` and `ccf fedramp20x delta`.
- **Evidence confidence + reproducibility** (`ccf/evidence/confidence.py`,
  `models_evidence_conf.py`, migration 0030) — a pure scorer weighs source type,
  freshness, digest integrity, review/lock status, replayability, and human-
  attestation dependence into a 0-100 score + band with a per-dimension breakdown;
  connector/scan evidence outscores manual screenshots. `evidence_objects.source_type`
  added. Replay reproduces connector/scan evidence by digest (non-fatal). API:
  `GET /api/evidence-repo/{id}/confidence`, `POST /api/evidence-repo/{id}/replay`,
  `GET /api/evidence-repo/confidence/summary` (confidence %, automated coverage %,
  reproducible %, manual dependency %, stale-fact count). CLI `ccf evidence
  score|replay`; `evidence_confidence_freshness` + `evidence_replayability`
  reliability checks.
- **Assurance graph / authorization digital twin** (`ccf/assurance/`,
  `models_assurance.py`, `routes/assurance.py`, migration 0029) — a typed,
  tenant-isolated relational graph (no external graph DB) built from Concord's
  existing records (systems, controls, KSIs, evidence, scans, POA&Ms, risks,
  vendors, connectors, control tests, evidence objects). Idempotent per-org
  rebuild; each source is isolated so a missing optional module degrades that
  slice, not the build. Impact analysis (BFS blast radius) via
  `GET /api/assurance/impact/{evidence|control-tests|ksis|vendors|connectors}/{id}`;
  system subgraph at `GET /api/assurance/graph/systems/{id}`; `POST …/graph/rebuild`
  (audited). CLI `ccf assurance graph-rebuild|impact`; `/assurance` UI;
  `assurance_graph_freshness` reliability check.

### Added — enterprise hardening (Phase 1)
- **Evidence repository** (`ccf/evidence/`, `models_evidence.py`,
  `routes/evidence_repo.py`, migration 0028) — versioned, content-addressed
  evidence objects with a pluggable storage backend (local FS default; S3/object-
  lock WORM via boto3 when configured). Draft → submitted → approved/rejected
  review flow; approval sets an immutable lock; downloads record access events;
  expiry surfaces in an `evidence_repository` reliability check. API under
  `/api/evidence-repo`, UI at `/evidence`. Sits alongside the existing
  implementation-scoped `/api/evidence` intake (unchanged).
- **OIDC / SSO / SCIM foundation** (`ccf/identity/`, `models_identity.py`,
  `routes/identity.py`, migration 0027) — optional, disabled by default so local
  dev keeps its session login. OIDC authorization-code login (`/auth/login` →
  `/auth/callback`) with **JIT provisioning**, **IdP group → role mapping**, admin
  IdP + mapping APIs, and a **SCIM 2.0** `/api/scim/v2/Users|Groups` endpoint
  (create/update/deactivate) guarded by `CCF_SCIM_BEARER_TOKEN`. Provisioning and
  role changes write to the tamper-evident audit log; deactivation blocks login.
  New `auth_oidc_posture` reliability check.
- **Official OSCAL validation** (`ccf/oscal/validation.py`) — validates SSP /
  Component Definition / POA&M / assessment documents against the upstream NIST
  OSCAL JSON Schemas when `CCF_OSCAL_SCHEMA_DIR` is set, degrading to built-in
  structural checks (with a warning) otherwise; `CCF_OSCAL_REQUIRE_OFFICIAL_SCHEMA`
  fails closed. New `POST /api/oscal/validate`, `ccf oscal validate --path --kind`,
  and an `oscal_official_schema` reliability check.

### Added — server-rendered UI for the new modules
- **Scan ingestion** page (`/scans`) — upload a scan and see reconciliation counts +
  ingestion history.
- **Personnel & access** page (`/personnel`) — onboard/offboard people, screening +
  training KPIs, and access-review campaigns.
- **Vendor questionnaires** (`/vendor-questionnaires` + detail) — send an assessment,
  answer inline, and score/review to rate the vendor. All three appear under the
  Governance mega-menu.

### Added — continuous controls monitoring (CCM parity)
- **Vulnerability-scan ingestion → automated POA&Ms** (`src/ccf/ingest/scanners.py`,
  `POST /api/scans/ingest`). Parses Nessus/Tenable `.nessus` XML, AWS Inspector
  JSON, and generic/Qualys CSV; reconciles findings into the POA&M register
  (open / update / reopen / auto-close) with severity-driven SLA due dates.
  Idempotent re-ingest; provenance in new `ccf.scan_ingestions` (migration 0023,
  which also adds `poams.scanner` + `poams.finding_uid`).
- **Assertion-based control tests** — optional `assertion` JSON on `ControlTest`
  (migration 0024) evaluated against the latest connector capture; on-demand via
  `POST /api/control-tests/{id}/evaluate` and in the scheduler auto-run.
- **OSCAL POA&M export** — `GET /api/oscal/poam/{system_id}` (OSCAL 1.1
  plan-of-action-and-milestones).

### Added — personnel & access (workforce security lifecycle)
- **People** (`ccf.people`) with PS-2 risk designation, PS-3 background screening,
  and PS-4/PS-5 employment lifecycle. Creating a person runs onboarding
  (assigns baseline AT-2 awareness training + opens a screening task);
  `POST /api/personnel/{id}/offboard` opens a high-priority access-revocation task.
- **Security training** (`ccf.training_records`, AT-2/AT-3) — assign + complete
  with evidence; overdue tracking feeds the personnel summary.
- **Access reviews** (`ccf.access_reviews` + `ccf.access_review_items`, AC-2) —
  certification campaigns; completion is blocked until every item has a
  retain/revoke/modify decision.
- `GET /api/personnel/summary` rollup (headcount, screening gaps, overdue
  training, open reviews, pending decisions). Migration 0025; all tenant-isolated.

### Added — vendor security questionnaires (TPRM)
- **Questionnaire templates** (`ccf.questionnaire_templates`) with a built-in
  CAIQ-Lite (10 weighted questions); organizations can define their own.
- **Vendor assessments** (`ccf.vendor_questionnaires` + `ccf.questionnaire_responses`)
  — instantiate for a vendor, answer, and `submit` to score security posture
  (weighted 0-100 → low/moderate/high/critical rating; `no` answers flagged).
  `review` pushes the rating onto the Vendor record and can open a deduped
  remediation Task per flagged gap. Scoring is a pure function in
  `ccf.governance.tprm`. Migration 0026; all tenant-isolated.

### Added — evidence preparation pipeline
- **Evidence preparation** (`ccf.prep`, migrations, `/api/prep`,
  `ccf prep-worker`) — a five-stage pipeline (parse → screen → expand →
  classify → embed) that turns uploaded evidence and policy versions
  (PDF/DOCX/XLSX/PPTX/text) into control-cited, retrievable passages: parse
  preserves page/heading/table-cell structure; screen ranks lines against
  `ccf.controls` via `ts_rank`, collapses candidates to base control
  identifiers so enhancements can't crowd out their base control, and folds
  zero-padded/unpadded spellings (`AC-06`/`AC-6`) to one canonical form since
  the real ingested catalog is not consistently formatted; expand builds
  semantically complete units; classify tags each unit with control
  identifiers, artifact type, and evidence strength by calling the AI gateway
  directly, recording its own AI provenance (`ccf.ai_actions.provenance.record_ai_run`)
  rather than routing through `ccf.ai_actions.run_action` — see "AI provenance
  and audit trail for pipeline AI calls" below. Embed writes pgvector vectors.
  Retrieval (`GET /api/prep/retrieve`) fuses lexical `ts_rank`, pgvector
  cosine similarity, and a classifier-tagged boost by reciprocal-rank fusion,
  with a deterministic tiebreak so repeated identical queries return
  identically ordered evidence. Runs are queued in `ccf.prep_jobs` and drained
  by the `prep-worker` compose profile, which commits each job independently
  and rolls back before recording a failed job's error, so one job's crash —
  including a raw DBAPI error — can't discard another's completed work or
  strand the rest of a claimed batch; a job that keeps crashing is
  dead-lettered after `CCF_PREP_JOB_MAX_ATTEMPTS` reclaims instead of cycling
  forever. `POST /api/prep/runs` queues a run and `GET /api/prep/runs/{id}`
  reports per-stage status. **A prepared classification's evidence strength
  does *not* currently feed the existing evidence confidence scorer**: the
  adapter (`prep_signal()`/`score_evidence(prep_strength=...)` in
  `ccf.evidence.confidence`) exists and is unit-tested, but no production
  caller passes `prep_strength` — `score_object()` (the only caller in the
  scoring path) never does — so it's dead code today; wiring it up is tracked
  as follow-up work, not yet done.

### Changed — evidence preparation
- Postgres image is now `pgvector/pgvector:pg16` (drop-in for stock PG16),
  required for the prep pipeline's vector embeddings.

### Changed — UI & navigation
- **Consolidated the primary navigation** from 11 top-level items into 5
  lifecycle buckets — **Dashboard · Compliance · Authorization · Operations ·
  Insights** — plus a right-side pinned strip (Executive, FedRAMP 20x, AI Gov)
  kept one click from anywhere. Every href/active-key preserved; the mega-menu,
  section nav, and mobile sheet all derive from the regrouped `nav_groups`.
- **Extracted the dashboard overview aggregation** into
  `ccf.analytics.overview.dashboard_overview()` — a single guarded aggregator
  (catalog coverage, per-system readiness, finding/POA&M posture, risk bands,
  ConMon health) that degrades gracefully on an empty database.

### Fixed — UI
- Overview cards no longer clip their tile content: removed `content-visibility`
  paint-containment from `.ovw-card` and made the inner grids shrink-safe
  (`minmax(0,1fr)`, `repeat(auto-fit, …)` for the system tiles). No horizontal
  overflow at 360–1440px.
- WCAG AA contrast fixes (muted text, info chip), an invisible "Overdue" KPI, a
  modernized skip-link, `aria-label`s on all placeholder-only inputs, 44px
  touch targets on coarse pointers, and a live-region for toasts.

## [0.2.0] — 2026-04-15

### Added — data & governance
- `ccf_audit.workbook_versions` (content-addressed by SHA-256) with FK from
  `ingestion_runs.workbook_version_id`.
- `ccf_audit.rejected_rows` quarantine for unparseable rows (surfaced at
  `/quarantine`).
- `ccf_audit.control_history` and `ccf_audit.mapping_history` — SCD-2
  snapshots of every ingested workbook version.
- `contracts/headers.v1_1.json` + `src/ccf/etl/validate.py`: fail-closed
  header contract checking.
- ETL refactor: content-addressed ingest, SCD-2 snapshotting, per-run
  reject quarantine, header drift logging.

### Added — operational CRUD
- Evidence CRUD: `POST/GET/DELETE /api/evidence` tied to implementations.
- POA&M writes: `POST /api/poams`, `PATCH /api/poams/{id}`, `POST /api/poams/{id}/close`.
- Risk register CRUD: `/api/risks` + `/risks` UI.
- Users CRUD: `/api/users` + `/users` UI (pre-auth; governance only).
- Bulk implementation import: `POST /api/systems/{id}/implementations/bulk`.

### Added — reporting & exploration
- Cross-framework mapping search: `GET /api/mappings/search?q=…&framework=…`
  and `/mappings` UI.
- Coverage heatmap: `GET /api/coverage/matrix` and `/coverage` UI (framework × family).
- OSCAL Component Definition export: `GET /api/oscal/component-definition/{system_id}`.
- Workbook version diff: `GET /api/diff/workbook?a=<sha>&b=<sha>` and `/diff` UI.
- System detail page: `/systems/{id}` with coverage KPIs and POA&Ms.

### Added — observability & platform
- Prometheus `/metrics` (HTTP requests total + latency histogram, ingestion
  counters, catalog gauges).
- `slowapi` rate limit (120/min default) with `RateLimitExceeded` handler.
- `.pre-commit-config.yaml` (ruff, mypy, hygiene checks).
- CI: separate job for `web/landing` (Node 20 + typecheck + build).

### Added — docs
- `docs/ARCHITECTURE.md`, `docs/DATA_MODEL.md`, `docs/THREAT_MODEL.md`.
- `docs/runbooks/ingestion-failed.md`, `docs/runbooks/header-contract-mismatch.md`.

### Added — landing page
- `/api/healthz` JSON health endpoint.
- `not-found.tsx` and `error.tsx` branded error pages.
- OpenGraph + Twitter metadata, favicon SVG, keywords.

### Known gaps (see `docs/THREAT_MODEL.md`)
- No OIDC / RBAC yet: writes are unauthenticated.
- No Postgres role split or RLS yet.
- No async worker for evidence-expiry reminders or webhooks.
- OSCAL *import* not implemented.

## [0.1.0] — 2026-04-14

Initial release — FastAPI + HTMX UI + Typer CLI + async SQLAlchemy + Alembic
baseline + Docker Compose + initial test suite + landing page scaffold.

See `README.md` for the full feature surface at 0.1.
