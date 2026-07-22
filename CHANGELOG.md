# Changelog

All notable changes to Concord will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
