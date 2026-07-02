# Changelog

All notable changes to Concord will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
