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
                    │  ext: pg_trgm, pgcrypto    │
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
- Evidence expiry reminders + webhooks (needs a worker).
- OSCAL *import* (export is live at `/api/oscal/component-definition/{id}`).
