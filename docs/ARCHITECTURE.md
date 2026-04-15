# Concord — Architecture

Copyright © 2026 Colleen Townsend. All rights reserved.

## Service topology

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Concord service (single container image)                                │
│                                                                         │
│   FastAPI (HTMX UI @ /, REST @ /api, OpenAPI @ /docs, /metrics, /*z)    │
│   Typer CLI  (ingest, stats, show, search, serve)                       │
│   Alembic migrator (alembic upgrade head)                               │
│   ETL (openpyxl → staged insert → tsvector refresh)                     │
└──────────────┬─────────────────────────────────────────┬────────────────┘
               │                                         │
        OIDC (planned)                              OTLP (planned)
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

`web/landing/` is a **separate** Next.js 14 application (marketing site) —
independent of the FastAPI service.

## Request path

1. Request hits FastAPI → `metrics_middleware` records method/route/status
   and duration on `ccf_http_requests_total` + `ccf_http_request_duration_seconds`.
2. Route handler pulls an async SQLAlchemy session via `get_session` dep.
3. UI routes render Jinja2 templates; REST routes return Pydantic v2 JSON.
4. `/metrics` scrape exposes Prometheus text format.
5. Writes: any mutation records an `audit_log` row (schema ready, wiring
   pending with OIDC integration).

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
- Audit schema (`ccf_audit.*`) exists; append-only grants + pgaudit are
  in the P1 roadmap.

## Deferred / planned

- OIDC + RBAC (see `docs/THREAT_MODEL.md`).
- Postgres role split (`ccf_migrator` / `ccf_etl` / `ccf_app` / `ccf_ro`).
- RLS for multi-tenant.
- Evidence expiry reminders + webhooks (needs a worker).
- OSCAL *import* (export is live at `/api/oscal/component-definition/{id}`).
