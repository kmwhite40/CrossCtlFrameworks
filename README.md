# Concord

> *A compliance controls platform — cross-framework, cross-ctl, in concord.*

Concord (repo: `CrossCtlFrameworks`, package: `ccf`) is an internal compliance
controls platform. It ingests the **NIST Cross Mappings Rev. 1.1**
workbook into Postgres, normalizes the 5,400 SP 800-53A Rev. 5 assessment objectives
and their 550+ cross-framework mappings, and exposes the data through a FastAPI
service with an HTMX + Tailwind UI, a Typer CLI, and a REST API.

Copyright © 2026 Colleen Townsend. All rights reserved. See [LICENSE](LICENSE).

---

## What it does

- **Ingests** every tab of the workbook (17 sheets).
  `SP.800-53Ar5_assessment` is parsed into typed `ccf.controls` + normalized
  `ccf.framework_mappings`; every other sheet lands in `ccf.worksheets` /
  `ccf.worksheet_rows` with full JSONB payloads.
- **Classifies** each non-core column into a canonical framework
  (FedRAMP, CMMC, NIST 800-171, HIPAA, HITRUST, ISO 27001, SOC 2, CIS v8,
  NIST CSF, GDPR, StateRAMP, CJIS, MARS-E, AWS/Azure/GCP, CDM, CUI Overlay, …).
- **Captures provenance** in `ccf.ingestion_runs` (SHA-256 of source, stats,
  timings, status).
- **Provides a compliance-ops layer** — organizations, systems (FIPS-199 +
  FedRAMP baseline + ATO status), per-system control implementations,
  evidence, assessments, POA&Ms, risks, and an `audit_log`.
- **Serves a UI** at `/` with dashboards, a faceted control browser,
  per-control detail with grouped cross-framework mappings, a framework
  catalog, a generic worksheet viewer, and Postgres full-text search.
- **Publishes a REST API** under `/api` with OpenAPI docs at `/docs`.

## Architecture

```
src/ccf/
├── __init__.py
├── config.py            pydantic-settings, CCF_* env
├── logging.py           structlog (JSON or console)
├── db.py                async SQLAlchemy engine + session_scope
├── models.py            SQLAlchemy 2.0 ORM (reference + operational layers)
├── schemas.py           Pydantic v2 API schemas
├── cli.py               Typer entrypoint: ingest / serve / stats / search / show
├── etl/
│   ├── frameworks.py    canonical framework catalog + header classifier
│   └── pipeline.py      workbook → Postgres (all sheets, dedup-safe)
└── api/
    ├── main.py          FastAPI app factory, CORS, lifespan
    ├── deps.py          get_session dependency
    ├── routes/
    │   ├── health.py        /healthz /readyz
    │   ├── controls.py      /api/controls
    │   ├── frameworks.py    /api/frameworks
    │   ├── worksheets.py    /api/worksheets
    │   ├── search.py        /api/search (Postgres FTS)
    │   ├── systems.py       /api/systems (+ implementations, POA&Ms, summary)
    │   └── ui.py            server-rendered HTMX pages
    ├── templates/       Jinja2 (base, dashboard, controls, detail, search, …)
    └── static/

migrations/              Alembic (baseline 0001_baseline.py)
tests/                   unit + integration (Postgres required)
.github/workflows/ci.yml lint · typecheck · test · SBOM · Trivy · Docker build
```

## Data model (summary)

- `ccf.controls` — typed columns + `audit_payload` JSONB (full raw row) + `search_vector` tsvector.
- `ccf.framework_mappings` — tall table (`control_id`, `framework_id`, `column_key`, `value`), one row per non-null mapping; GIN trigram index on `value`.
- `ccf.frameworks`, `ccf.control_families` — reference catalogs.
- `ccf.worksheets` / `ccf.worksheet_rows` — generic landing for non-primary tabs.
- `ccf.ingestion_runs` — provenance: source path, SHA-256, timing, stats JSONB.
- Operational: `ccf.organizations`, `ccf.users`, `ccf.systems`,
  `ccf.control_implementations`, `ccf.evidence`, `ccf.assessments`,
  `ccf.assessment_results`, `ccf.poams`, `ccf.risks`, `ccf.audit_log`.

## Quickstart

### Docker (recommended)

```sh
mkdir -p data
cp "NIST Cross Mappings Rev. 1.1.xlsx" data/

docker compose up -d db migrator api
docker compose --profile etl run --rm etl

open http://localhost:8000
open http://localhost:8000/docs
```

### Local

```sh
make install          # venv + editable install with dev extras
docker compose up -d db
make migrate          # alembic upgrade head
make ingest           # reads ./data/NIST Cross Mappings Rev. 1.1.xlsx
make serve            # uvicorn on :8000
```

## CLI

```sh
ccf ingest --xlsx "./data/NIST Cross Mappings Rev. 1.1.xlsx"
ccf stats
ccf show AC-01
ccf search "multi-factor authentication"
ccf serve --reload
```

## REST API (selected)

| Method | Path | Description |
|---|---|---|
| GET | `/healthz` | Liveness |
| GET | `/readyz` | Readiness (DB check) |
| GET | `/api/controls?family=AC&baseline=high&q=mfa` | Filtered catalog |
| GET | `/api/controls/{identifier}` | Control + grouped framework mappings |
| GET | `/api/controls/families` | Family catalog |
| GET | `/api/frameworks` | Framework catalog with mapping counts |
| GET | `/api/frameworks/{code}/controls` | All mappings for a framework |
| GET | `/api/worksheets` · `/api/worksheets/{slug}` | Generic tab viewer |
| GET | `/api/search?q=...` | Postgres full-text search over controls |
| GET | `/api/systems/{id}/summary` | Compliance summary (coverage %, POA&Ms) |
| PATCH | `/api/systems/{sid}/implementations/{cid}` | Upsert implementation state |

Full schema at `/openapi.json` / Swagger UI at `/docs`.

## Tests & quality

```sh
make test            # pytest (requires a running Postgres; see tests/conftest.py)
make lint            # ruff
make typecheck       # mypy strict
make sbom            # CycloneDX SBOM
make scan            # Trivy HIGH/CRITICAL scan
```

CI runs lint + mypy + pytest against a Postgres 16 service container, plus a
supply-chain job producing an SBOM + `pip-audit` + Trivy scan, plus a Docker
build smoke test.

## Configuration

All settings are `CCF_*` environment variables (see [.env.example](.env.example)):

- `CCF_DATABASE_URL` — async DSN used by the API/CLI.
- `CCF_DATABASE_URL_SYNC` — sync DSN used by Alembic + tests.
- `CCF_LOG_LEVEL`, `CCF_LOG_JSON`.
- `CCF_API_HOST`, `CCF_API_PORT`, `CCF_API_CORS_ORIGINS`.
- `CCF_WORKBOOK_PATH`.

## Security posture (today vs. roadmap)

Today: non-root container, tini PID 1, HEALTHCHECK, typed pydantic config,
SBOM in CI, Trivy/pip-audit in CI, Alembic-managed schema, structured logs.

Roadmap (see design review in git history): DB role split
(`ccf_migrator`/`ccf_etl`/`ccf_app`/`ccf_ro`), append-only `ccf_audit` schema
with `REVOKE UPDATE,DELETE`, OIDC login + RBAC on writes, RLS for multi-tenant,
pgaudit, workbook object-store with object lock, cosign-signed images, OTEL
tracing + Prometheus `/metrics`, runbooks and SLOs.

## Project status

Early. The ingestion pipeline, data model, API, UI, CLI, Alembic baseline,
Docker/Compose, CI, and initial test suite are in place. Authentication,
SCD-2 history, OSCAL export, and production runbooks are next.

---

Copyright © 2026 Colleen Townsend. All rights reserved.
