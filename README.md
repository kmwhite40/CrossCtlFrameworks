# Concord

> *A compliance controls platform — cross-framework, cross-ctl, in concord.*

Concord (repo: `CrossCtlFrameworks`, package: `ccf`) is an internal compliance
controls platform. It ingests the **NIST Cross Mappings Rev. 1.1**
workbook into Postgres, normalizes the 5,400 SP 800-53A Rev. 5 assessment objectives
and their 550+ cross-framework mappings, and exposes the data through a FastAPI
service with an HTMX + Alpine web UI, a Typer CLI, and a REST API.

The interface is a calm, editorial, **top-navigation** shell (no permanent
sidebar): a global nav with per-area mega menus organized into five
authorization-lifecycle buckets — **Dashboard · Compliance · Authorization ·
Operations · Insights** — a contextual section nav, and an editorial hero on
every page. It is **light-first** with a neutral graphite
dark mode, built on a small design-token system in
[`app.css`](src/ccf/api/static/css/app.css) — system typography, a single blue
accent, soft shadows, no chrome-heavy glassmorphism.


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
- **Enforces access & tenancy** — session-cookie + bearer-token auth,
  separation-of-duties RBAC on writes, PostgreSQL **row-level security** on every
  tenant-owned table, and a SHA-256 **audit hash-chain** over all mutations.
- **Serves a UI** at `/` — a top-navigation shell (global nav → section nav →
  page hero) with dashboards, a faceted control browser, per-control detail with
  grouped cross-framework mappings, a framework catalog, a cross-framework
  mapping search, a generic worksheet viewer, and Postgres full-text search.
- **Publishes a REST API** under `/api` with OpenAPI docs at `/docs`.
- **Supports FedRAMP 20x** (see below) — Key Security Indicators, deterministic
  validation, readiness scoring, and a machine-readable authorization package —
  kept logically separate from traditional FedRAMP Rev. 5 but traceable to NIST.
- **Runs continuous controls monitoring** — vulnerability-scan ingestion that
  reconciles findings into POA&Ms, assertion-based control tests over live
  connector captures, plus a **workforce-security lifecycle** (personnel, training,
  access reviews) and **vendor security questionnaires** — each with a REST API, a
  server-rendered UI, and alert-digest integration (see below).
- **Self-checks** via a reliability subsystem (`ccf reliability-check` /
  `/api/admin/reliability`) covering DB, migrations, core services, and the 20x layer.
- **Runs a continuous-authorization layer** — an **assurance graph**
  (authorization digital twin + impact analysis), **evidence confidence scoring**
  with reproducible digests, **authorization packages** with provenance, diff, and
  replay, a **typed, citation-first, human-approved AI action layer** (optional,
  disabled by default), **AI-agent governance** (privileged non-human actors with
  risk scoring + kill-switch), a **compliance-pack runtime** (local-first
  framework/control/evidence/rule packs), **Concord-on-Concord self-assurance**
  (Concord continuously assessing itself), and an **external collaboration portal**
  (scoped, expiring, token-authenticated, fully-audited access for
  customers/assessors/vendors with no internal account), and a **deterministic
  assurance query layer** (reusable, parameterized, exportable questions over the
  authorization data — no AI).
- **Produces a complete, machine-readable authorization package** — an
  end-to-end OSCAL pipeline: define the **system boundary & inventory**, generate a
  real **NIST SP 800-53 Rev 5 SSP**, record an assessment, and export the whole
  **authorization package** (SSP + SAR + POA&M + component-definition) as one ZIP —
  every document **validated against the official NIST OSCAL v1.1.2 JSON Schema**
  (see *Authorization package* below).
- **Verifies control-read accuracy** — an advisory **OSCAL catalog reconciliation
  engine** checks the workbook-sourced controls against the pinned authoritative NIST
  OSCAL 800-53r5 catalog + 800-53B baselines (canonicalization, unknown/withdrawn
  ids, baseline over/under-claims, dangling cross-framework mappings), producing a
  catalog-integrity report (`ccf catalog reconcile`, `/catalog/integrity`).

## Authorization package (OSCAL, NIST 800-53 Rev 5)

An end-to-end, OSCAL-native path from "we have a system" to a downloadable
authorization package — all validated against the **official NIST OSCAL v1.1.2
schemas** (vendored in-package; `validate_document` runs official-schema validation
by default and CI fails the build on any non-conformant export):

- **System boundary & inventory** (`/systems/{id}/boundary`) — first-class,
  tenant-scoped components, inventory items, per-type FIPS-199/800-60 information
  types, and interconnections/ISAs, with **auto-generated boundary + data-flow
  diagrams** (Mermaid, always in sync) and a categorization reconciler that flags
  when the rollup disagrees with the system's triad. Maps to OSCAL
  `system-implementation`.
- **Real 800-53r5 SSP** — an `SSPProject` with `framework="nist-800-53r5"` selects
  the authoritative 800-53B baseline control set for the system's FIPS-199 level
  (287 controls at Moderate), scaffolds each control's **organization-defined
  parameters (ODPs)** from the catalog, and generates an OSCAL SSP
  (`implemented-requirements` + `set-parameters` + boundary-backed
  `system-implementation`) and a FedRAMP-style `.docx`. The existing CMMC L2 /
  800-171 generator is unchanged (`framework="cmmc-800-171"`, the default).
- **Assessment results (SAR)** — `GET /api/oscal/sar/{assessment_id}` emits an OSCAL
  assessment-results document: control-level findings (satisfied / not-satisfied,
  with N/A preserved), evidence observations, and open POA&Ms as risks.
- **Package bundle** — `GET /api/oscal/package/{system_id}` returns a ZIP of
  `ssp.json` + `sar.json` + `poam.json` + `component-definition.json` + a README
  manifest (absent artifacts are omitted and noted, never fabricated).

## FedRAMP 20x

FedRAMP 20x is a cloud-assurance model built on **Key Security Indicators (KSIs)**,
automated validation, machine-readable evidence, and continuous monitoring. Concord
implements it as a first-class, separate layer — traditional FedRAMP Rev. 5 scoring
(`systems.baseline`, `ccf.scoring`) is untouched — while staying **traceable to NIST
SP 800-53** through each KSI's control mapping.

- **KSI catalog** — 51 indicators across the 10 published families
  (CED/CMT/CNA/IAM/INR/MLA/PIY/RPL/SVC/TPR), seeded from
  [`data/fedramp_20x_ksi_catalog.json`](data/fedramp_20x_ksi_catalog.json) (packaged
  fallback ships in the wheel/image). Representative wording + rules; update the seed,
  don't touch business logic.
- **Deterministic validation engine** — evaluates each KSI's machine-readable rule
  (`control_state` / `control_any` / `evidence_present` / `dependency_authorized` /
  `connector_capture` / `any_of` / `manual`) against control implementations,
  evidence, authorized-dependency inventory, and **live cloud-connector captures**
  (Microsoft Graph MFA/session; AWS EBS-encryption/log-retention). No cloud creds
  required — connector-backed KSIs degrade to manual review until captures exist.
- **Readiness scoring** — a separate, documented blend (pass rate, automation
  coverage, evidence completeness, assessor completion, dependency readiness,
  ConMon freshness) → an overall % + a 9-state lifecycle, snapshotted per system.
- **Continuous monitoring** — the scheduler re-validates every 20x system on a
  cadence, records readiness snapshots, and raises **drift** events/alerts
  (pass → warn/fail) to the notification/webhook sink.
- **Authorized-dependency tracking**, **assessor-review workflow** (a finding
  auto-opens a POA&M), and **KSI exceptions** feed the readiness metrics.
- **Machine-readable package** — export to JSON, Markdown, **DOCX**, an
  **OSCAL-shaped** JSON structure (validated against a Concord OSCAL-*subset* schema
  via `jsonschema` — not official OSCAL conformance), or a downloadable **zip bundle**
  (package + OSCAL + evidence manifest).
- **UI** at `/fedramp20x` — KSI catalog by family, per-system readiness, CSO profile,
  dependencies, assessor review, exceptions, and package export. Reverse
  KSI↔control traceability appears on each control's detail page.

Continuous-controls-monitoring (parity with commercial CCM/GRC platforms):
- **Vulnerability-scan ingestion → automated POA&Ms** — `POST /api/scans/ingest`
  parses Nessus/Tenable `.nessus` XML, AWS Inspector JSON, and generic/Qualys CSV,
  then **reconciles** findings into the POA&M register: new weaknesses open POA&Ms
  with severity-driven SLA due dates (Crit 15 / High 30 / Mod 90 / Low 180 days),
  recurring ones update in place, and fixed ones **auto-close** when they drop out of
  the latest scan (re-ingest is idempotent). Provenance is kept in `ccf.scan_ingestions`.
- **Assertion-based control tests** — a `ControlTest` can carry a machine-checkable
  `assertion` (`{odp_key, operator, value}`) evaluated against the latest live
  connector capture, so a test asserts real posture (`mfa_enforced == true`,
  `retention_days >= 90`) instead of only that the connector synced. Run on demand via
  `POST /api/control-tests/{id}/evaluate` or automatically in the scheduler cycle.
- **OSCAL exports** — SSP (`/api/oscal/ssp/{project_id}`), assessment-results/SAR
  (`/api/oscal/sar/{assessment_id}`), POA&M (`/api/oscal/poam/{system_id}`),
  component-definition (`/api/oscal/component-definition/{system_id}`), and a full
  authorization-package ZIP (`/api/oscal/package/{system_id}`).
- **Official OSCAL validation — on by default** — the pinned **NIST OSCAL v1.1.2**
  JSON Schemas ship in-package, so `POST /api/oscal/validate` (and `ccf oscal
  validate`) validate SSP / SAR / POA&M / component-definition against the official
  schemas with no configuration. A small adapter handles OSCAL's draft-07 anchors and
  ECMA `\p{}` patterns; every export is **machine-proven schema-valid** (`mode ==
  "official"`). `CCF_OSCAL_SCHEMA_DIR` overrides the bundled schemas;
  `CCF_OSCAL_REQUIRE_OFFICIAL_SCHEMA` (set in CI) fails closed if official validation
  is unavailable, so a non-conformant export fails the build.
- **UI** at `/scans` — upload a scan and review reconciliation counts + ingestion history.

Personnel & Access (workforce security lifecycle, `/api/personnel` + `/api/access-reviews`):
- **People** with PS-2 risk designation, PS-3 background screening, and PS-4/PS-5
  lifecycle. Onboarding auto-assigns baseline **AT-2** awareness training and opens a
  screening task; **offboarding** opens a high-priority access-revocation task.
- **Security training** (AT-2/AT-3) assignment + completion with evidence, and
  **access-certification reviews** (AC-2) whose completion is gated on every grant
  getting a retain/revoke/modify decision. `GET /api/personnel/summary` rolls up
  screening gaps, overdue training, and pending access decisions.
- **UI** at `/personnel` — onboard/offboard, screening + training KPIs, and reviews.
- Overdue training, incomplete screening, and overdue reviews surface in the alert
  digest each scheduler cycle.

Vendor security questionnaires (TPRM, `/api/questionnaires`):
- **Templates** (built-in CAIQ-Lite + custom) drive weighted question sets.
  Instantiate one for a vendor, answer it, and **submit** to score security
  posture (weighted 0-100 → low/moderate/high/critical); `no` answers are flagged.
- **Review** pushes the rating onto the Vendor record and can open a deduped
  remediation task per flagged gap. Scoring is pure (`ccf.governance.tprm`).
- **UI** at `/vendor-questionnaires` (+ detail) — send, answer inline, and review.
  Overdue questionnaires surface in the alert digest.

GRC operating system (server-rendered modules under the **Governance** nav, each
backed by a JSON API and covered by reliability checks):
- **Executive dashboard** (`/executive`) — a single consolidated rollup: average
  SPRS, systems, open/overdue POA&Ms, evidence freshness, risk-by-residual-band,
  systems-by-ATO, the full data-quality check list, and the top "implement once,
  satisfy many" cross-framework controls. Print/PDF for board reporting. Built on
  the read-only insights layer (`/api/reports/executive`, `/api/admin/data-quality`,
  `/api/mappings/unified`).
- **Trust Center** (`/trust`) — posture summary, framework badges, FAQ, a
  shareable package export (`.md`/JSON), and an **access-request workflow**
  (log a request → approve/deny inline).
- **Audit collaboration workspace** (`/audit-workspace`) — engagements with a
  PBC **evidence-request** list and **findings** tracked through to closure.
- **Regulatory change management** (`/regulatory`) — track framework/regulatory
  updates with applicability, control/policy/system impact, owner, and due dates
  (overdue items surface in the alert digest).
- **Cloud connector registry** (`/connectors`) — register cloud/SaaS connectors
  (Azure/Azure Gov, M365/GCC High, AWS/AWS GovCloud, GCP, GitHub, Jira,
  ServiceNow) and sync for evidence collection.
- **Continuous control tests** (`/control-tests`) — define repeatable tests per
  control, **record a manual result** from the UI, or let the scheduler
  **auto-run** `method='connector'` tests on their cadence. A failing run opens a
  critical alert + a dedup'd remediation task (identical for manual and automated
  triggers via a shared `record_result` helper).
- **Scan ingestion** (`/scans`), **Personnel & access** (`/personnel`), and
  **Vendor questionnaires** (`/vendor-questionnaires`) — the continuous-monitoring,
  workforce-security, and third-party-risk pages described above.
- **Register import/export** — round-trip the POA&M / risk / vendor / policy
  registers: `GET /api/export/{dataset}?fmt=csv|json|md` and
  `POST /api/import/{dataset}` (upserts by org-scoped id; recomputes derived
  scores; returns a `{created, updated, skipped, errors}` summary).

Observability: Prometheus metrics (`ccf_ksi_validations_total`,
`ccf_fedramp20x_validation_duration_seconds`, `ccf_ksi_drift_events_total`,
`ccf_fedramp20x_readiness_pct`) with a ready-to-import Grafana dashboard at
[`deploy/grafana/fedramp20x-dashboard.json`](deploy/grafana/fedramp20x-dashboard.json).

## Architecture

```
src/ccf/
├── __init__.py
├── config.py            pydantic-settings, CCF_* env
├── logging.py           structlog (JSON or console)
├── db.py                async SQLAlchemy engine + session_scope
├── models.py            SQLAlchemy 2.0 ORM (reference + operational layers)
├── models_grc.py        GRC-OS tables (trust, audit, regulatory, connectors, tests)
├── models_people.py     personnel, training, access reviews (PS/AT/AC-2)
├── models_tprm.py       vendor security questionnaires (templates, responses)
├── schemas.py           Pydantic v2 API schemas
├── cli.py               Typer entrypoint: ingest / serve / stats / search / show /
│                        score / ssp-generate / fedramp20x / reliability-check / …
├── etl/
│   ├── frameworks.py    canonical framework catalog + header classifier
│   └── pipeline.py      workbook → Postgres (all sheets, dedup-safe)
├── ingest/
│   └── scanners.py      vuln-scan (Nessus/Tenable/Inspector/Qualys/CSV) → POA&M reconcile
├── catalog/            OSCAL 800-53r5 catalog loader + control-read reconciliation engine
│                        (pinned NIST catalog/baselines in catalog/oscal_data/)
├── boundary/           system boundary & inventory service + summary + Mermaid diagrams
├── oscal/              official OSCAL validation adapter + vendored v1.1.2 schemas/
├── ssp/                SSP generators — CMMC L2/800-171 + nist80053 (800-53r5) + OSCAL/docx
├── governance/          scheduler, digest, conmon, control tests, personnel, tprm, …
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

migrations/              Alembic (0001 baseline → RLS-enforced multi-tenant schema)
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
  `ccf.assessment_results`, `ccf.poams`, `ccf.risks`, `ccf.audit_log` — plus the
  governance (tasks, policies, vendors, approvals, connectors, audit workspace,
  trust center) and FedRAMP 20x (KSIs, states, validation history, dependencies)
  tables.
- Continuous-monitoring & workforce: `ccf.scan_ingestions` (+ `poams.scanner` /
  `finding_uid` for reconciliation), `control_tests.assertion`; `ccf.people`,
  `ccf.training_records`, `ccf.access_reviews` / `access_review_items`; and TPRM
  `ccf.questionnaire_templates`, `ccf.vendor_questionnaires`,
  `ccf.questionnaire_responses`.
- OSCAL authorization pipeline: `ccf.catalog_integrity_reports` (control-read
  reconciliation runs + raw→canonical crosswalk); the boundary model
  `ccf.system_components`, `ccf.inventory_items`, `ccf.information_types`,
  `ccf.interconnections` (RLS, each with a stable `oscal_uuid` + discovery hooks);
  `ssp_projects.framework` (cmmc-800-171 | nist-800-53r5); and `users.locked_until` /
  `failed_login_attempts` (AC-7 lockout).
- Every tenant-owned table is protected by **row-level security** keyed on the
  `ccf.tenant_id` session GUC; `ccf.audit_log` carries a `prev_hash`/`row_hash`
  chain for tamper evidence.

## Quickstart

### Docker (recommended)

```sh
docker compose up -d --build      # builds image, starts db, runs migrator, starts api
```

Then open:

- App:   http://localhost:8088   (landing → dashboard)
- Docs:  http://localhost:8088/docs

> Host ports: the API is published on **8088** (→ container 8000) and Postgres
> on **5433** (→ 5432). Change the `ports:` lines in `docker-compose.yml` if
> either is taken.
>
> Postgres runs as `pgvector/pgvector:pg16` (a drop-in replacement for stock
> PG16 that adds the `vector` extension), not the plain `postgres` image —
> the evidence preparation pipeline's embeddings require pgvector, so a
> self-managed Postgres for local/prod use must have the `vector` extension
> installed.

The database persists in the `ccf_pgdata` Docker volume across restarts. Stop
with `docker compose down` (keeps data) or `docker compose down -v` (full reset).

### Loading the cross-framework catalog

Live Scoring, the SSP builder, and the CMMC L2 assessment workflow seed their
own 110 CMMC practices from bundled data and **work without any ingest**. The
cross-framework **catalog** (Controls / Frameworks / Coverage / Mapping search)
is populated by ingesting the workbook — a one-time step.

The **`NIST Cross Mappings Rev. 1.1.xlsx`** workbook (~26 MB) **ships with the
repo** at `data/NIST Cross Mappings Rev. 1.1.xlsx`, so on any clone or GitHub
zip download you can ingest the catalog directly:

```sh
docker compose --profile etl run --rm etl
```

No file copying is required. If you ever need to ingest a different/updated
workbook, drop it in `./data/` (or point `CCF_WORKBOOK_PATH` at it) and re-run
the `etl` profile. A `Workbook not found: /data/NIST Cross Mappings Rev. 1.1.xlsx`
message means the file was removed or renamed — the app itself keeps running.

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

# FedRAMP 20x
ccf fedramp20x seed-ksi
ccf fedramp20x validate --system-id 1
ccf fedramp20x readiness --system-id 1
ccf fedramp20x list-gaps --system-id 1
ccf fedramp20x dependency-check --system-id 1
ccf fedramp20x monitor                     # continuous-monitoring sweep (drift)
ccf fedramp20x export-package --system-id 1 --format bundle --out pkg.zip

# OSCAL authorization pipeline
ccf catalog reconcile                       # control-read accuracy vs official 800-53r5 catalog
ccf oscal validate <doc.json>              # validate against official NIST OSCAL v1.1.2 schema

# Operations
ccf reliability-check                       # platform + 20x readiness checks
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
| GET | `/api/fedramp/20x/ksis` · `/ksis/{id}` | KSI catalog |
| POST | `/api/fedramp/20x/systems/{id}/validate` | Run deterministic KSI validation |
| GET | `/api/fedramp/20x/systems/{id}/readiness` | 20x readiness rollup |
| GET · POST | `/api/fedramp/20x/systems/{id}/dependencies` | Authorized dependencies |
| POST · PATCH | `/api/fedramp/20x/assessor-reviews` | Assessor review workflow |
| POST · PATCH | `/api/fedramp/20x/exceptions` | KSI exceptions |
| GET | `/api/fedramp/20x/controls/{id}/ksis` | Reverse KSI↔control traceability |
| GET | `/api/fedramp/20x/systems/{id}/package?format=json\|markdown\|oscal\|docx\|bundle` | Authorization package export |
| GET | `/api/reports/executive` | Consolidated executive rollup (posture, risk, POA&M, DQ) |
| GET | `/api/admin/data-quality` | GRC data-completeness checks |
| GET | `/api/mappings/unified` | "Implement once, satisfy many" cross-framework ranking |
| GET · POST | `/api/export/{dataset}` · `/api/import/{dataset}` | Register round-trip (poams\|risks\|vendors\|policies) |
| POST · GET | `/api/scans/ingest` · `/api/scans/ingestions` | Vulnerability-scan ingestion → POA&M reconciliation |
| GET | `/api/oscal/ssp/{project_id}` · `/api/oscal/component-definition/{system_id}` | OSCAL SSP + component-definition export (official-schema validated) |
| GET | `/api/oscal/poam/{system_id}` | OSCAL 1.1 plan-of-action-and-milestones export |
| GET | `/api/oscal/sar/{assessment_id}` · `/api/oscal/sar/system/{system_id}` | OSCAL assessment-results (SAR) export |
| GET | `/api/oscal/package/{system_id}` | Authorization-package ZIP (SSP + SAR + POA&M + component-def + manifest) |
| GET · POST · PATCH · DELETE | `/api/systems/{id}/boundary/{components\|inventory\|information-types\|interconnections}` | System boundary & inventory (OSCAL system-implementation) |
| GET · POST | `/api/catalog/...` · `ccf catalog reconcile` | OSCAL 800-53r5 catalog reconciliation report (`/catalog/integrity` UI) |
| GET · POST | `/api/control-tests` (+ `/{id}/run`, `/{id}/evaluate`) | Continuous control tests; manual result + assertion evaluate |
| GET · POST | `/api/personnel` (+ `/{id}/offboard`, `/summary`) | Personnel lifecycle + workforce-security rollup |
| POST | `/api/personnel/{id}/training` · `/api/training/{id}/complete` | Security-training assignment + completion |
| GET · POST | `/api/access-reviews` (+ items, `/{id}/complete`) | AC-2 access-certification campaigns |
| GET · POST | `/api/questionnaire-templates` · `/api/vendors/{id}/questionnaires` | Vendor questionnaire templates + assessments |
| POST | `/api/questionnaires/{id}/submit` · `/{id}/review` | Score posture + push vendor risk rating |
| GET · POST | `/api/audit/engagements` (+ requests, findings) | Audit collaboration workspace |
| GET · POST | `/api/regulatory` | Regulatory change register |
| GET · POST | `/api/connector-configs` (+ `/{id}/sync`) | Cloud connector registry |
| GET · POST | `/api/trust/access-requests` (+ `/{id}/decide`) | Trust Center access workflow |
| GET | `/api/admin/reliability` | Reliability checks (503 on hard fail) |
| GET | `/api/assurance/systems/{id}/graph` (+ `/impact`) | Assurance graph + change-impact analysis |
| GET · POST | `/api/evidence-repo` (+ versions, review, download) | Versioned, content-addressed evidence with WORM lock |
| GET · POST | `/api/packages` (+ `/{id}/diff`, `/{id}/replay`) | Authorization packages: provenance, diff, replay |
| GET · POST | `/api/ai-actions` (+ `/{id}/approve`, `?status=recorded` for prep/assessment-engine provenance) | Typed, citation-first, human-approved AI actions |
| GET · POST | `/api/ai-agents` (+ `/{id}/kill-switch`) | AI-agent inventory, risk scoring, kill-switch |
| GET · POST | `/api/packs` (+ `/{key}/install\|coverage\|test`) | Compliance-pack runtime |
| POST · GET | `/api/admin/self-assurance/init\|run\|status\|package` | Concord-on-Concord self-assurance |
| POST · GET | `/api/admin/portal/grants` (+ `/{id}/revoke`) | Issue/list/revoke external portal grants |
| GET · POST | `/api/portal/session` · `/api/portal/comments` | External portal (token-authenticated) |
| GET · POST | `/api/queries` · `/api/queries/{key}/run\|export` | Deterministic assurance query templates (+ CSV) |
| POST · GET | `/api/prep/runs` · `/api/prep/runs/{id}` · `/api/prep/retrieve` | Evidence preparation pipeline: queue a run, check stage status, hybrid retrieval |
| POST · GET | `/api/assessment-engine/proposals` (+ `/{id}`, `/{id}/accept`, `/{id}/reject`) | Objective-level assessment: queue evaluation, inspect a proposal, accept it into `AssessmentControlResult`, or reject it with an assessor's correction |
| GET | `/api/assessment-engine/calibration` | Agreement between proposed and assessor-decided findings for the caller's org (`missed_findings` / `false_alarms` reported separately) |

Full schema at `/openapi.json` / Swagger UI at `/docs`.

## Tests & quality

```sh
make test            # pytest (requires a running Postgres; see tests/conftest.py)
make lint            # ruff
make typecheck       # mypy strict
make sbom            # CycloneDX SBOM
make scan            # Trivy HIGH/CRITICAL scan
```

CI runs lint + mypy + **`bandit` SAST** + pytest against a `pgvector/pgvector:pg16`
service container (with `CCF_OSCAL_REQUIRE_OFFICIAL_SCHEMA=1`, so any non-conformant
OSCAL export fails the build), plus a supply-chain job producing an SBOM +
`pip-audit` + Trivy scan, plus a Docker build smoke test.

## Configuration

All settings are `CCF_*` environment variables (see [.env.example](.env.example)):

- `CCF_DATABASE_URL` — async DSN used by the API/CLI.
- `CCF_DATABASE_URL_SYNC` — sync DSN used by Alembic + tests.
- `CCF_LOG_LEVEL`, `CCF_LOG_JSON`.
- `CCF_API_HOST`, `CCF_API_PORT`, `CCF_API_CORS_ORIGINS`.
- `CCF_ENV` — deployment environment. **Defaults to `production` (fail-closed):** a
  non-dev value enforces the secure-config gate at startup. Set `dev`/`local`/`test`
  to relax for local work (compose/Makefile/CI do this automatically).
- `CCF_WORKBOOK_PATH`.
- `CCF_AUTH_ENABLED`, `CCF_AUTH_SESSION_SECRET` — enable auth/RBAC + set a strong
  secret before serving federal data; required (with explicit `CCF_API_CORS_ORIGINS`)
  for the app to start in a non-dev environment.
- `CCF_AUTH_LOCKOUT_THRESHOLD` / `CCF_AUTH_LOCKOUT_MINUTES` (default 5 / 15),
  `CCF_AUTH_PASSWORD_MIN_LENGTH` (default 12), `CCF_AUTH_LOGIN_RATE_LIMIT`
  (default `10/minute`) — authentication hardening.
- `CCF_OSCAL_SCHEMA_DIR` — overrides the **bundled** NIST OSCAL v1.1.2 schemas (which
  make official validation the default); `CCF_OSCAL_REQUIRE_OFFICIAL_SCHEMA` fails
  closed if official validation is unavailable (set in CI).
- `CCF_SCHEDULER_ENABLED`, `CCF_SCHEDULER_INTERVAL_HOURS` — in-app continuous
  monitoring. Multi-replica safe: a Postgres advisory lock elects a single runner
  per tick.
- `CCF_FEDRAMP20X_OSCAL_VALIDATE` — validate the OSCAL-shaped export against the
  bundled OSCAL-subset schema before returning it (`?validate=true` overrides per call).
- `CCF_NOTIFY_WEBHOOK_URL`, `CCF_NOTIFY_MIN_SEVERITY` — Slack/Teams sink for alerts
  (including KSI drift).
- `CCF_AI_ENABLED`, `CCF_AI_PROVIDER` — the AI action layer is **disabled by
  default**; when enabled it stays citation-first and human-approved. Local/dev
  runs with a deterministic stub and no cloud credentials. The
  `ai_disabled_safe_default` reliability check confirms the safe default.
- `CCF_PREP_ENABLED` — turn on the evidence preparation pipeline (`/api/prep`,
  `ccf prep-worker`); **disabled by default**. When unset, the `/api/prep/*`
  routes are not registered at all (a plain 404, not just a locked door) and
  `ccf prep-worker` exits immediately without draining anything — there is no
  way to spend a model-call dollar on this feature without opting in first.
  Its own tenant scoping is derived from the authenticated principal
  (`CCF_AUTH_ENABLED`); with auth off — the default, and true of the whole
  app, not specific to prep — every caller is unscoped and the
  `organization_id` a request supplies is trusted outright.
  `CCF_PREP_SCREEN_THRESHOLD` (default **0.72**) is the `ts_rank_cd` cutoff a
  parsed line must clear to be considered control-relevant — derived
  empirically against the fully-ingested 5,430-row 800-53A catalog, with only
  ~0.03 of margin between the highest-scoring boilerplate line and the
  lowest-scoring genuine match, so re-derive it if the catalog is
  re-ingested. `CCF_PREP_EXPAND_WINDOW` (default 4) bounds context expansion
  around a triggered line. `CCF_PREP_EMBED_PROVIDER` /
  `CCF_PREP_EMBED_MODEL` / `CCF_PREP_EMBED_DIMENSIONS` (default `openai` /
  `text-embedding-3-small` / 1024) configure the embedding backend
  independently of `CCF_AI_PROVIDER`, since Anthropic has no embeddings
  endpoint. `CCF_PREP_WORKER_BATCH_SIZE` (default 10) and
  `CCF_PREP_JOB_STALE_AFTER_MINUTES` (default 60) tune the `prep-worker`
  queue; a job stuck `claimed` past the stale window is reaped back to
  `pending`, and one still failing at `CCF_PREP_JOB_MAX_ATTEMPTS` (default 5)
  claims is dead-lettered instead of being requeued forever.
- `CCF_ASSESSMENT_ENGINE_ENABLED` — turn on the objective-level assessment
  engine (`/api/assessment-engine`, `ccf assessment-worker`); **disabled by
  default**, same reasoning as `CCF_PREP_ENABLED`: the worker spends money on
  a model call per assessment objective. When unset, the
  `/api/assessment-engine/*` routes are not registered at all (a plain 404,
  absent from `/openapi.json`) and `ccf assessment-worker` exits immediately
  without draining anything. Its tenant scoping is derived the same way prep's
  is, from the authenticated principal (`CCF_AUTH_ENABLED`) by resolving the
  named assessment's own `System -> Organization`; with auth off — the
  default, and true of the whole app, not specific to this engine — every
  principal is unscoped, so the assessment/proposal id a request names is
  trusted outright. Do not run with auth disabled against data from more than
  one real tenant. The `assessment_control_proposals` /
  `assessment_objective_proposals` / `assessment_jobs` tables carry no
  row-level-security policies, the same exemption as the `prep_*` tables —
  isolation is application-layer, not database-enforced, for this engine.
  `CCF_ASSESSMENT_ENGINE_RETRIEVAL_LIMIT` (default 8) bounds how many prepared
  passages are retrieved per objective; `CCF_ASSESSMENT_ENGINE_BATCH_SIZE`
  (default 5) and `CCF_ASSESSMENT_JOB_STALE_AFTER_MINUTES` (default 60) tune
  the `assessment-worker` queue the same way the `CCF_PREP_*` equivalents tune
  `prep-worker`, and one still failing at
  `CCF_ASSESSMENT_JOB_MAX_ATTEMPTS` (default 5) claims is dead-lettered.
  Proposals are inert: nothing an evaluation writes reaches the SAR generator
  until an assessor accepts it, and a proposal that settled on
  `insufficient_evidence` cannot be accepted at all — the engine could not
  tell, which is not the same as the control failing. Accepting an
  `other_than_satisfied` finding auto-creates a POA&M (idempotent on a
  stable back-reference, never overwriting one a human has since edited),
  and closing that POA&M enqueues a re-evaluation of the control — a passing
  re-evaluation still surfaces as a proposal a human must accept, never an
  auto-close; see `docs/ARCHITECTURE.md`'s "Closure & remediation loop" for
  the full loop and its deliberate asymmetry with scan auto-closure. Both prep
  classification and objective evaluation record their own AI provenance
  (`ccf.ai_actions.provenance.record_ai_run`) on every call — an
  `ai_action_runs` row with `status="recorded"`, citations, and a link back
  from `PrepClassification`/`AssessmentObjectiveProposal` — independently of
  `CCF_AI_ENABLED`'s approval-gated action layer above, and by design does not
  route through it (see `docs/ARCHITECTURE.md` for why). Accepting a proposal
  additionally stamps the accepting assessor (`reviewer`, `disposition`,
  `decided_at`) onto every AI run linked to it, so `ai_action_runs` joined to
  `ai_action_citations` answers which model, which evidence, and who accepted
  it, for both pipelines, in one query. `POST
  /api/assessment-engine/proposals/{id}/reject` is acceptance's other
  outcome: an assessor records that a proposed finding was wrong, with the
  finding they believe correct (`corrected_finding`, never
  `insufficient_evidence` — that is proposal-only, and a correction asserts
  what is true) and a required `note`. Rejection stamps the same
  `AiActionRun`s with `disposition="rejected"` but never writes
  `AssessmentControlResult` — the engine's wrong answer must not reach the
  SAR with a human's name attached. `GET /api/assessment-engine/calibration`
  and `ccf calibration-snapshot <organization_id>` compute agreement between
  proposed and assessor-decided findings, reporting `missed_findings` (a
  control passes that should not) and `false_alarms` (wasted remediation
  effort) **separately** — they are never averaged into one accuracy figure
  — alongside `agreement_rate` and a per-family breakdown. A
  `calibration_snapshots` row records each measurement with a
  `config_fingerprint` (a hash over `prep_screen_threshold`, the rollup
  policy version, the model name, and — see `CCF_ASSESSMENT_DISSENT_ENABLED`
  below — whether the AI dissent path is on and which policy version it
  challenges under); two snapshots with different fingerprints compare as
  **not comparable**, not drift, which matters because
  `prep_screen_threshold`'s narrow margin (above) means it will be
  re-derived. Nothing here is retrofitted: proposals decided before this
  reject path existed carry no recorded disagreement, so an early snapshot's
  `decided` count starting near zero is expected. The harness measures; it
  does not tune the threshold, gate CI on a metric change, or generate
  synthetic evidence — all deliberately out of scope for this slice.
- `CCF_ASSESSMENT_DISSENT_ENABLED` — run an independent second model call (a
  "challenger") against a `satisfied` verdict before an assessor ever sees
  it; **disabled by default**, same reasoning as the other AI-call flags
  above: this doubles model calls on the passing subset, and a deployment
  must opt into that cost. Only `satisfied` is ever challenged — the
  expensive error direction is a control passing that should not, not the
  reverse — and the challenger sees the exact same retrieved passages the
  primary call saw, never a fresh retrieval. A challenger that reaches a
  different, cited verdict flips the objective to `insufficient_evidence`
  (never averaged, majority-voted, or tie-broken toward either side) and
  increments `AssessmentControlProposal.dissent_count`; one contested
  objective is enough to force the whole control's rollup to
  `insufficient_evidence`, which `accept_control_proposal` already refuses.
  Both verdicts are retained — `AssessmentObjectiveProposal.challenger_verdict`
  / `.challenger_rationale` — surfaced on `GET /api/assessment-engine/
  proposals/{id}` alongside each objective. A challenger failure (provider
  error, timeout, malformed response) never fails the evaluation: the
  primary verdict persists, the challenger columns stay `NULL`, and a
  warning is logged — a `NULL` `challenger_verdict` means either "not
  challenged" or "challenged but failed," distinguishable only in the logs.
  Toggling this flag changes what the calibration harness above is
  measuring, so `config_fingerprint` folds it in (plus
  `DISSENT_CHALLENGE_POLICY_VERSION`, naming the "satisfied only" policy so
  a later change to which verdicts get challenged is visible too) — two
  snapshots taken with the flag toggled between them compare as **not
  comparable**, not drift. Not retrofitted: objectives evaluated before this
  slice, or with the flag off, carry no dissent record. Migration `0063`
  adds five new columns: four nullable columns on
  `assessment_objective_proposals` (`primary_verdict` — the primary call's
  verdict, preserved because `verdict` itself is overwritten on a genuine
  disagreement — plus `challenger_verdict`, `challenger_rationale`, and
  `challenger_ai_action_run_id`), and `dissent_count` (`NOT NULL default 0`)
  on `assessment_control_proposals`; see `docs/ARCHITECTURE.md`'s "AI
  dissent path" for the full reasoning.

## Security posture

Shipped today:

- **Fail-closed by default** — the app **refuses to start** in a non-dev
  environment (`CCF_ENV` unset or `production`) when auth is disabled, the session
  secret is the insecure default, or CORS is wildcard. You must explicitly set
  `CCF_ENV=dev`/`local`/`test` to relax; local dev and CI do so automatically. This
  closes the previous fail-open hole where a missing `CCF_ENV` silently ran insecure.
- **AuthN / AuthZ** — session-cookie + bearer-token authentication
  (`CCF_AUTH_ENABLED`) and a separation-of-duties RBAC model
  (`admin` / `control_owner` / `assessor` / `viewer`, plus a
  draft → submitted → approved approval workflow). **Account lockout** (AC-7, 5
  failed attempts → 15-min lock), a **password policy** (IA-5, 12-char minimum,
  NIST 800-63B), and **per-IP login rate limiting** protect authentication.
- **Secure response headers** (SC-8/SI-10) — a pure-ASGI middleware adds HSTS,
  `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and a baseline CSP.
- **Static analysis (SAST)** — `bandit` runs in CI (RA-5/SA-11) over first-party code
  (it caught and closed an XXE in scan-upload parsing, since fixed with `defusedxml`).
- **Multi-tenant isolation** — PostgreSQL **row-level security** on every
  tenant-owned table (org- and system-scoped policies keyed on a `ccf.tenant_id`
  session GUC + a non-superuser `ccf_app` role), a database-enforced backstop
  beneath the application-layer org scoping. An unset GUC = bypass, so
  CLI / ETL / migrations run unscoped.
- **Tamper-evident audit** — every mutation is recorded in `ccf.audit_log` with a
  SHA-256 hash chain; `/api/audit/verify` re-checks the chain.
- **Supply chain & container** — non-root image, tini PID 1, HEALTHCHECK, typed
  pydantic config, structured logs, and CycloneDX SBOM + `pip-audit` + Trivy in CI.
- **Observability** — Prometheus `/metrics` (HTTP + FedRAMP 20x series) with a
  bundled Grafana dashboard.

Roadmap (see design review in git history): **MFA / PIV-CAC** + OIDC nonce/PKCE
hardening, **KMS-backed key rotation + FIPS 140-3-validated crypto**, **SIEM/syslog
audit export**, a finer DB role split (`ccf_migrator` / `ccf_etl` / `ccf_app` /
`ccf_ro`), an append-only `ccf_audit` schema with `REVOKE UPDATE,DELETE`, pgaudit, a
workbook object-store with object lock, cosign-signed images, OTEL tracing, a
Section 508 / VPAT pass, and published runbooks / SLOs.

## Project status

Active development; feature-complete across the core platform. In place: the
ingestion pipeline, data model, REST API + HTMX UI + Typer CLI, CMMC L2 live
scoring, the SSP builder, the enterprise governance layer, FedRAMP 20x
(KSIs → validation → readiness → authorization package), continuous-controls
monitoring (scan ingestion → POA&M reconciliation + assertion-based control
tests), the workforce-security lifecycle (personnel, training, access reviews)
and vendor security questionnaires — each with an API, a UI, and alert-digest
integration — OSCAL export (Component Definition / SSP / POA&M) with official
schema conformance, OIDC / SSO with JIT provisioning + SCIM, session + bearer
authentication with separation-of-duties RBAC, database-enforced multi-tenant RLS,
and a tamper-evident audit hash-chain. Also in place: the **continuous-authorization
layer** — assurance graph, evidence confidence scoring, authorization-package
provenance/diff/replay, a typed citation-first AI action layer, AI-agent
governance, a compliance-pack runtime, Concord-on-Concord self-assurance, and an
external collaboration portal; and the **OSCAL authorization pipeline** — control-read
reconciliation against the authoritative NIST catalog, a system boundary & inventory
model, a real NIST 800-53 Rev 5 SSP generator, assessment-results (SAR) export, and a
single authorization-package ZIP — with every OSCAL export **machine-proven valid
against the official NIST v1.1.2 schema**. Platform self-hardening is complete: the
app is **fail-closed by default**, with account lockout, a password policy, login
rate limiting, security-response-header middleware, and `bandit` SAST in CI.
Alembic-managed schema (54 migrations), Docker/Compose, CI (lint · mypy · pytest ·
bandit · SBOM · pip-audit · Trivy · Docker build), and a reliability self-check
subsystem. The suite runs **720+ tests** against a real Postgres.

Next (deliberately-scoped depth): a FedRAMP Rev 5 baseline overlay (FedRAMP-added
controls + assigned ODP values), objective-level (800-53A) SAR findings, a generated
OSCAL assessment plan (SAP), MFA / PIV-CAC + SSO hardening, KMS-backed key rotation +
FIPS-validated crypto, Azure Gov / GCP config connectors, and wiring the typed
`ai_actions` path to the org AI gateway.

---

