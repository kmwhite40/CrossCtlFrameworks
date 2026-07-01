# Runbook — Catalog currency & drift

**Goal:** keep the control catalog current as NIST (and the curated cross-mapping
workbook) publish revisions, instead of relying on a static Excel export.

## Model

`ccf.catalog_sources` is a registry of authoritative upstreams. A poll fetches
each source, content-hashes it, and writes a `ccf.catalog_checks` row:

| `kind`          | detection                                                        |
| --------------- | ---------------------------------------------------------------- |
| `oscal_catalog` | parse NIST OSCAL JSON, diff per-control prose → added/modified/removed |
| `xlsx`          | sha of the workbook; if `auto_ingest`, re-run the ETL            |
| `generic`       | sha of the body (any URL) — drift = sha changed                 |

Detection is conditional (`If-None-Match` ETag) and idempotent (sha compare),
so an unchanged source is a no-op and a flaky ETag never yields a false change.

## Operate

```bash
# Register the default authoritative sources (idempotent).
ccf sources-seed

# Poll everything and print a drift table.
ccf sources-check

# Poll one source; include disabled ones.
ccf sources-check --key nist_800_53_r5_catalog
ccf sources-check --all
```

Or on a schedule (one-shot container; wrap in host cron / CI):

```bash
docker compose --profile poller up
```

API (same data, for the UI / automation):

- `GET  /api/catalog/sources` — every source + last-known status
- `GET  /api/catalog/sources/{id}/checks` — recent drift checks
- `POST /api/catalog/sources/{id}/check` — poll one now (blocked in Reader)

## Triage

- **status = `changed`** — upstream drifted. `detail.counts` gives
  added/modified/removed control counts; `detail.modified` lists the ids. Open a
  reviewed PR to refresh the curated workbook, then re-ingest (see
  `ingestion-failed.md`). This is the intended gate — we do **not** auto-mutate
  the curated catalog.
- **status = `ingested`** — an `xlsx` source with `auto_ingest=true` changed and
  the ETL ran. `detail.ingestion_run_id` links the run; verify it `succeeded`.
- **status = `error`** — `detail.error` has the message. Common: upstream 404
  (NIST moved/renamed the OSCAL file — update `catalog_sources.url`), or a
  network/TLS failure. The previous `content_index` is retained, so the next
  good poll re-detects drift correctly.
- **status = `unchanged`** — nothing to do.

## Notes

- NIST publishes machine-readable OSCAL at
  `github.com/usnistgov/oscal-content`; that's the authoritative feed the
  default sources point at (no human re-export needed for the catalogs).
- The curated workbook source ships **disabled** — set its `url` to wherever the
  workbook is canonically stored (git raw, S3, SharePoint link) and enable it.
- `auto_ingest` writing needs a **writable** `/data` mount (the `etl` profile
  mounts it read-only); use the `poller` profile or a dedicated volume.
