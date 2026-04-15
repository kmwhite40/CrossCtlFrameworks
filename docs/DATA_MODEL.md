# Concord — Data Model

## Schemas

| Schema | Purpose |
|--------|---------|
| `ccf`       | Reference catalog + operational tables (the things users query and mutate). |
| `ccf_raw`   | Staging (reserved; Phase-2 roadmap). |
| `ccf_audit` | Append-only provenance and quarantine (`workbook_versions`, `ingestion_runs` FK, `control_history`, `mapping_history`, `rejected_rows`). |

## Reference layer (`ccf`)

- **`frameworks(id, code, name, family, description)`** — 26 canonical codes.
- **`control_families(id, code, name, category)`** — NIST AC / AU / ...
- **`controls(id, identifier unique, family_id fk, …, audit_payload jsonb, search_vector tsvector, source_row, loaded_at)`**.
- **`framework_mappings(id, control_id fk, framework_id fk, column_key, value)`** — tall table, unique `(control_id, column_key)`.
- **`worksheets` + `worksheet_rows`** — generic landing for non-primary xlsx tabs.

## Provenance layer (`ccf_audit`)

- **`workbook_versions(id, sha256 unique, source_path, size_bytes, imported_at, imported_by)`** — content-addressed.
- **`ingestion_runs(id, workbook_version_id fk, source_file, sha256, status, stats jsonb, started_at, finished_at)`**.
- **`control_history(id, identifier, workbook_version_id fk, payload jsonb, valid_from)`** — SCD-2 of `controls.audit_payload`.
- **`mapping_history(id, identifier, workbook_version_id fk, column_key, value, valid_from)`** — SCD-2 of `framework_mappings`.
- **`rejected_rows(id, run_id fk, sheet, row_index, rule, payload jsonb, rejected_at)`** — quarantine.

## Operational layer (`ccf`)

- **`organizations` / `users`** — tenant + identity (OIDC pending).
- **`systems`** — FIPS-199 (CIA) + FedRAMP baseline + ATO status.
- **`control_implementations`** — per `(system, control)`: status, responsibility, narrative, conmon frequency, last / next assessed.
- **`evidence`** — artifacts tied to an implementation.
- **`assessments` / `assessment_results`** — assessment runs + per-control findings.
- **`poams`** — Plan of Actions & Milestones.
- **`risks`** — risk register.
- **`audit_log`** — application-level activity journal.

## Indexes of note

| Table | Index | Reason |
|-------|-------|--------|
| `controls` | `GIN(search_vector)` | Postgres FTS on identifier/name/objective/description/discussion. |
| `controls` | `GIN(audit_payload)` | Ad-hoc JSONB queries. |
| `framework_mappings` | `GIN(value gin_trgm_ops)` | Trigram search for `/mappings?q=...`. |
| `framework_mappings` | `UNIQUE(control_id, column_key)` | Contract: one value per control per column. |
| `control_history` / `mapping_history` | `(workbook_version_id)` + `(identifier)` | Power `/diff`. |

## JSONB usage rationale

- `controls.audit_payload` — raw row, preserved forever. Evidence trail for
  auditors and the source-of-truth when the normalized columns change.
- `worksheet_rows.payload` — unknown-shape sheets (CUI overlay, AWS managed
  rules, etc.) do not merit their own tables.
- `ingestion_runs.stats` — per-sheet counts and error detail.
- `audit_log.diff` — before/after snapshot on writes.
