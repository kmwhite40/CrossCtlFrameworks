# OSCAL Catalog Reconciliation Engine — Design

- **Date:** 2026-07-26
- **Status:** Approved (brainstorming → spec)
- **Author:** Concord assessment program
- **Related:** [[ssp-ai-assessment-program]], `docs/superpowers/assessments/integrity_checks.py`,
  `src/ccf/fedramp20x/catalog.py`, `src/ccf/etl/pipeline.py`

## Problem

Concord reads its NIST 800-53 controls from a single 27 MB spreadsheet
(`data/NIST Cross Mappings Rev. 1.1.xlsx`). The ETL
(`src/ccf/etl/pipeline.py::_ingest_assessment`) trusts the cell content: the only
guardrail is a header contract (`src/ccf/etl/validate.py`) that fails only when a
*required column is removed*. Nothing verifies the controls themselves against an
authoritative source. Concrete accuracy risks found during assessment:

1. **No authoritative cross-check.** Control IDs, titles, statement text, ODPs, and
   withdrawn status are whatever a human typed. Typos, stale revisions, missing
   enhancements, and mis-transcribed discussion are invisible.
2. **No control-ID canonicalization.** `AC-2`, `AC-02`, `AC-2(1)`, `AC-2 (1)` are
   distinct keys. Control identity is fragmented across the codebase
   (`Control.identifier` `String(128)` unique, `Control.control_number` free text,
   `ControlImplementation.control_id` `String(64)`, SSP entries carry separate
   `control_id` + `nist_id`). ID drift silently fractures the control→
   implementation→evidence→POA&M→SSP joins that are the platform's core value.
   **Highest-leverage defect.**
3. **Baseline membership is bool-coerced from free-text cells** (`fisma_low/mod/high`);
   a disagreement with 800-53B scopes the wrong control set.
4. **Cross-framework mapping endpoints are never verified to exist.**
5. **Duplicate identifiers are silently auto-suffixed** (`#row{n}`), masking data
   quality problems.

> Note: the `controls` table holds ~5,433 rows — far more than the ~1,189 Rev 5
> controls+enhancements — strongly implying the rows are 800-53**A** determination
> statements/objectives, not controls. The engine keys off `control_number` (the NIST
> id), so it is correct either way: multiple rows may share one canonical id.

## Goal

Add an **advisory** reconciliation engine that verifies the controls Concord reads
against the authoritative NIST OSCAL 800-53 Rev 5 catalog, producing a
**catalog-integrity report** — the control-content analog of the existing static
`integrity_checks.py`. Non-destructive: it never rewrites control data in v1.

### Decisions (from brainstorming)

| Decision | Choice |
|---|---|
| Authority | **Advisory cross-check first** — OSCAL is the yardstick, not the source of record. Promotable to authoritative later. |
| Catalog source | **Bundled, pinned OSCAL JSON** (+ 800-53B baselines) in `data/oscal/`, sha256-verified against a `MANIFEST.json`. Air-gap safe, deterministic. Updating = a committed file bump. |
| v1 checks | **All four**: identity & canonicalization, baseline membership, content drift (prose), cross-framework mapping endpoints. |
| Crosswalk | **Store the raw→canonical crosswalk, do not enforce.** Makes v2 enforcement data-ready while keeping v1 advisory. |

## Non-goals (v1) — deferred deliberately

- Writing canonical ids back onto `controls` or enforcing them on joins (**v2**; the
  stored crosswalk is its input).
- Field-level provenance columns on `controls`.
- Bundling ISO / CIS / CSF / CMMC catalogs for endpoint validation (v1 reports such
  mappings as "not evaluated — no bundled catalog").
- Runtime OSCAL fetch (bundled-only in v1).
- Blocking `/readyz` or CI on findings (config toggle exists, defaulted off).

## Architecture

Standalone engine, three consumers (Approach C). The engine reads `controls` /
`framework_mappings` and writes **only** to a new `catalog_integrity_reports` table —
so the advisory-only contract is guaranteed by construction (no write path into
control content).

```
data/oscal/
  NIST_SP-800-53_rev5_catalog.json                 # pinned authoritative catalog
  NIST_SP-800-53_rev5_{LOW,MODERATE,HIGH}_baseline.json
  MANIFEST.json                                    # {oscal_version, sha256 per file, retrieved_at}

src/ccf/catalog/
  __init__.py
  oscal.py         # load pinned catalog + baselines; sha256-verify vs MANIFEST;
                   # index by canonical id; expose withdrawn set + per-baseline membership
  canonical.py     # ONE control-id normalizer: canonicalize(raw) -> CanonicalId | None
  reconcile.py     # 4 reconcilers -> list[CatalogFinding]; pure; no writes to `controls`
  report.py        # persist CatalogIntegrityReport; render (json / text / UI payload)
```

Consumers: (1) `ccf catalog reconcile` CLI; (2) a non-fatal tail-call in
`ingest_workbook`; (3) a `/readyz` `catalog_integrity` check; (4) a read-only,
role-gated UI report page.

## Data model

New table `catalog_integrity_reports` (report header + findings as JSONB, mirroring
`ingestion_runs` / `RejectedRow`). Alembic migration `0051` (RLS-consistent with the
platform; report is org-agnostic catalog data — follow the `framework_controls`
global/NULL-org precedent from migrations 0046/0047).

```
catalog_integrity_reports
  id                    bigint pk
  run_at                timestamptz default now()
  oscal_version         text            # from MANIFEST
  oscal_sha256          text            # provenance of the catalog reconciled against
  controls_checked      int
  findings_total        int
  findings_by_severity  jsonb           # {"high": N, "medium": N, "low": N}
  findings              jsonb           # list[CatalogFinding]
  crosswalk             jsonb           # {raw_control_number: canonical_id | null}
  summary               jsonb           # per-check counts + coverage notes (for /readyz + UI)
```

No new columns on `controls` in v1.

### `CatalogFinding` (typed dataclass → JSONB)

```
check          # identity | baseline | content_drift | mapping_endpoint
severity       # high | medium | low
canonical_id   # "AC-2(1)"  (or raw value when it won't canonicalize)
raw_id         # workbook's original string, preserved
field          # e.g. "control_name", "fisma_mod", "ISO-27001"  (nullable)
workbook_value
oscal_value    # authoritative value, or null (e.g. "id not found")
detail         # human-readable one-liner
```

## The canonicalizer (`canonical.py`) — the linchpin

One pure function `canonicalize(raw: str) -> CanonicalId | None`, returning the
canonical string plus parsed `(family, number, enhancement)`. Preserves the raw input
on findings. **Never guesses** — anything not confidently an 800-53 id returns `None`
and becomes an identity finding rather than a silent bad match.

```
"AC-2"        -> AC-2       family=AC num=2  enh=None
"AC-02"       -> AC-2       (zero-pad stripped)
"AC-2 (1)"    -> AC-2(1)    enh=1
"AC-2(1)"     -> AC-2(1)
"ac-2 (1)"    -> AC-2(1)    (case-folded)
"AC.L2-3.1.1" -> None       (CMMC form — not an 800-53 id; reported, not forced)
""/garbage    -> None
```

Test corpus = the **real distinct `control_number` values** extracted from the
workbook, plus adversarial forms.

## The four checks

Each reconciler is pure: `(oscal_index, controls, mappings) -> list[CatalogFinding]`.
Every check **degrades gracefully** — a control failing identity is recorded
`not_evaluated` downstream so counts always reconcile. Severity is actionable:
`high` = corrupts scope or joins; `medium` = accuracy risk needing review; `low` =
informational drift.

### 1. Control identity & canonicalization (highest leverage)
- `canonicalize()` → `None` ⇒ **high** `unparseable_control_id`.
- Canonical id not in OSCAL catalog ⇒ **high** `unknown_control_id`.
- OSCAL marks it withdrawn/incorporated-into ⇒ **medium** `withdrawn_control` (detail
  names the successor).
- Two rows collapse to the same canonical id with conflicting core fields ⇒ **medium**
  `ambiguous_duplicate` (a *reported* replacement for today's silent `#row{n}`).
- Emits the raw→canonical **crosswalk** into the report (v2 enforcement input).

### 2. Baseline membership
- Build authoritative per-baseline sets from 800-53B Low/Moderate/High.
- Workbook in-baseline, OSCAL not ⇒ **medium** `baseline_overclaim` (inflates SSP scope).
- Workbook not-in-baseline, OSCAL in ⇒ **high** `baseline_underclaim` (required control
  could be omitted — the dangerous direction).
- Controls that failed identity ⇒ `not_evaluated`.

### 3. Content drift (prose — advisory, never overwrites)
- Title (`control_name`) vs OSCAL title: normalized exact compare → mismatch =
  **medium** `title_drift`.
- `description`/`discussion` vs OSCAL statement/guidance: similarity ratio below a tuned
  threshold = **low** `text_drift` with a short diff snippet. Threshold tuned so trivial
  formatting differences don't flood the report.

### 4. Cross-framework mapping endpoints
- 800-53 is the anchor: any mapping whose endpoint is an 800-53 id gets canonicalized and
  confirmed to exist ⇒ missing = **medium** `dangling_mapping_endpoint`.
- Target frameworks with no bundled catalog (ISO, CIS, CSF, CMMC): report coverage
  honestly in `summary` ("N mappings to ISO-27001 — endpoint validation unavailable, no
  bundled catalog"). No silent pass. Clean seam to add catalogs later.

## Consumers & surfacing

- **CLI** — `ccf catalog reconcile [--strict] [--format text|json]`: run engine on the
  live DB, persist a report, print summary. `--strict` exits non-zero on any **high**
  finding (future CI gate, like `integrity_checks.py --strict`). `ccf catalog show`
  prints the latest stored report.
- **Ingest tail-call** — `ingest_workbook` calls the engine after a successful load and
  stores a report, wrapped so a reconciliation error is logged but **never fails the
  ingest** (advisory contract).
- **`/readyz`** — new `catalog_integrity` reliability check: OSCAL version + sha loaded,
  last-reconciliation time, high/medium/low counts. Reports `pass` (informational) by
  default; a config toggle (default off) can make high findings block readiness.
- **UI** — read-only `/catalog/integrity` page, role-gated like `/audit`: summary tiles +
  filterable findings table (by check/severity), each row showing raw vs canonical id and
  workbook-vs-OSCAL values. HTMX/Alpine + existing templates; no new frontend stack.

**Catalog provenance:** `oscal.py` verifies each bundled file's sha256 against
`MANIFEST.json` on load and fails loudly on mismatch — the catalog reconciled against is
itself integrity-checked.

## Testing strategy (TDD; `ccf_test` per the harness)

- `canonical.py` — exhaustive unit tests over the real `control_number` corpus + adversarial
  forms (whitespace, case, zero-pad, nested enhancements, CMMC ids → `None`).
- Each reconciler — table-driven tests with a **small fixture OSCAL catalog** (a few
  controls incl. one withdrawn + baseline membership) and hand-built control/mapping rows
  exercising every finding type and the `not_evaluated` degradation path.
- Golden end-to-end: fixture workbook → ingest → reconcile → assert exact report counts
  (guards parser/engine regressions).
- `oscal.py` — sha-mismatch fails loudly; missing file resolves via candidate paths
  (mirrors `fedramp20x/catalog.py` tests).
- `/readyz` + report route — status and role-gating tests (match `test_health.py` /
  `test_audit_rbac.py`).

## Rollout / migration

- Alembic `0051_catalog_integrity_reports`. Rebuild `api` + `migrator` images after adding
  it (known gotcha — see [[migrator-image-rebuild]]).
- Bundle the pinned OSCAL files under `data/oscal/` and add `data/oscal/*.json` to the
  package-data globs so they ship in the wheel/Docker image (mirror the
  `fedramp20x` `ksi_catalog.json` packaging).
- Ship advisory/off: no existing workflow changes behavior; the report is additive.

## Success criteria

1. `ccf catalog reconcile` runs against the live catalog and produces a report whose
   counts reconcile (`checked` = evaluated + not_evaluated).
2. The canonicalizer passes its full real-corpus test suite.
3. Every finding type and the `not_evaluated` path are covered by tests; full suite green
   on `ccf_test`.
4. `/readyz` reports the loaded OSCAL version + latest reconciliation summary.
5. The stored crosswalk is queryable and complete (one entry per distinct
   `control_number`) — ready for a v2 enforcement slice.
