# The DISA CCI list as an authoritative source (P0″a)

**Status:** design, awaiting implementation plan
**Extends:** `catalog/oscal.py`, `etl/sources.py`, `assessment/engine/objectives.py`
**Adds:** `ccf/cci/`, three global reference tables
**Closes:** G4, and the CCI half of the P0 deferral recorded in the gap
analysis §8
**Serves, without building:** P5 (STIG/SCAP ingestion), P8 (eMASS interop)

The FedRAMP Rev. 5 baseline half of P0″ is a different upstream
(`GSA/fedramp-automation`) with a different question attached to it, and is
left to its own cycle.

## 1. CCI is shallow here, not absent

`DISA_CCI` is already a registered `FrameworkSpec` (`etl/frameworks.py:56`),
and the cross-mapping workbook carries ten CCI columns. Column 163,
`CCI Rev 5 ("*" are automatically compliant)`, already lands in
`framework_mappings` as a semicolon-separated string like
`CCI-003621; CCI-003622; CCI-003615`.

So the earlier claim that CCIs are "entirely absent" is wrong, and the
correction changes what needs building. What exists is:

- **one-directional** — `framework_mappings` is `UNIQUE (control_id,
  column_key)` with a single `value`, so it answers "which CCIs touch this
  control" as unparsed text and cannot answer "which control does CCI-003612
  belong to" at all;
- **unparsed** — no CCI has a definition, a type, a status, or a publication
  date anywhere in the platform;
- **not authoritative** — it is a third-party spreadsheet's opinion, carrying
  no revision of its own and no provenance back to DISA.

The reverse index is the whole point. A STIG finding names a CCI and nothing
else; without CCI → control, P5 has no route into
`ingest/scanners.reconcile_findings`.

## 2. Two artifacts, one authority

Both ship in `data/cci/` (commit `4bb396f`), following the precedent set by the
cross-mapping workbook: an ingest input travels with the repository so a clone
can run the pipeline without a network fetch.

**`CCI List.html` is the authority.** DISA's published CCI List, version
2026-07-14: 5,149 CCIs, each with status (5,058 draft, 91 deprecated), type
(4,245 policy, 718 technical, 186 both), contributor, published date,
definition, and references that name **the revision they decompose** —
800-53 v3, v4, Revision 5, and 800-53A. Of its 10,216 references, 3,849 across
3,847 CCIs are Rev. 5 (3,001 are Rev. 4, 1,683 each v3 and 800-53A).

**`All Rev. 5 CCIs.ods` is derived, and its filename is wrong.** Of its 3,626
rows, 2,616 are in Rev. 5 spelling (`AC-01`, AP acronym `AC-01a`) and **1,010
are in Rev. 4 spelling** (`AC-1`, `AC-1 (a) (1)`). It covers 2,579 distinct
CCIs — roughly half the list — with 1,047 duplicate rows, because the same CCI
appears once per generation. Loaded naively it yields two conflicting mappings
per CCI, and only the HTML can say which generation a row belongs to.

It is therefore ingested as an **overlay**, filtered to the Rev. 5 generation,
in a table whose `source` column carries the filename verbatim so no reader
can mistake it for DISA's.

## 3. What a CCI points at

A Rev. 5 reference reads `AC-1 a 1 (a)`: a control, then an item path. It maps
exactly onto the OSCAL catalog's nested statement parts —
`ac-1_smt.a.1.a` — with one disambiguation that is easy to get wrong:

> **A leading `(n)` is a control enhancement, not a statement item.**
> `AC-2 (1)` is control AC-2(1), i.e. `ac-2.1`, not `ac-2_smt.1`. The rule is
> to absorb leading parenthesized integers into the control id *while the
> enhanced control actually exists in the catalog*, and treat the rest as the
> item path. Reading `(1)` as an item instead costs 1,860 of 3,849 references.

With that rule, **3,848 of 3,849 Rev. 5 references resolve to an exact OSCAL
part id.** The single exception is the design's justification:

> CCI-005020 cites `SI-18 b 1`, but SI-18 b has no sub-items in the Rev. 5
> catalog — DISA's reference is a revision behind the control text.

So resolution is **opportunistic, never a gate**: the canonical control is
always stored, the raw index is always stored verbatim, and the resolved part
id is stored when the catalog agrees. A CCI is never dropped for failing to
resolve. This follows the P1 precedent — capability→control edges store the
canonical string rather than an FK, because the workbook and the OSCAL catalog
genuinely differ.

**Resolution needs one addition to the catalog loader.** `OscalControl`
flattens the statement into a single `statement: str`, so there is nothing
addressable to resolve against. `_parse_control` gains
`statement_parts: dict[str, str]` — part id → labeled prose — built by the walk
`_collect_prose` already performs. It is additive with a default, it is pure
parsing, and `load_oscal_catalog` stays DB-free, so the grep test that enforces
that keeps passing. P4's evidence-citation work gets an addressable target it
does not have today.

## 4. Data model

Three tables, all **authority-published reference data**: no
`organization_id`, and all three join `GLOBAL_TABLES` in
`tests/test_rls_registry_no_gap.py` with that reason stated.

```
cci_items              5,149 rows
  cci UNIQUE           "CCI-000002"
  status               draft | deprecated
  type                 policy | technical | "policy, technical"
  contributor, published_date, definition
  source_version       "2026-07-14"
  source_sha256        content address of the file it was read from

cci_control_refs       10,216 rows
  cci_id FK, revision  "5" | "4" | "3" | "800-53A"
  raw_index            "AC-1 a 1 (a)"   -- verbatim, always
  canonical_control    "AC-1"           -- via catalog/canonical.py
  oscal_control_id     "ac-1"
  oscal_part_id        "ac-1_smt.a.1.a" -- NULLABLE, see §3
  UNIQUE (cci_id, revision, raw_index)
  INDEX (canonical_control)             -- this index is the reverse lookup

cci_assessment_overlay
  cci_id FK, ap_acronym, emass_identifier
  assessment_procedure, assessment_methods
  source               "derived:All Rev. 5 CCIs.ods"
```

**All revisions are stored, not only Rev. 5.** The source carries them and a
STIG in the field may still cite Rev. 4; `revision` scopes every query. But
`oscal_part_id` is attempted *only* for Rev. 5, because that is the only
catalog the platform holds — for other revisions it is null by construction
rather than by failure, and the two cases must not be confused.

## 5. Ingest and currency

`ccf cci load` (a `cci_app` Typer group beside `catalog`), keyed on `cci` and
content-addressed by `source_sha256`, so re-running the same file is a no-op
and a different file is a new version.

A `CatalogSource` row registers the list under `kind="generic"`, authority
DISA, **`enabled=False`** with the reason in the row: cyber.mil refuses
non-browser fetches, and a source that can only ever error would put a
permanent red line in the alert digest that means nothing. Where egress allows,
enabling it is a one-field change and the existing poller handles it — `poll`
already records a per-source failure and moves on (`sources.py:436`).
`auto_ingest` stays `False` regardless, matching P0′: drift is recorded for a
human to review.

## 6. Consumers

**The reverse index.** `ccis_for_control(canonical, revision="5")` and
`controls_for_cci(cci)`. That is the entire P5 seam, and P5's CKL and XCCDF
parsers are **not** in this spec — a scanner parser inside a reference-data
spec is how a spec stops being reviewable.

**eMASS identifiers.** The overlay makes `emass_identifier` queryable per CCI.
P8's import/export is its own work.

**Objective labels — and a correction.** The plan was to source AP acronyms
from the .ods. The numbers say otherwise:

- the workbook's own `AP Acronym` column is populated on **4 of 5,435 rows**;
- the .ods AP acronyms join to workbook identifiers at **64%** (739/1,162),
  the misses being one-to-many spelling families (`AC-02a` against the
  workbook's `AC-02a.[01]` and `AC-02a.[02]`);
- and where both name a CCI for the same item, they **disagree 430 times out
  of 1,112**.

Meanwhile the objective rows already carry the item path in
`Control.identifier` — `AC-02a.[01]`, `AC-02b.`, `AC-02_ODP[01]` — and
`identifier` is UNIQUE, so it is unique *by construction*, which is the exact
property `objectives.py` spends thirty lines defending against duplicate
`ap_acronym`.

So `objectives_for` prefers the row's own `identifier` over `_ordinal_label`,
with every existing uniqueness fallback left intact. No CCI data is involved,
no fuzzy join, no derived-source provenance. Stored proposals keep their stored
labels: they are records of what was proposed, not a cache.

## 7. Reconciliation, advisory only

`ccf cci reconcile` compares the workbook's column-163 CCI sets — split on
`;`, `*` suffix stripped — against DISA's Rev. 5 references, per control item,
reporting three categories: CCIs the workbook claims and DISA does not, CCIs
DISA maps that the workbook omits, and CCIs both name against *different*
controls.

It reports and never corrects, following `catalog/reconcile.py`. The workbook
keeps loading its CCI columns untouched — the header classifier is
deliberately generic, and special-casing one column would make
`mapping_history` snapshots differ for reasons unrelated to the workbook.
Disagreement is a finding *about the workbook*, which is useful on its own.

## 8. What this does NOT do

- **No scanner parsers.** CKL, XCCDF and ARF are P5.
- **No eMASS import or export.** P8.
- **No mutation of workbook-sourced tables.** Nothing writes
  `controls.ap_acronym`, `framework_mappings`, or any history snapshot. A
  non-workbook value in a workbook-rebuilt table is reverted by the next
  ingest, or makes the snapshot misrepresent its source.
- **No auto-adoption.** An upstream CCI revision is detected and reported,
  never ingested silently.
- **No part resolution for revisions whose catalog we do not hold.**
- **No second CCI vocabulary.** `framework_mappings` keeps its workbook rows;
  the new tables are the system of record and the reconciliation report is the
  only thing that compares them.
- **No UI.**

## 9. Testing strategy

**Against the real committed file, not an invented fixture.** The parse tests
assert the measured numbers, so a silent upstream or parser change fails
loudly: 5,149 items, 91 deprecated, 3,849 Rev. 5 references, 3,848 resolved,
and CCI-005020 as the single unresolved case named explicitly.

- **The enhancement rule gets its own test.** `AC-2 (1)` resolves to `ac-2.1`
  and *not* to `ac-2_smt.1`; `AC-1 a 1 (a)` resolves to `ac-1_smt.a.1.a`.
- **The overlay's Rev. 4 rows are excluded**, asserted by loading the real
  .ods and checking a CCI that appears in both generations lands once.
- `resolve.py` is pure — reference string in, triple out — and tested without
  a database.
- Re-running `cci load` on the same file changes nothing (content address),
  and on a file with one edited definition updates exactly one row.
- All three tables are asserted present in `GLOBAL_TABLES`; the migration
  carries the `pg_roles` GRANT guard that `0054` sets as standard.
- Tests respect the shared-session database discipline: unique values for
  unique columns, no assumption of emptiness, and cleanup of rows other
  modules count.
- `objectives_for` keeps its duplicate-label and ordinal fallbacks under test,
  with a case where `identifier` is absent to prove the fallback still runs.
- Mutation testing on every guard, with the harness invariants from the
  mutation-testing memory — in particular, a harness that cannot fail proves
  nothing.
