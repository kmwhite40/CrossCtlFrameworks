# P0' — OSCAL Authoritative Source Spine (design)

**Date:** 2026-09-14 (revised same day after source review)
**Status:** Design revised; awaiting spec review
**Program context:** `docs/superpowers/assessments/2026-09-14-grc-capability-gap-analysis.md`
**Sub-project:** P0', narrowed first pass (per sequencing decision 2026-09-14)

## 0. Correction to the gap analysis

The gap analysis stated that Concord has "no fetcher" and that catalog refresh
is manual. **That is wrong**, and this spec was rewritten once the existing code
was read properly.

`ccf.etl.sources` is a working catalog-currency subsystem:

- `CatalogSource` (`models.py:1098`) is a DB-backed registry of upstream
  authorities, seeded by `ccf sources-seed` with the NIST 800-53r5 catalog,
  800-53A r5, the HIGH baseline profile, and the cross-mappings workbook.
- `check_source()` fetches with `If-None-Match` ETag conditional requests and
  compares the body sha256, so a server ignoring the ETag still produces no
  false "changed" event.
- `parse_oscal_catalog()` indexes every control by a hash of title + prose, and
  `_diff_index()` produces a real added / modified / removed changelog.
- `CatalogCheck` is an append-only log of every poll (status, http_status,
  sha256, duration, detail) — the drift audit trail.
- Scheduler (`governance/scheduler.py`), alert digest (`governance/digest.py`,
  which surfaces sources whose `last_status == "changed"`), API
  (`api/routes/catalog.py`), and CLI (`ccf sources-seed`, `ccf sources-check`)
  are all wired.
- `auto_ingest` defaults to **off**, because "drift is recorded for a human to
  review and re-ingest through a gated PR, which is the safer default for a
  compliance catalog."

That last point is the same human-gated principle the first draft of this spec
proposed as though it were new. It is existing, deliberate design.

**The actual gap is a disconnect, not an absence.** Two subsystems exist and do
not talk to each other:

- `etl/sources.py` polls upstream URLs and records that content drifted.
- `catalog/oscal.py` loads sha256-pinned files from disk — and everything that
  matters (SSP seeding, reconciliation, scoring, reliability) reads *that*.

So drift is detected and then goes nowhere. There is no way to take the new
upstream content and **adopt** it into the pinned catalog the platform actually
reads. That, plus the four deficiencies below, is this sub-project.

## 1. Problem

What is genuinely missing:

1. **No adoption path.** Detected drift cannot be promoted into the pinned
   catalog that `load_oscal_catalog` resolves. This is the "update against my
   baseline" gap.
2. **No revision retention.** `CatalogSource` holds `last_sha256` and
   `content_index` for the *latest* poll only. There is no set of retained
   revisions to diff between arbitrary points or roll back to. (The same
   last-value-only shape as `CaptureSnapshot` — a recurring pattern worth
   naming.)
3. **No commit pinning.** Sources poll
   `raw.githubusercontent.com/usnistgov/oscal-content/**main**/...` — a moving
   branch ref. A recorded drift cannot be reproduced later.
4. **No impact analysis.** The existing diff is catalog-level (controls added /
   modified / removed). It does not say what adoption does to each system's
   baseline or to authored SSP content.
5. **No offline import.** Air-gapped environments cannot adopt at all.
6. **Manifest is hand-maintained.** `catalog_data/MANIFEST.json` is edited by
   hand; adoption must generate it.

## 2. Goals and non-goals

**Goals.**

1. Retain multiple revisions per source, content-addressed and commit-pinned.
2. Materialize a revision on disk with a generated `MANIFEST.json` so
   `catalog/oscal.py` can load it unchanged.
3. Diff any two retained revisions, including parameters and baseline membership.
4. Report what adopting a revision does to each organization's baselines and
   authored content.
5. Adopt only by explicit, audited human action.
6. Support offline import for air-gapped environments.

**Non-goals.**

- **No new source registry.** `CatalogSource` is the registry. Sources are
  added to `DEFAULT_SOURCES`, not to a parallel structure.
- **No new poll/drift log.** `CatalogCheck` stays the poll log.
- **No new fetch client.** `_fetch()` and its ETag handling are reused.
- **No per-tenant catalog divergence.** Adoption is platform-global (§6.5).
- **No auto-adoption.** Preserves the existing `auto_ingest=False` principle.
- **No network dependency in catalog reads.**
- **No new reconciliation logic.** The impact report calls
  `catalog/reconcile.py`.

## 3. Scope

**Sources this pass.** Already seeded: `nist_800_53_r5_catalog`,
`nist_800_53a_r5_assessment`, `nist_800_53_r5_high_baseline`. Added:

| Source key | Why |
|---|---|
| `nist_800_53_r5_low_baseline` | Only HIGH is seeded; `_BASELINE_FILES` needs all three |
| `nist_800_53_r5_moderate_baseline` | Same |
| `nist_csf_2_0_catalog` | Bundled on disk but unregistered as a source |
| `nist_800_171_r3_catalog` | **New content** — proves source-agnostic revisioning; supplies the CMMC lane's mapping targets |

**Explicitly deferred** (second pass, alongside P5): FedRAMP Rev 5 OSCAL
baselines (L/M/H + LI-SaaS); DISA CCI list and CCI -> control-item mapping;
derived CMMC catalog; CR26 / KSI definition source (registers as a
`CatalogSource` with its own `kind` in P9a); NIST 800-171 Rev 2.

Note 800-53A is already a registered *source*, but is not parsed into the
loaded catalog. Wiring it into assessment objectives belongs to P2, not here.

**Clarification on baselines and CR26.** `_BASELINE_FILES` is keyed
`low`/`moderate`/`high`. Those are **NIST SP 800-53B's own baselines**,
unaffected by CR26. FedRAMP's Certification Classes A–D are a separate FedRAMP
construct landing in P9a. Nothing here renames them or depends on the
unresolved Class-to-impact mapping.

## 3a. Authoritative source hierarchy

Three upstream repositories are routinely conflated. They are not the same
authority and this design keeps them separate:

| Repository | What it is | Concord's use |
|---|---|---|
| `usnistgov/oscal-content` | The **content** — 800-53 catalogs, 800-53B baseline profiles, CSF, 800-171 | Registered sources; parsed by `catalog/oscal.py` |
| `usnistgov/OSCAL` | The **specification** — the JSON schemas exports are validated against | Bundled under `ccf/oscal/schemas` (pinned v1.1.2, retrieved 2026-07-28, hand-maintained); registered as a `generic` source so releases are at least *detected* |
| `GSA/fedramp-automation` | Historical FedRAMP OSCAL baselines | Deferred to the second pass (§3) |

**There is no official FedRAMP 20x OSCAL package.** The OSCAL Foundation
publishes a community-maintained Phase One KSI catalog; it is not a FedRAMP PMO
artifact and **must not** become Concord's system of record. The FedRAMP
community has itself noted that experimental OSCAL use for 20x was not an
official FedRAMP position.

The rule that follows, governing P9a:

> **FedRAMP provides the requirements. NIST provides OSCAL. Concord converts
> the authoritative FedRAMP 20x requirements into OSCAL itself.**

Concord already takes this posture and it should be preserved rather than
rediscovered: `fedramp20x/catalog.py` seeds KSIs from
`data/fedramp_20x_ksi_catalog.json` with an idempotent upsert keyed on
`identifier`, and the `fedramp20x` package docstring explicitly disclaims
official FedRAMP authorization or validated OSCAL output. The normalized KSI
object is Concord's own, carrying its FedRAMP identifier, requirement,
objective, source URL, source version, and publication date — and an OSCAL
representation is *generated* from it against the NIST schemas, never ingested
from a community catalog.

## 4. Approach

Add a **revision** object between the existing poll layer and the existing
pinned loader, bridging the two.

```
CatalogSource  ──poll (exists)──>  CatalogCheck  (exists: drift detected)
      │
      └──materialize──>  CatalogRevision  ──adopt──>  data/oscal/<source>/<rev>/
                              (new)                    + generated MANIFEST.json
                                                              │
                                                    load_oscal_catalog (exists)
```

Revisions are directories on disk with metadata in Postgres. Rejected
alternatives:

- **DB-resident content (JSONB).** 800-53r5 is ~5MB and several revisions would
  be retained; it discards `_verify`'s hash checking and its structural-coupling
  guard; and it puts Postgres in front of catalog reads that today need no
  database — `catalog/report.py` and the pure `ssp/nist80053.py` path both
  depend on that.
- **Reuse `CatalogSource.content_index` as the revision store.** It is a single
  latest-poll snapshot with no retention, no commit pin, and no materialized
  files. Extending it to hold N revisions would turn one row into a
  mini-database.
- **Fetch on demand at load.** Breaks air-gapped deployment and reproducibility,
  and destroys the hash-pin property authorization decisions rest on.

The deciding constraint: GovCloud, GCC High, and IL4/5 targets cannot reach
`github.com`, so fetching stays an administrative operation and never a runtime
dependency.

This extends an existing seam. `load_oscal_catalog(base_dir: Path | None)`
already parameterizes the directory, with four real callers
(`ssp/seed.py:222`, `catalog/report.py:23`, `reliability/checks.py:771`, and the
packaging note in `catalog/__init__.py`).

## 5. Data model

**One new table.** Poll history stays in `CatalogCheck`; adoption is recorded in
the hash-chained `audit_log`; the reviewed impact report is stored on the
revision row.

```
catalog_revisions
  id                    bigint pk
  source_id             int fk -> ccf.catalog_sources.id ON DELETE CASCADE
  revision              varchar(64)   -- 12-char commit-sha prefix, or 'bundled'
  upstream_commit_sha   varchar(64)   -- full sha; null for an offline import
  upstream_url          text
  oscal_version         varchar(32)   -- catalog metadata version
  content_sha256        varchar(64)   -- sha256 of the primary document body
  files                 jsonb         -- {filename: sha256}; mirrors the manifest
  content_index         jsonb         -- {control_id: prose_hash} from parse_oscal_catalog
  content_dir           text          -- null => the packaged bundled revision
  status                varchar(16)   -- available | adopted | superseded | rejected
  retrieved_at          timestamptz not null default now()
  retrieved_by          varchar(255)
  adopted_at            timestamptz
  adopted_by            varchar(255)
  adoption_impact       jsonb         -- the impact report as reviewed at adoption
  notes                 text

  UNIQUE (source_id, revision)
  partial unique index on (source_id) WHERE status = 'adopted'
```

The partial unique index makes "exactly one adopted revision per source" a
database invariant rather than application discipline.

`content_index` is deliberately the same shape `parse_oscal_catalog()` already
returns, so the existing `_diff_index()` works on it directly.

**Tenancy.** Catalogs are global reference data. Like `catalog_sources` and
`catalog_checks`, this table carries no `organization_id` and no RLS —
`models.py:1751` already documents non-tenant reference tables as an
established category. Writes are gated by the existing admin RBAC role. The
migration must state this explicitly.

## 6. Components

### 6.1 Materializing a revision (extends `etl/sources.py`)

`check_source()` currently detects drift and stops. It gains an optional
follow-on: when the body is new and the source's `kind == "oscal_catalog"`,
persist a `CatalogRevision` with `status='available'`.

- `revision` = 12-char prefix of the resolved upstream commit SHA.
- Content is written to `data/oscal/<source_key>/<revision>/<filename>`.
- A `MANIFEST.json` is **generated** — `oscal_version`, `source_url`,
  `upstream_commit_sha`, `retrieved_at`, and the `files` sha256 map — in the
  exact shape `_verify()` expects.
- **Parse-check before the row is committed:** run `load_oscal_catalog` against
  the new directory. A revision that does not parse is recorded
  `status='rejected'` with the error in `notes`, and its directory removed.

Never touches the adopted revision. Re-observing an existing commit SHA is a
no-op, so this stays idempotent like the poll it extends.

### 6.2 Commit pinning

`DEFAULT_SOURCES` URLs point at `.../main/...`. Add a `resolve_commit_sha()`
helper that queries the GitHub commits API for the ref that served the content,
and record it on the revision. Where a source's host offers no commit concept,
`upstream_commit_sha` is null and `content_sha256` is the only identity — that
is acceptable for the identity property, and the design does not pretend
otherwise.

Existing source URLs are left on `main` for *polling* (that is what detects
drift); the pin is recorded per revision, which is where reproducibility
actually matters.

### 6.3 Offline import

`ccf catalog import <source-key> <dir|zip>` — same materialization, same
parse-check, same landing. If the payload contains a `MANIFEST.json` it is
verified as-is; otherwise one is generated from the files present.
`upstream_commit_sha` is null and the operator's stated provenance goes in
`notes`. No network.

### 6.4 Diff

A pure function over two loaded catalogs — no DB, no network:

```python
def diff_revisions(old: OscalCatalog, new: OscalCatalog) -> CatalogDiff
```

`CatalogDiff` reports controls added, removed, newly withdrawn, and
un-withdrawn; title, statement, and guidance changes; parameters added, removed
and changed per control; and baseline-membership changes per level (controls
entering or leaving LOW / MODERATE / HIGH).

This is a superset of the existing prose-hash diff, so the control-level
added/modified/removed computation **delegates to `etl.sources._diff_index()`**
over the stored `content_index` values rather than recomputing it. The new work
is parameters and baseline membership, which the prose-hash index cannot see.
`_diff_index` is promoted to a public name (`diff_content_index`) as part of
this task, since it gains a second caller.

Built on the existing `OscalControl` / `OscalParam` dataclasses and
`oscal_id_to_canonical`. No new parsing.

### 6.5 Impact report

```python
async def build_adoption_impact(session, *, diff: CatalogDiff) -> AdoptionImpact
```

Read-only. Aggregated platform-wide and broken down per organization:

- **Systems affected** — per `System.fedramp_baseline`, which controls enter or
  leave that system's applicable set.
- **Orphaned authored content** — `SSPControlEntry` rows referencing removed or
  newly withdrawn controls.
- **Stale narrative** — entries whose control statement text changed.
- **Parameter drift** — entries whose ODP parameters changed.
- **Dangling mappings** — `framework_mappings` pointing at removed controls.
- **KSI references** — `fedramp20x` `nist_refs` pointing at removed controls.

Dangling-mapping and unknown/withdrawn-id detection **calls
`catalog/reconcile.py`** against the candidate revision rather than
reimplementing it — that engine already does this work against a pinned catalog.

**Why global adoption is safe for in-flight work.** `SSPControlEntry` rows are
authored copies, not live catalog views, so adoption does not silently rewrite
an assessment in progress. Affected entries surface in the report as requiring
review. Per-tenant pinning was rejected because divergent catalogs would make
cross-tenant mappings and the reconciliation engine incoherent.

### 6.6 Adoption

`ccf catalog adopt <source-key> <revision> [--acknowledge-impact]`

- Computes the impact report; **refuses without `--acknowledge-impact` when the
  report is non-empty** — meaning it names at least one affected system,
  orphaned entry, stale narrative, parameter drift, dangling mapping, or KSI
  reference.
- In one transaction: previous adopted -> `superseded`; this revision ->
  `adopted`; store the reviewed report in `adoption_impact`; write an
  `audit_log` entry (hash-chain) naming actor and revision.
- Rolling back is adopting an earlier revision, through the same gate.

### 6.7 Resolution

`_resolve_dir` gains revision awareness. Order, per source:

1. explicit `base_dir` argument (preserves today's dev-override behavior)
2. the adopted revision's `content_dir`
3. the packaged in-wheel directory (the implicit `bundled` revision)

Falling back to packaged when an adopted directory is missing keeps a container
with no volume working. `_verify` is unchanged, including its guard that every
required file must be listed in the manifest.

Packaged content keeps today's flat layout, registered as revision `bundled`
with `content_dir` null. Only fetched and imported revisions use the nested
layout, so the wheel needs no file moves.

Because resolution now consults the database while `load_oscal_catalog` must
stay DB-free, the adopted directory is resolved by a **separate async helper**
that callers with a session use; `load_oscal_catalog(base_dir=...)` keeps its
current pure-filesystem signature and gains nothing. This preserves the
no-database-required property of `catalog/report.py` and `ssp/nist80053.py`.

### 6.8 API

Extends `api/routes/catalog.py`, which already serves sources and checks.
Admin-scoped, SoD-gated on the write:

```
GET  /api/catalog/sources/{source_id}/revisions
GET  /api/catalog/revisions/{id}/diff?against=<id|adopted>
GET  /api/catalog/revisions/{id}/impact
POST /api/catalog/revisions/{id}/adopt
```

### 6.9 Reliability check

Extend the existing catalog check in `reliability/checks.py`: the adopted row
exists, its directory resolves, every file verifies against the manifest, the
catalog parses, and the DB `files` map matches disk. This catches the one real
risk in this approach — filesystem and adoption pointer drifting apart.

## 7. Testing strategy

Pure-function coverage first; the diff and verification cores need neither DB
nor network.

- **Diff** — synthetic old/new catalogs: control added, removed, newly
  withdrawn, un-withdrawn; title/statement/guidance change; parameter added,
  removed, changed; baseline membership entering and leaving each level; and
  that control-level results match `diff_content_index` on the same input.
- **Verification** — a tampered file yields `OscalManifestError`; a generated
  manifest omitting a required file yields `OscalManifestError` (preserving the
  existing structural-coupling guard); the generated manifest's recorded sha256
  matches the bytes written.
- **Materialization** — mocked HTTP: a new body produces an `available`
  revision with a generated manifest that `load_oscal_catalog` can read; a
  non-parsing body produces `status='rejected'` and leaves no directory;
  re-observing the same commit SHA is a no-op; the adopted revision is
  untouched throughout.
- **Import** — directory and zip paths verify, parse-check, and land with null
  `upstream_commit_sha`.
- **Resolution** — explicit override beats adopted; adopted beats packaged; a
  missing adopted directory falls back to packaged;
  `load_oscal_catalog` performs no DB access.
- **Adoption** — refuses without acknowledgement on a non-empty impact report;
  the partial unique index rejects a second adopted row for one source; the
  supersede transition is atomic; an `audit_log` entry is written; rollback to
  an earlier revision works.
- **Impact** — orphaned entries, stale narrative, parameter drift, dangling
  mappings, and KSI references are each detected, and `reconcile.py` is the code
  path used for dangling/withdrawn detection.
- **Offline guarantee** — with fetching disabled, no load, diff, impact, or
  adopt path performs network I/O.
- **Regression** — existing `etl/sources.py` poll behavior is unchanged when
  revision materialization is disabled: 304 stays `unchanged`, an unchanged
  sha256 produces no false drift.

Per repo practice, guards get mutation-tested: delete each guard and confirm a
test fails rather than assuming coverage from reading.

## 8. Migration

One Alembic revision, `0066_catalog_revisions`, revising
`0065_user_session_version`:

1. Create `catalog_revisions` with the FK, unique constraint, and partial unique
   index. State in the migration that this table is intentionally global with no
   RLS, consistent with `catalog_sources` / `catalog_checks`.
2. Seed the currently bundled content as `revision='bundled'`,
   `status='adopted'`, `content_dir=null` (resolving to the packaged directory),
   with `files` and `oscal_version` read from the existing `MANIFEST.json` and
   `upstream_commit_sha` taken from the commit in its `source_url`. This row
   attaches to the existing `nist_800_53_r5_catalog` source, created by
   `sources-seed` if absent.
3. Include the `pg_roles` GRANT guard the RLS migrations established as standard
   (`DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app')
   THEN GRANT ... END IF; END $$`).

Confirm `alembic heads` returns exactly one head before assuming the chain is
sound.

## 9. Risks

| Risk | Mitigation |
|---|---|
| Filesystem and adoption pointer drift | Reliability check (§6.9); packaged fallback on a missing directory |
| A fetched revision is malformed | Parse-check before the row commits; `status='rejected'` (§6.1) |
| Upstream change silently moves an authorization boundary | Adoption is always human, gated on a reviewed impact report; no auto-adopt path, preserving the existing `auto_ingest=False` principle |
| Containers lose fetched revisions | The packaged `bundled` revision always resolves; `data/oscal` documented as needing a volume |
| Air-gapped deployment cannot fetch | `ccf catalog import` (§6.3) |
| Adding DB lookups to catalog resolution breaks DB-free callers | Separate async resolver; `load_oscal_catalog` signature and purity preserved (§6.7) |
| Regression in the working poll path | Materialization is additive and separately tested (§7 Regression) |

## 10. Open items

1. **800-171 Rev 3 OSCAL path.** The exact filename under
   `usnistgov/oscal-content/nist.gov/SP800-171/` must be confirmed at
   implementation time and pinned in `DEFAULT_SOURCES`.
2. **Scheduler cadence.** Settled: the existing poll cadence is unchanged, and
   revision materialization rides on it. Adoption never rides on it.
