# P1 — Assurance Capability Ontology (design)

**Date:** 2026-09-14
**Status:** Design approved in brainstorming; awaiting spec review
**Programme context:** `docs/superpowers/assessments/2026-09-14-grc-capability-gap-analysis.md`
**Inventory (authoritative on what exists):** `docs/architecture/forge-capability-inventory.md`
**Sub-project:** P1 — the root gap

## 1. Problem

Concord is control-first. `SSPControlEntry` is keyed `(project_id, control_id)`
with narrative authored per control (`models.py:1033`). `Evidence` parents to a
`ControlImplementation`, itself keyed `(system_id, control_id)`.
`ControlTest` keys to a control plus an ODP key. `framework_mappings` crosswalks
control **to control**. And `Risk` (`models.py:862`) exists but is *terminal* —
it has no edge downward, because nothing exists for it to point at.

The consequence is duplication proportional to framework breadth. One MFA
decision must be written into IA-2, IA-2(1), IA-2(2), AC-7, MA-4 and every
other dependent control — then rewritten per project and per framework. At
800-53 High (400+ controls) across FedRAMP, CMMC, and 800-171 simultaneously,
that is the dominant cost of the product.

There is no object representing *a thing the organization does*. Adding one,
with edges to controls, components, risks, KSIs, and evidence, is this
sub-project. It is the root gap: the SSP engine (P4), gap assessment and Trust
Center (P6), and capability-level validation (P2) all key off it, so building
them control-first means re-keying later.

## 2. Goals and non-goals

**Goals.**

1. `Capability` as a first-class, **org-scoped** object — authored once, reused
   across every system, project, and framework.
2. Edges: capability → canonical control, → `SystemComponent`, → `Risk`, → KSI.
3. Cross-framework reach **through the existing crosswalk**, not a new mapping.
4. Control status *derivable* from capability coverage, without overwriting
   authored status.
5. Evidence attachable to a capability once, instead of duplicated per control.

**Non-goals.**

- **No new mapping table.** Concord's `framework_mappings` remains the
  authoritative crosswalk.
- **No `Stack` or `Solution` table.** `SystemComponent.type` already includes
  `policy` and `process`, and `System` is the boundary; Solution is a grouping
  label on `Capability`. Either can be added later without reshaping this.
- **No overwrite of authored status or existing evidence links.**
- **No SSP narrative derivation** — that is P4, and the payoff of this work.
- **No KSI *validation* derivation** — the edge ships here; wiring
  `fedramp20x/validation.py` to consume it is P2.
- **No pack-shipped capability libraries** — natural follow-on once the object
  exists.
- **No new status vocabulary** — reuse the `impl_status` enum.

## 3. Data model

New package `src/ccf/capability/` for the service layer; the ORM models go in
`src/ccf/models_capability.py`, following the repo's existing
`models_<domain>.py` convention (`models_grc.py`, `models_tprm.py`, …).

### 3.1 `capabilities`

```
capabilities
  id               bigint pk
  organization_id  int fk -> ccf.organizations.id ON DELETE CASCADE   (RLS)
  key              varchar(64)   -- stable slug, addressable, pack-installable
  title            varchar(255)
  statement        text          -- the reusable narrative
  purpose          text
  responsible_role varchar(128)
  solution         varchar(128)  -- grouping label; Paramify's Solution as a facet
  status           impl_status   -- reuses the EXISTING enum
  notes            text
  created_at       timestamptz not null default now()
  updated_at       timestamptz not null default now()

  UNIQUE (organization_id, key)
```

`status` deliberately reuses `impl_status`
(`not_implemented | planned | partial | implemented | inherited |
not_applicable`) rather than inventing a parallel vocabulary.

### 3.2 Edge tables

Four tables, one edge each. **Every one carries `organization_id`** — not
denormalization for its own sake, but because the RLS pattern compares
`ccf.current_tenant()` against that column, and
`tests/test_rls_registry_no_gap.py` fails loudly for any tenant table without
it. The alternative (omitting it) would force these onto the `GLOBAL_TABLES`
allowlist, which would be a tenant-isolation hole.

```
capability_controls
  id, organization_id, capability_id fk, control_id varchar(64), created_at
  UNIQUE (capability_id, control_id)

capability_components
  id, organization_id, capability_id fk, component_id fk -> system_components
  UNIQUE (capability_id, component_id)

capability_risks
  id, organization_id, capability_id fk, risk_id fk -> risks
  UNIQUE (capability_id, risk_id)

capability_ksis
  id, organization_id, capability_id fk, ksi_identifier varchar(32)
  UNIQUE (capability_id, ksi_identifier)
```

**Why `capability_controls.control_id` is a string, not an FK to
`ccf.controls`.** Those two control sets genuinely differ —
`catalog/reconcile.py` exists precisely because the workbook-derived `controls`
table and the OSCAL catalog disagree. An FK would make capabilities
un-mappable to catalog controls the workbook lacks. The column stores the
**canonical** id (`AC-2`), matching what `SSPControlEntry.control_id` already
does.

**Why `capability_ksis.ksi_identifier` is a string, not an FK to `ksis`.**
Same reasoning, plus `KSI` is a global reference table on the `GLOBAL_TABLES`
allowlist; a tenant-owned FK into it would couple tenant rows to reference-data
row ids that reseeding can change. `KSI.identifier` is the stable key.

### 3.3 Alterations to existing tables

```
control_implementations
  derived_status  impl_status    NULL   -- what capability coverage computes
  derived_at      timestamptz    NULL
  derived_from    jsonb  not null default '{}'   -- contributing capabilities

evidence
  implementation_id  bigint  -> becomes NULLABLE
  capability_id      bigint  NULL fk -> ccf.capabilities.id ON DELETE CASCADE
  CHECK (implementation_id IS NOT NULL OR capability_id IS NOT NULL)
```

`ControlImplementation` carries `UNIQUE (system_id, control_id)` — one row per
pair — so authored and derived values cannot be separate rows. They are sibling
**columns** instead. This is better than the flag first proposed in
brainstorming: `status` keeps its exact current meaning, so every existing
reader (SSP, scoring, analytics, OSCAL export, the assessment engine) is
unaffected, and **divergence stays visible** rather than being silently
resolved. "Your SSP says `planned` but your capabilities say `implemented`" is
actionable information; an overwrite destroys it.

The evidence CHECK guarantees no row can become parentless. Every existing row
already has `implementation_id`, so the nullability change is safe.

## 4. Components

### 4.1 Rollup — pure

```python
def roll_up(statuses: Iterable[str]) -> str | None
```

Deterministic, no DB, no I/O. Rules:

- `not_applicable` capabilities are **excluded** from the rollup entirely.
- `inherited` counts as satisfied, equivalent to `implemented`.
- Otherwise **worst-of** wins: one `planned` capability among `implemented`
  ones yields `partial`, not `implemented`.
- No contributing capabilities (or all `not_applicable`) yields `None` — no
  derived status is written, rather than a misleading `not_implemented`.

**Why worst-of.** Over-claiming control status in an authorization package is
the dangerous direction; under-claiming is merely conservative. `derived_from`
records which capability lowered the result, so the conservatism is explainable
rather than mysterious. Capabilities are treated as *jointly* required for a
control, which is the safe reading when the model cannot express "alternative
means."

### 4.2 Derivation — async

```python
async def derive_for_system(session, *, system_id: int) -> int   # rows touched
```

For each `(system, control)` reachable from that system's capabilities:

1. Find capabilities bound to the system via
   `capability_components` → `SystemComponent.system_id`.
2. Group their `capability_controls` by canonical control id.
3. `roll_up` each group.
4. Resolve the canonical id to `controls.id` via `canonicalize()` —
   **mandatory**, because `controls.identifier` is zero-padded (`AC-01`) while
   the canonical form is `AC-1`.
5. Write `derived_status`, `derived_at`, `derived_from` onto the **existing**
   `ControlImplementation` row. **Never writes `status`, and never creates a
   row.**

**Why derivation never creates rows.** `control_implementations.status` is
`NOT NULL DEFAULT 'not_implemented'`. A created row would therefore assert
`not_implemented` for a control that previously had *no row at all* — and
"absent" and "not_implemented" are not the same thing to the existing coverage
and analytics queries. Fabricating rows could silently change reported
coverage, which is the one outcome this design cannot risk. So derivation only
*annotates* what the platform already tracks.

Capability coverage for controls with no implementation row is still
answerable, live, through `GET /api/controls/{control_id}/capabilities` and the
coverage endpoint — no stale derived rows, and no new rows.

Idempotent: re-running with unchanged capabilities produces no change. Runs on
demand via API/CLI and on the existing `governance/scheduler.py` cycle — no new
scheduler.

**Binding a capability with no technical component.** `SystemComponent.type`
already includes `policy` and `process`, so a policy-backed or process-backed
capability binds through a component of that type. This is the OSCAL-native
answer, reuses `boundary/`, and avoids a fifth edge table.

### 4.3 Cross-framework reach — async

```python
async def framework_reach(session, *, capability_id: int) -> dict[str, list[str]]
```

Canonical control id → `canonicalize()` → `controls.identifier` →
`framework_mappings` → `{framework_code: [values]}`. Verified working: `AC-2`
resolves to CMMC `AC.L2-3.1.2`, FedRAMP `AC-2`, ISO `A.5.16`.

A capability maps to the **canonical 800-53 control only**. Mapping a capability
directly to each framework would fork the crosswalk Concord already maintains
and guarantee the two drift apart.

### 4.4 API

New `api/routes/capabilities.py`, plus additions to the existing
`api/routes/controls.py`. Reads are principal-scoped by RLS; writes use the
same `require_role` dependency as other tenant mutations.

```
GET    /api/capabilities                       list (filter: solution, status)
POST   /api/capabilities                       create
GET    /api/capabilities/{id}
PATCH  /api/capabilities/{id}
DELETE /api/capabilities/{id}
PUT    /api/capabilities/{id}/controls         replace control edges
PUT    /api/capabilities/{id}/components       replace component edges
PUT    /api/capabilities/{id}/risks            replace risk edges
PUT    /api/capabilities/{id}/ksis             replace KSI edges
GET    /api/capabilities/{id}/frameworks       cross-framework reach (4.3)
GET    /api/controls/{control_id}/capabilities which capabilities satisfy it
POST   /api/systems/{system_id}/derive-status  run derivation, return count
```

`PUT` for edges (replace the set) rather than per-edge POST/DELETE: the client
already holds the whole set, and replace-set is idempotent.

### 4.5 CLI

`ccf capability derive --system <id>` on the existing `app` Typer group,
following the `catalog_app` pattern.

## 5. Migration

One Alembic revision, `0067_capability_ontology`, revising
`0066_catalog_revisions`:

1. Create `capabilities` and the four edge tables.
2. For each of the five: `ENABLE` and `FORCE ROW LEVEL SECURITY`, then
   `CREATE POLICY tenant_isolation ... FOR ALL USING (...) WITH CHECK (...)`
   following migration 0020/0064's exact pattern. These are tenant-owned and
   must **not** join `GLOBAL_TABLES`.
3. Add `derived_status`, `derived_at`, `derived_from` to
   `control_implementations`.
4. Alter `evidence.implementation_id` to nullable; add `evidence.capability_id`;
   add the CHECK constraint.
5. Include the `pg_roles` GRANT guard the RLS migrations established as
   standard.

Confirm `alembic heads` returns exactly one head. No data migration: existing
rows are untouched, and `derived_*` starts NULL/empty everywhere.

## 6. Testing strategy

Pure functions first — the rollup needs neither DB nor network.

- **Rollup** — every status combination: all `implemented`; mixed
  `implemented`/`planned` → `partial`; `not_applicable` excluded; `inherited`
  treated as satisfied; empty and all-`not_applicable` → `None`.
- **Derivation** — writes `derived_status`/`derived_at`/`derived_from`;
  **never** mutates `status` (asserted explicitly); **never creates a
  `ControlImplementation` row** (asserted by comparing row counts before and
  after, so coverage math cannot shift); idempotent on re-run; respects the
  zero-padded/canonical id difference (a capability on `AC-2` reaches the
  `AC-01`-style row).
- **Divergence** — an authored `planned` beside a derived `implemented` is
  preserved and both are readable.
- **Cross-framework reach** — `AC-2` returns CMMC, FedRAMP, and ISO values via
  the existing crosswalk; a capability mapped to a control absent from the
  workbook returns empty rather than raising.
- **Evidence** — the CHECK rejects a row with neither parent; a
  capability-only row is accepted; existing `implementation_id` rows still work.
- **RLS** — all five tables reject cross-tenant reads and writes; the
  `GLOBAL_TABLES` guard test still passes (these tables are *not* added to it).
- **Edge uniqueness** — duplicate edges rejected by constraint.
- **Migration** — one head; `derived_*` NULL after upgrade; downgrade drops
  cleanly.

Per repo practice every guard is mutation-tested: delete it, confirm a test
fails, restore. Tests must not assume an empty database (`session_scope`
commits and the schema is migrated once per session), must use unique values
for unique columns, and must clean up rows other modules count.

## 7. Risks

| Risk | Mitigation |
|---|---|
| Derivation cost at scale (capabilities × controls × systems) | Per-system, on demand plus the existing scheduler cycle — never inside a request path; idempotent so re-runs are cheap |
| Derivation silently changes reported coverage | It never creates a `ControlImplementation` row, only annotates existing ones, and a test asserts the row count is unchanged (§4.2) |
| Worst-of rollup surprises users | `derived_from` names the contributing capabilities and the one that lowered the result |
| Two narrative homes (`ControlImplementation.narrative` and `SSPControlEntry.part_narratives`) grow to three | P1 adds `Capability.statement` as the *reusable* source; consolidating the other two is P4's job and is explicitly out of scope here |
| `evidence.implementation_id` nullability weakens an invariant | Replaced by a CHECK that is strictly stronger than "not null on one column" — a row must have at least one parent |
| Capability edges drift from a re-seeded KSI catalog | Edge stores `KSI.identifier`, the stable key, not a row id |
| Adding five tenant tables misses an RLS policy | Migration creates all five policies; the existing `test_rls_registry_no_gap` guard fails loudly otherwise |

## 8. Open items

1. **`Capability.key` generation.** Slug from the title on create, with a
   uniqueness suffix per org. Settled: server-generated, client may override.
2. **Alternative-means capabilities.** The worst-of rollup treats capabilities
   as jointly required. If a customer needs "either A or B satisfies this
   control," that wants a grouping on `capability_controls` (e.g. an
   `alternative_group` column). Deliberately deferred until a real case
   appears — YAGNI, and the column can be added without reshaping anything.
