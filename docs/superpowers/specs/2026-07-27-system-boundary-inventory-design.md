# System Boundary & Inventory Model — Design (Keystone #1)

- **Date:** 2026-07-27
- **Status:** Approved (brainstorming → spec)
- **Related:** [[ssp-ai-assessment-program]], `docs/superpowers/assessments/2026-07-27-holistic-capability-map.md` (Keystone #1),
  `src/ccf/api/routes/oscal.py`, `src/ccf/ssp/completeness.py`, `src/ccf/models.py`

## Problem

Concord models controls thoroughly but has **no model of the actual system** the controls
protect. Today:
- `System` carries name/description, a system-level FIPS-199 triad, baseline, ATO status.
- `SystemProfile` holds freeform JSONB (`workloads`, `endpoint_scope`, `data_types`) used for
  control *derivation* — not a formal inventory.
- The OSCAL SSP export **synthesizes placeholders**: `_oscal_system_implementation`
  (`oscal.py:168`) emits exactly one fake `software` component; `_oscal_information_types`
  (`oscal.py:109`) emits one information-type from the system triad. `authorization_boundary`
  is a single free-text field checked in `ssp/completeness.py`.

A real SSP (and a valid OSCAL SSP `system-implementation`) requires an **enumerated authorization
boundary**: components, inventory items, information types (each categorized), and
interconnections. This is the single largest SSP-completeness gap after control statements — the
backbone the OSCAL SSP, the CRM, and assessment scoping all reference.

## Goal

Add a first-class, tenant-scoped **boundary & inventory model** and wire it into the OSCAL SSP
export and SSP-completeness scoring, replacing the synthesized placeholders with real data.

### Decisions (from brainstorming)

| Decision | Choice |
|---|---|
| v1 entity scope | **Boundary backbone**: Components + Inventory items + Information types (per-type FIPS-199/800-60) + Interconnections/ISAs. |
| Population | **Manual first, import-ready** — CRUD (API + UI); service takes structured dicts so a future connector-import mapper drops in. No connector auto-import in v1. |
| Control allocation | **Keep control implementations system-level**; emit a real OSCAL system-implementation from the new inventory. By-component allocation is v2. |
| Diagrams | **In v1**: auto-generate the authorization-boundary + data-flow diagrams from the model (always in sync) — see §Diagrams. |
| State-of-the-art hooks | **In v1** (cheap, unlock the roadmap): persistent OSCAL UUIDs + discovery/provenance fields on every entity — see §SOTA. |

### Non-goals (v1) — deferred deliberately
Ports/protocols/services per component; leveraged authorizations; **connector auto-import /
discovery** (schema is ready for it — §SOTA); by-component control allocation; server-side raster
diagram rendering for docx (v1 renders Mermaid client-side + ships the source; docx image embed is v2).

### State-of-the-art hooks folded into v1 (design once, unlock later)
Every one of the four models additionally carries:
- `oscal_uuid` `str(36)` — a **stable, persisted** OSCAL UUID (generated once on create, never
  regenerated per export). Enables OSCAL round-trip, diffing, and machine-to-machine exchange
  (FedRAMP 20x). Impossible to retrofit cleanly later.
- `source` `str` default `"manual"` — `manual|connector|import`. Marks provenance so a future
  discovery/import layer coexists with hand-entered rows.
- `last_seen_at` `datetime|null` — set by a future discovery run; enables **drift detection**
  (an asset no longer seen, or newly appeared, without a migration).

These three columns are the seams for the SOTA roadmap (§State-of-the-art roadmap); v1 populates
`oscal_uuid` on create and defaults `source="manual"`, leaving `last_seen_at` null.

## Data model

Four new models in `src/ccf/models.py`, **all tenant-scoped** (`organization_id` FK →
`organizations`, RLS ENABLE + FORCE), each FK → `systems` (ON DELETE CASCADE is unsafe for
authorization records — use `ON DELETE CASCADE` here is acceptable since these are system-owned
descriptive records, but follow the soft-delete precedent: systems soft-delete, so boundary rows
remain queryable; use plain FK with `ondelete="CASCADE"` guarded by the app's soft-delete). Follow
the exact `Mapped`/`mapped_column` patterns near `SystemProfile`.

RLS policy (mirror migration 0046 syntax):
`USING (ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant())`, ENABLE + FORCE.

### 1. `SystemComponent` — `system_components`  (OSCAL `component`)
```
id                bigint pk
organization_id   int  FK organizations  (RLS)
system_id         int  FK systems  (indexed)
type              str  # software|hardware|service|policy|process|physical|network|interconnection|this-system
title             str(255)
description        text|null
status            str  # operational|under-development|disposition|other   (OSCAL status.state)
purpose           text|null
responsible_role  str(128)|null
props             jsonb  default {}    # extensibility (e.g. vendor, model)
oscal_uuid        str(36)  # stable OSCAL UUID (generated once on create)
source            str  default "manual"   # manual|connector|import
last_seen_at      datetime|null           # discovery/drift hook
created_at/updated_at
```

### 2. `InventoryItem` — `inventory_items`  (OSCAL `inventory-item`)
```
id                bigint pk
organization_id   int  FK organizations  (RLS)
system_id         int  FK systems  (indexed)
component_id      int|null  FK system_components  (the implemented-component link; SET NULL on delete)
asset_id          str(255)          # asset tag / identifier
description       text|null
asset_type        str  # software|hardware|firmware|virtual|network|appliance|other
vendor_name       str(255)|null
model             str(255)|null
version           str(128)|null
serial_number     str(255)|null
hostname          str(255)|null
ip_address        str(64)|null
virtual           bool default false
public            bool default false
baseline_config   text|null
props             jsonb default {}
created_at/updated_at
```

### 3. `InformationType` — `information_types`  (OSCAL `information-type`)
```
id                bigint pk
organization_id   int  FK organizations  (RLS)
system_id         int  FK systems  (indexed)
title             str(255)
description       text|null
categorization_system  str(255)  default "https://doi.org/10.6028/NIST.SP.800-60v2r1"
nist_800_60_id    str(64)|null     # e.g. "C.2.8.12"
confidentiality_impact  Enum(low,moderate,high)|null
integrity_impact        Enum(low,moderate,high)|null
availability_impact     Enum(low,moderate,high)|null
adjustment_justification text|null   # provisional vs adjusted rationale
props             jsonb default {}
created_at/updated_at
```
Reuse the existing `fips199_level` enum (`Enum("low","moderate","high", name="fips199_level", schema="ccf", create_type=False)`).

### 4. `Interconnection` — `interconnections`  (OSCAL `component` type=`interconnection`)
```
id                bigint pk
organization_id   int  FK organizations  (RLS)
system_id         int  FK systems  (indexed)
remote_system_name str(255)
remote_org        str(255)|null
direction         str  # incoming|outgoing|bidirectional
connection_type   str(128)|null     # e.g. VPN, API, SFTP
data_description  text|null
agreement_type    str  # ISA|MOU|MOA|none
agreement_ref     str(255)|null
agreement_date    date|null
expires_on        date|null
authorization_status str(64)|null
props             jsonb default {}   # e.g. ports/protocols list (simple), remote POC
created_at/updated_at
```

## Service layer — `src/ccf/boundary/`

- `service.py` — CRUD helpers per entity (create/update/delete/list by system), each accepting a
  **structured dict** (so a future connector mapper calls the same functions). All reads/writes go
  through the tenant-clamped session (RLS enforces isolation).
- `summary.py`:
  - `async def system_boundary_summary(session, system_id) -> BoundarySummary` — assembles
    components, inventory items (grouped by component), information types, interconnections.
  - `def categorization_rollup(info_types) -> dict` — high-water-mark C/I/A across information
    types; **reconciles against `System.fips199_*`** and returns any mismatch as a flagged
    finding (over/under-categorization), same spirit as the OSCAL reconciliation engine. Never
    silently overwrites the system triad.

## Integration

### OSCAL export (`src/ccf/api/routes/oscal.py`)
- Rewrite `_oscal_system_implementation` to build `components` from `SystemComponent` rows (+
  interconnections as `type=interconnection` components), and `inventory-items` from
  `InventoryItem` rows with `implemented-components` referencing their component uuid. Keep the
  users-from-roles logic. **Fall back to today's single placeholder component only when the
  boundary is empty** (never fabricate silently — annotate the fallback in `remarks`).
- Rewrite `_oscal_information_types` to emit one `information-type` per `InformationType` row
  (per-type C/I/A + adjustment justification in `remarks`); fall back to the system-triad-derived
  single type only when no information types exist.
- These builders take a session (or pre-fetched boundary summary) — thread it through `ssp_export`.

### SSP completeness (`src/ccf/ssp/completeness.py`)
- Add an optional `boundary` argument to `assess(project_metadata, entries, boundary=None)`
  (backward compatible). When provided, add a **boundary section** to the section score:
  - has ≥1 component; has ≥1 information type; categorization reconciles (no mismatch); every
    interconnection has an agreement (`agreement_type != "none"` and a ref).
- Rebalance the section weight to include boundary; keep control weight dominant. List boundary
  gaps in the report's `missing` area.

## Diagrams (v1 — self-drawing, always in sync)

`src/ccf/boundary/diagram.py`:
- `def boundary_mermaid(summary: BoundarySummary) -> str` — a **pure function** rendering the
  authorization-boundary diagram as Mermaid `flowchart` source: a subgraph for the system boundary
  containing its components (grouped/typed), inventory items collapsed under components, and
  interconnections drawn as edges to external systems (labeled with direction + agreement type).
- `def data_flow_mermaid(summary: BoundarySummary) -> str` — a data-flow view: information types
  as flows between components and across interconnections (direction from `Interconnection.direction`
  and `data_description`).

Because the source is generated deterministically from the model, the diagrams can never drift
from the inventory. Pure string output → fully unit-testable (assert nodes/edges present) with no
browser.

Rendering:
- **UI** — the boundary page + the SSP view render the Mermaid client-side via a vendored
  `mermaid.min.js` static asset (self-contained; reuse the existing `diagrams` feature's renderer
  if one is already vendored — check `templates`/`static` first).
- **OSCAL** — attach the Mermaid source (and, where available, a rendered SVG) as a
  `back-matter` resource on the SSP export, referenced from `system-implementation` remarks.
- **docx** — v1 embeds the Mermaid source as a fenced code block / link; raster image embed is v2.

## API + UI

- `src/ccf/api/routes/boundary.py` — JSON CRUD API under `/api/systems/{system_id}/boundary/...`
  (components, inventory, information-types, interconnections), scoped via the existing
  `require_system_in_scope` dependency (`systems.py:46`) + `require_role`.
- `src/ccf/api/routes/ui.py` (or a new `ui_boundary.py`) — a server-rendered page
  `GET /systems/{system_id}/boundary` with HTMX/Alpine CRUD for all four entities, gated like the
  other admin pages; template `system_boundary.html` extending `base.html`, following the
  `systems.html`/`system_detail.html` conventions. A read-only boundary summary surfaced in the
  SSP view.

## Migration

`0052_system_boundary_inventory` (down_revision = current head `0051_catalog_integrity_reports`):
create the four tables in schema `ccf`, indexes on `system_id`/`organization_id`, FKs, and RLS
policies (ENABLE + FORCE + tenant policy) mirroring migration 0046. Rebuild `api`+`migrator`
images after (known gotcha — [[migrator-image-rebuild]]).

## Testing (TDD; `ccf_test` harness — `session_scope()`, `fresh_engine`; no `db_session` fixture)

- **Model CRUD + RLS isolation** — create boundary rows under org A, confirm org B (tenant-clamped
  session) cannot see them (mirror `test_rls_coverage.py`).
- **Categorization rollup + reconciliation** — high-water-mark math; mismatch vs `System.fips199_*`
  is flagged, not silently applied.
- **OSCAL export** — with a populated boundary, `system-implementation` emits real components +
  inventory-items (with `implemented-components`) + interconnections, and `information-types` emits
  per-type entries; with an empty boundary, the annotated placeholder fallback still validates.
  Update/extend existing OSCAL export tests (`test_oscal_validation.py`).
- **Completeness** — boundary section raises/lowers the score; gaps listed.
- **Diagrams** — `boundary_mermaid`/`data_flow_mermaid` are pure functions: assert the expected
  nodes/edges/subgraph appear for a populated boundary, and a safe empty diagram for none.
- **Stable UUID** — `oscal_uuid` is generated on create and unchanged across two OSCAL exports
  (regression against per-export UUID churn).
- **API + UI** — CRUD roundtrip; role-gating (403 for non-admin, mirror `test_audit_rbac.py`);
  page renders (incl. the diagram).

## State-of-the-art roadmap (build on this foundation; v1 schema accommodates all four)

The v1 model + the three hook columns (`oscal_uuid`, `source`, `last_seen_at`) are deliberately
the substrate for the GRC/authorization frontier (cATO, FedRAMP 20x). Sequenced follow-ons:

1. **Living inventory + drift detection (cATO)** — a discovery layer that maps captured
   connector/IaC config (M365 Graph, AWS GovCloud, later Azure/GCP/Terraform state) into
   components/inventory via the same structured-dict service functions, stamping `source=connector`
   + `last_seen_at`. A reconcile pass flags drift (new/missing/changed assets) → a boundary finding
   that feeds significant-change evaluation and re-categorization. *Hooks: `source`, `last_seen_at`.*
2. **Boundary graph queries** — expose the components→inventory→interconnection→information-type
   relationships as a queryable graph for blast-radius, data-flow tracing, and "which controls
   protect this information type." *Hooks: the normalized FKs already form the graph edges.*
3. **OSCAL SSP round-trip (import)** — import an existing OSCAL SSP's `system-implementation` into
   these models (matched by `oscal_uuid`), diff against current, and stay in sync — machine-
   exchangeable packages. *Hooks: persistent `oscal_uuid`.*
4. **AI-drafted boundary narratives** — via the existing org AI gateway (under human review):
   draft component/ISA/data-flow descriptions from discovered config, and auto-classify data types
   → auto-derive per-type FIPS-199 (surfaced as a draft the categorization reconciler checks).
   *Hooks: `props` for provenance, the reconciler for validation.*

Each is its own spec→plan→build slice; none requires reworking the v1 schema.

## Rollout
Advisory/additive: no existing workflow changes behavior when the boundary is empty (placeholder
fallback preserves today's OSCAL output). Systems with a populated boundary get materially more
complete SSP/OSCAL output and a higher-fidelity completeness score.

## Success criteria
1. The four models exist with RLS; cross-tenant reads are blocked (tested).
2. OSCAL SSP `system-implementation` + `information-types` are built from real data, with an
   annotated fallback when empty (tested; OSCAL still validates).
3. Categorization rollup reconciles against the system triad and flags mismatches (tested).
4. SSP completeness reflects boundary presence (tested).
5. Auto-generated boundary + data-flow diagrams render from the model (tested; in UI + SSP).
6. Each entity has a stable persisted `oscal_uuid` (unchanged across exports) + `source`/
   `last_seen_at` hooks for the SOTA roadmap.
7. Full CRUD via API + a role-gated UI page; full suite green; ruff + mypy-strict clean.
