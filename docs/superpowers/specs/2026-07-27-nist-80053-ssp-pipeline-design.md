# NIST 800-53r5 FedRAMP SSP Pipeline — Design (Keystone #2)

- **Date:** 2026-07-27
- **Status:** Approved (brainstorming → spec)
- **Related:** `docs/superpowers/assessments/2026-07-27-holistic-capability-map.md` (Keystone #2), FR-01 (the current
  generator is CMMC/800-171 relabeled), the OSCAL reconciliation engine (`src/ccf/catalog/`), the boundary/inventory
  model (Keystone #1); `src/ccf/ssp/`, `src/ccf/api/routes/oscal.py`, `src/ccf/api/routes/ssp.py`

## Problem

Concord's SSP generator is entirely **CMMC Level 2 / NIST SP 800-171 Rev.2** (`ssp/generator.py` renders the
110 practices from `ScoringControl`). FR-01 honestly relabeled it and removed the misleading "FedRAMP" picker —
so the product has **no real FedRAMP 800-53r5 SSP capability**, despite "FedRAMP" being in its positioning. This
is the single largest product-value gap. Two foundations now make it buildable:
- The OSCAL reconciliation engine vendors the pinned **NIST 800-53 Rev 5.2.0 catalog + Low/Mod/High 800-53B
  baselines** (`src/ccf/catalog/oscal.py`, `OscalCatalog.baselines`).
- The **boundary & inventory model** (Keystone #1) supplies a real OSCAL `system-implementation`.

## Goal

Add a parallel **800-53r5 SSP generation pipeline**: given a system + FIPS-199 baseline (Low/Mod/High), select the
authoritative 800-53B control set, produce per-control SSP entries (statement, ODP scaffolding, role, status,
origination), and export both an **OSCAL SSP** (implemented-requirements + set-parameters + boundary-backed
system-implementation) and a **FedRAMP-style .docx**.

### Decisions (from brainstorming)

| Decision | Choice |
|---|---|
| Baseline source | **NIST 800-53B** (already vendored) for v1 — a genuine 800-53r5 SSP. FedRAMP Rev5 baseline overlay (added controls + assigned ODP values) is a v2 follow-on. |
| ODPs | **Scaffold from catalog params** — capture parameter definitions; surface each control's ODPs as fillable; flag unset in completeness; emit `set-parameters` for filled values. |
| Output | **OSCAL SSP + FedRAMP-style docx.** Re-enable a real `nist-800-53r5` generation path. |

### Non-goals (v1) — deferred
FedRAMP Rev5 baseline overlay (added controls + FedRAMP-assigned ODP values); control tailoring (add/remove) UI;
by-component control allocation; per-part narrative editing UI; AI-drafted statements (separate slice).

## Key simplification (existing model already fits)

`SSPControlEntry` (table `ssp_control_entries`) ALREADY has: `control_id`, `nist_id`, `domain`, `title`,
`requirement`, `responsible_role`, `implementation_status` (JSONB), `control_origination` (JSONB), `part_narratives`
(JSONB), **`odp_values` (JSONB dict)**, `sort_order`, unique `(project_id, control_id)`. So **no new entry columns
are needed** — the 800-53 pipeline populates these. The only schema change is a `framework` selector on `SSPProject`.

## 1. Extend the OSCAL catalog loader (`src/ccf/catalog/oscal.py`)

- Add `@dataclass OscalParam { id: str; label: str; guidance: str; choices: list[str] }`.
- Add `params: list[OscalParam]` to `OscalControl` (KEEP `param_ids: list[str]` — the reconciler uses it; backward
  compatible). Parse each control `params[]`: `id`; `label` (top-level `label`, fallback to the `sp800-53a` prop
  label); `guidance` (join `guidelines[].prose`); `choices` (from `select.choice[]` when present).
- Existing catalog tests must still pass; add a test asserting `AC-2` yields ≥1 `OscalParam` with a non-empty label.

## 2. Framework selector (`models.py`, migration `0054`)

- `SSPProject` += `framework: Mapped[str] = mapped_column(String(32), default="cmmc-800-171", server_default="cmmc-800-171")`.
  Values: `cmmc-800-171` (today's behavior) | `nist-800-53r5` (new). Migration `0054_ssp_project_framework`
  (`down_revision=0053_user_lockout`) adds the column with a `cmmc-800-171` server default (existing projects keep
  today's behavior). No RLS change (ssp_projects policy unchanged).

## 3. 800-53r5 entry builder (`src/ccf/ssp/nist80053.py`)

- `_family_of(canonical_id) -> str` — the family code (`AC-2` → `AC`).
- `def build_80053_entries(catalog, baseline_level, *, named_roles=None) -> list[dict]` — for each canonical id in
  `catalog.baselines[baseline_level]` where the control is not withdrawn, sorted by family then number/enhancement,
  build an entry dict shaped for `SSPControlEntry`:
  - `control_id` = canonical (`AC-2`); `nist_id` = same; `domain` = family; `title` = OSCAL title;
    `requirement` = OSCAL statement prose.
  - `odp_values` = `{param.id: None}` for each `OscalParam` on the control (scaffold — unset). Carry each param's
    `label`/`guidance` in a sidecar structure the UI/docx can render (either a separate returned `odp_defs` map by
    control, or store defs in `part_narratives`/a lightweight field — v1: return an `odp_defs` dict keyed by
    control_id from the builder so callers can render fill prompts; the entry's `odp_values` holds only id→value).
  - `responsible_role` = `constants.responsible_role_for(family, named_role=named_roles.get(family))`.
  - `implementation_status` = `["planned"]` (draft default — an SSP starts unimplemented and is filled in).
  - `control_origination` = `["system-specific"]` draft default (tailorable).
  - `part_narratives` = a single draft-flagged placeholder narrative referencing the responsible role + baseline
    (a starting point, not a claim). Mark draft so completeness/UI show it needs authoring.
- Pure function over the loaded catalog → unit-testable without a DB.

## 4. Seed wiring (`src/ccf/ssp/seed.py` or a new `seed_80053_project`)

- `async def seed_80053_project(session, project, catalog=None) -> int` — resolve the baseline from the project's
  `System.baseline` (or `System.fips199_*` high-water-mark when baseline is unset; error clearly if neither is set),
  load the catalog (`load_oscal_catalog()`), call `build_80053_entries`, and upsert `SSPControlEntry` rows
  (respecting the `(project_id, control_id)` unique key; do not clobber human-edited entries — insert missing,
  leave existing). Returns the count seeded.
- The generate route (§7) calls this when `project.framework == "nist-800-53r5"`, else the existing
  `seed_project_entries` (CMMC).

## 5. ODP completeness (`src/ccf/ssp/completeness.py`)

- Extend `assess(...)` with an ODP dimension for 800-53 projects: an entry with any `odp_values` value that is None
  contributes an "unset ODP" gap. Surface a count ("N of M ODPs unset") and list the worst offenders. Backward
  compatible (CMMC projects, which use `odp_values` too but were already scored, unaffected — gate the new dimension
  on the presence of scaffolded ODPs / the framework). Keep control-implementation weight dominant.

## 6. OSCAL SSP export (`src/ccf/api/routes/oscal.py`)

- In the `ssp_export` `implemented-requirements` build: for entries whose `control_id` is a canonical 800-53 id,
  emit `control-id` = canonical lowercased dotted OSCAL form (`AC-2(1)` → `ac-2.1`; add a small
  `canonical_to_oscal_id` helper — inverse of the loader's `oscal_id_to_canonical`), the statement(s) from
  `part_narratives`, and **`set-parameters`** = `[{"param-id": pid, "values": [val]} for pid, val in odp_values if val]`.
  `system-implementation` already comes from the boundary summary (Keystone #1). Non-800-53 (CMMC) entries keep
  today's behavior.
- Tests: a seeded 800-53 project exports implemented-requirements with real `ac-2` etc. control-ids and a
  `set-parameters` entry for any filled ODP; OSCAL still validates.

## 7. FedRAMP-style docx (`src/ccf/ssp/nist80053_docx.py`) + generate route/UI

- `def render_80053_docx(project, entries, meta) -> bytes` — parallel to `generate_ssp_docx`: cover/metadata
  (baseline = Low/Mod/High, "NIST SP 800-53 Rev 5"), then per-family sections with one table per control:
  control id + title, the statement, ODP values (from `odp_values`, showing `[unset]` for None), responsible role,
  implementation status, control origination. Reuse the docx helpers in `generator.py` (extract shared helpers if
  clean, else duplicate minimally).
- `src/ccf/api/routes/ssp.py`: the generate/seed endpoints accept `framework` (default the project's, default
  `cmmc-800-171`). When `nist-800-53r5`: seed via `seed_80053_project` and render via `render_80053_docx`. Keep the
  existing role-gating. Re-add a `nist-800-53r5` option in the SSP UI project-create form.

## Testing (TDD; `session_scope()`/`fresh_engine`, no `db_session`; count-sensitive tests TRUNCATE first)

- Loader params (§1), backward-compat with reconciliation.
- `build_80053_entries` (§3): baseline count matches `len(catalog.baselines[level])` minus withdrawn; a known control
  (AC-2) has scaffolded ODPs, family-derived role, canonical id.
- `seed_80053_project` (§4): seeds the right number of `SSPControlEntry` rows for a Moderate system; idempotent
  (re-seed doesn't duplicate or clobber).
- ODP completeness (§5): unset ODPs → gaps; filling them clears the gaps.
- OSCAL export (§6): 800-53 project → `implemented-requirements` with `ac-2` ids + `set-parameters`; validates.
- docx (§7): renders non-empty bytes for a seeded Moderate project; the generate route with `framework=nist-800-53r5`
  returns a docx; role-gated.
- Golden e2e: create a Moderate 800-53r5 project → seed → assert control count == baseline size → export OSCAL
  (real ids + set-parameters + boundary system-implementation) → render docx.

## Rollout
Additive: existing CMMC projects (`framework="cmmc-800-171"` via server default) are unchanged. Migration `0054`
(one column). Rebuild `api`+`migrator` images.

## Success criteria
1. A `nist-800-53r5` project seeds the authoritative 800-53B baseline control set for its FIPS-199 level (tested).
2. ODPs are scaffolded from the catalog and flagged when unset (tested).
3. OSCAL SSP export emits real 800-53 control-ids + set-parameters + boundary-backed system-implementation (tested; validates).
4. A FedRAMP-style 800-53r5 .docx generates (tested).
5. Existing CMMC pipeline unaffected; full suite green; ruff + mypy-strict + bandit clean; single alembic head `0054`.
