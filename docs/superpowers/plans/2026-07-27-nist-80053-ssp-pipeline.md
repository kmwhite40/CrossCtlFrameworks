# NIST 800-53r5 FedRAMP SSP Pipeline Implementation Plan (Keystone #2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** A parallel 800-53r5 SSP generation pipeline — select the 800-53B baseline control set, produce per-control SSP entries with ODP scaffolding, and export an OSCAL SSP (implemented-requirements + set-parameters + boundary-backed system-implementation) and a FedRAMP-style .docx — without disturbing the existing CMMC pipeline.

**Architecture:** Extend the OSCAL loader with parameter definitions; add a `framework` selector to `SSPProject`; a pure `build_80053_entries` over the catalog; a `seed_80053_project` that upserts `SSPControlEntry` rows; an ODP completeness dimension; OSCAL export set-parameters; a FedRAMP-style docx renderer; and a `framework=nist-800-53r5` generate path.

**Tech Stack:** Python 3.12, async SQLAlchemy/asyncpg, Alembic, python-docx, FastAPI, pytest.

**Spec:** `docs/superpowers/specs/2026-07-27-nist-80053-ssp-pipeline-design.md` (authoritative).

## Global Constraints

- **Existing CMMC pipeline unaffected:** `SSPProject.framework` defaults to `cmmc-800-171` (server default); all current behavior is the default path. Non-800-53 entries keep today's OSCAL/docx behavior.
- **`SSPControlEntry` needs NO new columns** — reuse `control_id`, `nist_id`, `domain`, `title`, `requirement`, `responsible_role`, `implementation_status`, `control_origination`, `part_narratives`, `odp_values`. Only new schema is `SSPProject.framework`.
- **Canonical ids:** entries store the canonical form (`AC-2`, `AC-2(1)`); OSCAL export converts to OSCAL dotted lower (`ac-2`, `ac-2.1`).
- **Loader backward-compat:** keep `OscalControl.param_ids` (the reconciler uses it); add `params` alongside.
- **Test harness:** `PYTHONPATH=src`, `CCF_DATABASE_URL[_SYNC]=...localhost:5433/ccf_test`; no `db_session` fixture — `session_scope()` + `fresh_engine`, DB tests copy `_migrate` from `test_ato.py`; count-sensitive tests `TRUNCATE ... CASCADE` first. Style: ruff + mypy-strict + bandit clean; line-length 100; no function-level imports. **Stage only your own files (never `git add -A`).** Commit on branch `feat/nist-80053-ssp`.

---

### Task 1: OSCAL loader — capture parameter (ODP) definitions

**Files:** Modify `src/ccf/catalog/oscal.py`; Test: `tests/test_catalog_params.py`.

**Interfaces (produced):** `@dataclass(frozen=True) class OscalParam: id: str; label: str; guidance: str; choices: list[str]`; `OscalControl.params: list[OscalParam]` (new field; `param_ids` retained).

- [ ] **Step 1: failing tests** — `load_oscal_catalog().get("AC-2").params` is non-empty; the first param has a non-empty `id` and `label`; a control's `param_ids` still equals the ids (backward compat).
```python
def test_ac2_has_odp_params():
    cat = load_oscal_catalog()
    ac2 = cat.get("AC-2")
    assert ac2.params and ac2.params[0].id.startswith("ac-2")
    assert ac2.params[0].label  # non-empty label
    assert [p.id for p in ac2.params] == ac2.param_ids  # param_ids preserved
```
- [ ] **Step 2: implement** — add `OscalParam`, add `params` to `OscalControl`, and in `_parse_control` build it:
```python
def _parse_param(p: dict[str, Any]) -> OscalParam:
    label = p.get("label", "")
    if not label:
        for prop in p.get("props", []):
            if prop.get("name") == "label":
                label = prop.get("value", "")
                break
    guidance = "\n".join(g["prose"] for g in p.get("guidelines", []) if g.get("prose"))
    choices = [c for c in (p.get("select", {}) or {}).get("choice", []) if isinstance(c, str)]
    return OscalParam(id=p.get("id", ""), label=label, guidance=guidance, choices=choices)
```
  In `_parse_control`, set `params=[_parse_param(p) for p in c.get("params", [])]` and keep `param_ids=[p["id"] for p in c.get("params", []) if p.get("id")]`.
- [ ] **Step 3-4:** Run `tests/test_catalog_params.py` + `tests/test_catalog_oscal.py` (regression). ruff/mypy clean. **Commit:** `feat(catalog): capture OSCAL parameter (ODP) definitions on controls`.

---

### Task 2: `SSPProject.framework` + migration 0054

**Files:** Modify `src/ccf/models.py`; Create `migrations/versions/0054_ssp_project_framework.py`; Test: `tests/test_ssp_framework_field.py`.

- [ ] **Step 1: model** — add to `SSPProject`: `framework: Mapped[str] = mapped_column(String(32), default="cmmc-800-171", server_default="cmmc-800-171")`.
- [ ] **Step 2: migration** `0054_ssp_project_framework.py` (`down_revision="0053_user_lockout"`):
```python
def upgrade():
    op.add_column("ssp_projects", sa.Column("framework", sa.String(32), server_default="cmmc-800-171", nullable=False), schema="ccf")
def downgrade():
    op.drop_column("ssp_projects", "framework", schema="ccf")
```
  Run `alembic upgrade head`; confirm single head `0054_ssp_project_framework`.
- [ ] **Step 3: test** — create an `SSPProject` without specifying framework → `framework == "cmmc-800-171"`; create with `framework="nist-800-53r5"` → persists. (session_scope + _migrate).
- [ ] **Step 4:** Run test + `tests/test_scoring_ssp.py` (regression). ruff/mypy clean. **Commit:** `feat(ssp): framework selector on SSPProject + migration 0054`.

---

### Task 3: 800-53r5 entry builder

**Files:** Create `src/ccf/ssp/nist80053.py`; Test: `tests/test_nist80053_entries.py`.

**Interfaces (produced):**
- `def family_of(canonical_id: str) -> str` — `"AC-2(1)" -> "AC"`.
- `def build_80053_entries(catalog, baseline_level: str, *, named_roles: dict[str,str] | None = None) -> tuple[list[dict], dict[str, list[dict]]]` — returns `(entries, odp_defs_by_control)`. Each entry dict has keys matching `SSPControlEntry` columns: `control_id, nist_id, domain, title, requirement, responsible_role, implementation_status (list), control_origination (list), part_narratives (list), odp_values (dict), sort_order (int)`. `odp_defs_by_control[control_id]` = `[{"id","label","guidance","choices"}]` for rendering fill prompts.

- [ ] **Step 1: failing tests** (uses the real catalog):
```python
def test_moderate_baseline_entry_count_and_shape():
    cat = load_oscal_catalog()
    entries, odp_defs = build_80053_entries(cat, "moderate")
    expected = {cid for cid in cat.baselines["moderate"] if not (cat.get(cid) and cat.get(cid).withdrawn)}
    assert {e["control_id"] for e in entries} == expected
    ac2 = next(e for e in entries if e["control_id"] == "AC-2")
    assert ac2["domain"] == "AC"
    assert ac2["responsible_role"]                       # family-derived, non-empty
    assert ac2["odp_values"] and all(v is None for v in ac2["odp_values"].values())  # scaffolded unset
    assert odp_defs["AC-2"] and odp_defs["AC-2"][0]["label"]

def test_family_of():
    assert family_of("AC-2(1)") == "AC" and family_of("SC-7") == "SC"
```
- [ ] **Step 2: implement** — select `catalog.baselines[baseline_level]`, skip withdrawn, sort deterministically (family, then number, then enhancement tuple — reuse `canonicalize` from `ccf.catalog.canonical` to parse), and build each entry:
  - `domain = family_of(cid)`; `responsible_role = constants.responsible_role_for(domain, named_role=(named_roles or {}).get(domain))`;
  - `odp_values = {p.id: None for p in oc.params}`; `odp_defs[cid] = [{"id":p.id,"label":p.label,"guidance":p.guidance,"choices":p.choices} for p in oc.params]`;
  - `implementation_status = ["planned"]`; `control_origination = ["system-specific"]`;
  - `part_narratives = [{"label":"", "text": f"[DRAFT] {domain} control {cid} is implemented by {role}. Describe the implementation.", "draft": True}]`;
  - `sort_order` = running index.
  Import `constants` from `.` (the ssp package) and `load_oscal_catalog`/`canonicalize` from `ccf.catalog`.
- [ ] **Step 3-4:** Run test. ruff/mypy clean. **Commit:** `feat(ssp): 800-53r5 baseline entry builder with ODP scaffolding`.

---

### Task 4: `seed_80053_project` wiring

**Files:** Modify `src/ccf/ssp/seed.py` (add `seed_80053_project`); Test: `tests/test_nist80053_seed.py`.

**Interfaces:** `async def seed_80053_project(session, project, *, catalog=None) -> int` — resolve the baseline from `System.baseline` (fallback: FIPS-199 high-water-mark of `System.fips199_*`; raise `ValueError` if neither set), load the catalog if not passed, call `build_80053_entries`, and UPSERT `SSPControlEntry` rows by `(project_id, control_id)` — insert missing, leave existing rows untouched. Store `odp_defs` where useful (e.g. into each entry's `part_narratives` sidecar or leave to the docx/UI to recompute from the catalog — v1: recompute in the renderer; the entry stores only `odp_values`). Return the number of rows inserted.

- [ ] **Step 1: failing tests** — a Moderate system + `nist-800-53r5` project → `seed_80053_project` inserts `len(moderate baseline minus withdrawn)` `SSPControlEntry` rows with canonical `control_id`s; a second call inserts 0 (idempotent) and doesn't duplicate; a project whose system has no baseline nor FIPS triad → `ValueError`. (TRUNCATE `ssp_control_entries` CASCADE first for the count.)
- [ ] **Step 2: implement.** Resolve baseline: `level = (system.baseline or _fips_high_water(system))`; map `low|moderate|high`. Query existing entry `control_id`s for the project; insert only new ones (`SSPControlEntry(project_id=project.id, **entry)`), skipping keys the model doesn't have. `await session.flush()`.
- [ ] **Step 3-4:** Run test. ruff/mypy clean. **Commit:** `feat(ssp): seed 800-53r5 project entries from the baseline`.

---

### Task 5: ODP completeness dimension

**Files:** Modify `src/ccf/ssp/completeness.py`; Test: `tests/test_nist80053_completeness.py`.

- [ ] **Step 1: failing tests** — `assess(meta, entries, ...)` where entries carry scaffolded `odp_values` with `None` values reports an ODP gap and a count; filling all ODP values clears the ODP gap. Existing `tests/test_ssp_completeness.py` still passes unchanged (backward compat).
- [ ] **Step 2: implement** — add an ODP sub-check: across entries, count `odp_values` entries whose value is None (`unset`) vs total; if any unset, add a gap "N of M ODPs unset (organization-defined parameters need values)". Fold into the section score modestly (keep control-implementation weight dominant); gate so projects without any scaffolded ODPs are unaffected. Read the current `assess` signature/structure (it may already take `boundary=` from Keystone #1 — thread ODPs similarly, e.g. compute from the passed `entries` directly since each entry has `odp_values`).
- [ ] **Step 3-4:** Run test + `tests/test_ssp_completeness.py` + `tests/test_boundary_completeness.py` (regression). ruff/mypy clean. **Commit:** `feat(ssp): ODP completeness dimension for 800-53r5 SSPs`.

---

### Task 6: OSCAL SSP export — set-parameters + canonical control-ids

**Files:** Modify `src/ccf/api/routes/oscal.py` (+ a `canonical_to_oscal_id` helper, likely in `src/ccf/catalog/canonical.py`); Test: `tests/test_nist80053_oscal.py`.

**Interfaces:** `def canonical_to_oscal_id(canonical: str) -> str` in `ccf.catalog.canonical` — `"AC-2" -> "ac-2"`, `"AC-2(1)" -> "ac-2.1"`, `"AC-2(1)(2)" -> "ac-2.1.2"` (inverse of `oscal_id_to_canonical`).

- [ ] **Step 1: failing tests** — a seeded 800-53 project (Moderate, at least one entry with a filled `odp_values` value) exported via the SSP OSCAL route produces `implemented-requirements` containing `control-id == "ac-2"` and, for the filled entry, a `set-parameters` list `[{"param-id": ..., "values": [...]}]`. Unfilled ODPs produce no set-parameter. OSCAL still validates (reuse the validation helper from `tests/test_oscal_validation.py`). Also test `canonical_to_oscal_id` directly.
- [ ] **Step 2: implement** — add `canonical_to_oscal_id`. In `ssp_export`'s `implemented-requirements` build: detect canonical 800-53 entries (e.g. the entry's `control_id` canonicalizes and exists in the catalog, OR the project `framework == "nist-800-53r5"` — the export has the project, use it); set `control-id = canonical_to_oscal_id(entry.control_id)`; add `set-parameters = [{"param-id": pid, "values": [v]} for pid, v in (entry.odp_values or {}).items() if v]`; statements from `part_narratives` (existing pattern). Leave CMMC entries on their current path.
- [ ] **Step 3-4:** Run test + `tests/test_oscal_validation.py` + `tests/test_boundary_oscal.py` (regression). ruff/mypy clean. **Commit:** `feat(oscal): 800-53r5 SSP implemented-requirements with set-parameters`.

---

### Task 7: FedRAMP-style docx + generate route/UI

**Files:** Create `src/ccf/ssp/nist80053_docx.py`; Modify `src/ccf/api/routes/ssp.py` and the SSP UI project-create template; Test: `tests/test_nist80053_docx.py`.

- [ ] **Step 1: docx renderer** `def render_80053_docx(project, entries, meta) -> bytes` — parallel to `generate_ssp_docx` (read `src/ccf/ssp/generator.py` for the docx helper patterns: `_shade`, `_runs`, `_cover`, `_add_control`). Produce: a cover ("System Security Plan — NIST SP 800-53 Rev 5", baseline label from `project`/system), then controls grouped by family, one block per control with title, statement (`part_narratives`), ODP values (from `odp_values`, `[unset]` when None), responsible role, implementation status, control origination. Extract shared docx helpers into a small module if clean; otherwise duplicate minimally. Return `bytes` (save to a `BytesIO`).
- [ ] **Step 2: route** — in `src/ccf/api/routes/ssp.py`, the create/seed/generate endpoints accept `framework` (default the project's or `cmmc-800-171`). When `nist-800-53r5`: on seed call `seed_80053_project`; on generate render via `render_80053_docx`. Keep role-gating and the existing CMMC path intact. Add a `framework` option to the project-create request model + the UI project-create form (a select: "CMMC L2 / 800-171" | "FedRAMP / NIST 800-53r5").
- [ ] **Step 3: failing tests** — `render_80053_docx` returns non-empty bytes for a seeded Moderate project and the bytes start with the docx zip signature `PK`; the generate route with `framework=nist-800-53r5` for a seeded project returns 200 + a docx content-type; role-gated (non-authorized → 403). Mirror existing SSP route tests (`tests/test_scoring_ssp.py` / how the CMMC generate route is tested) for auth + invocation.
- [ ] **Step 4:** Run test + `tests/test_scoring_ssp.py` (CMMC regression). ruff/mypy clean. **Commit:** `feat(ssp): FedRAMP-style 800-53r5 docx + nist-800-53r5 generate path`.

---

### Task 8: Golden e2e + full-suite verification

**Files:** Test: `tests/test_nist80053_golden.py`.

- [ ] **Step 1: golden test** — TRUNCATE `ssp_control_entries, ssp_projects` CASCADE; create Organization + System (`baseline="moderate"`) + a boundary (2 components, 1 info type, from `ccf.boundary.service`) + a `SSPProject(framework="nist-800-53r5", system_id=...)`; `seed_80053_project`; then assert end-to-end:
  - entry count == moderate baseline size (minus withdrawn);
  - fill one entry's ODP value; export the SSP OSCAL and assert `implemented-requirements` has `ac-2` ids, a `set-parameters` for the filled ODP, and `system-implementation.components` from the boundary;
  - `render_80053_docx` returns `PK`-prefixed bytes;
  - completeness reports unset-ODP gaps.
- [ ] **Step 2: full boundary+ssp+oscal regression sweep:**
```bash
PYTHONPATH=src pytest tests/test_catalog_params.py tests/test_ssp_framework_field.py \
  tests/test_nist80053_entries.py tests/test_nist80053_seed.py tests/test_nist80053_completeness.py \
  tests/test_nist80053_oscal.py tests/test_nist80053_docx.py tests/test_nist80053_golden.py \
  tests/test_oscal_validation.py tests/test_ssp_completeness.py tests/test_scoring_ssp.py \
  tests/test_catalog_oscal.py -q
```
- [ ] **Step 3: commit** `test(ssp): golden e2e 800-53r5 seed→OSCAL→docx→completeness`.

---

## Final verification (after all tasks)
- [ ] `ruff check .` + `mypy src` + `bandit -r src -ll -x tests` clean.
- [ ] Full suite green (`pytest -q`; baseline 672 + new).
- [ ] `alembic heads` → single `0054`; rebuild `docker compose build api migrator`.
- [ ] Manual: create a Moderate `nist-800-53r5` project, generate → real 800-53 SSP docx + OSCAL with set-parameters.

## Self-Review
**Spec coverage:** loader params ✔(T1); framework+migration ✔(T2); entry builder ✔(T3); seed ✔(T4); ODP completeness ✔(T5); OSCAL set-parameters ✔(T6); docx+route ✔(T7); golden ✔(T8). **Placeholders:** code given for the non-obvious pieces (param parse, canonical_to_oscal_id, entry build); field lists reference the existing `SSPControlEntry` model. **Type consistency:** `OscalParam`/`params` T1→T3→T7; `build_80053_entries` returns `(entries, odp_defs)` T3→T4→T8; `canonical_to_oscal_id` T6 used in export; `seed_80053_project` T4→T7→T8; entries always store canonical `control_id`, OSCAL converts on export.
