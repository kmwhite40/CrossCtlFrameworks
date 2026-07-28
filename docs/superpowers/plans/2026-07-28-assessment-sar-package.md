# Assessment SAR + Authorization-Package Bundle Implementation Plan (Keystone #3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Add an OSCAL Assessment-Results (SAR) export and a single authorization-package ZIP (SSP + SAR + POA&M + component-definition), reusing existing models — closing the authorization lifecycle to a deliverable.

**Architecture:** Extract the existing SSP/POA&M/component-def route bodies into reusable `build_*_doc(session, entity)` functions; add a `build_sar_doc` + `/oscal/sar/...` routes; add a `build_package_zip` + `/oscal/package/{system_id}` route. Read-only, no migration.

**Tech Stack:** Python 3.12, FastAPI, async SQLAlchemy, `zipfile`/`io.BytesIO`, pytest.

**Spec:** `docs/superpowers/specs/2026-07-28-assessment-sar-package-design.md` (authoritative).

## Global Constraints

- **Refactor is behavior-preserving:** extracting builders must leave existing OSCAL export output byte-identical; `tests/test_oscal_validation.py` + SSP/POA&M/boundary OSCAL tests pass UNCHANGED.
- **Scoping/auth:** every new route mirrors the existing export routes — `principal: Principal = Depends(get_principal)`, resolve the entity, 404 when it's outside `principal.org_id`. No new auth pattern.
- **Never fabricate:** the SAR's `import-ap` is an honest placeholder href with a remark (no SAP generated); the package README notes any missing artifact (no SSP / no assessment) rather than inventing one.
- **Determinism:** do NOT call `datetime.now()`/`uuid4` at import; generate timestamps inside handlers (existing code already does `datetime.now(UTC)` in-handler — follow that). Pass the timestamp into `build_package_zip`.
- **Validation:** SAR must pass `validate_document(doc, "assessment-results")`; the schema is already registered in `src/ccf/oscal/validation.py`.
- **Test harness:** `PYTHONPATH=src`, `CCF_DATABASE_URL[_SYNC]=...localhost:5433/ccf_test`; no `db_session` fixture — `session_scope()` + `fresh_engine`, DB tests copy `_migrate` from `test_ato.py`. Style: ruff + mypy-strict + bandit clean; line-length 100; no function-level imports. **Stage only your own files (never `git add -A`).** Commit on branch `feat/assessment-sar-package`.

---

### Task 1: Extract OSCAL doc builders (behavior-preserving refactor)

**Files:** Modify `src/ccf/api/routes/oscal.py`; Test: `tests/test_oscal_builders.py`.

**Interfaces (produced):**
- `async def build_ssp_doc(session, proj: SSPProject) -> dict[str, Any]` — the body of `ssp_export` after the 404 check.
- `async def build_poam_doc(session, sys: System, *, open_only: bool = True) -> dict[str, Any]` — body of `poam_export`.
- `async def build_component_definition_doc(session, sys: System) -> dict[str, Any]` — body of `component_definition`.

- [ ] **Step 1:** Read the three route handlers (`component_definition` ~274, `ssp_export` ~348, `poam_export` ~476). For EACH: move everything after the entity-resolution + 404 check into a new `build_*_doc(session, entity, ...)` function that returns the dict; make the route handler resolve+scope the entity, then `return await build_*_doc(session, entity)`. Keep the exact same computation (do not "improve" anything) so output is identical. `poam_export` has an `open_only`/status filter — thread it as a keyword arg defaulting to today's behavior.
- [ ] **Step 2: Write a characterization test** `tests/test_oscal_builders.py` — create a minimal System + SSPProject; call `build_ssp_doc(session, proj)` and `build_poam_doc(session, sys)` directly and assert they return dicts with the expected top-level OSCAL keys (`system-security-plan`, `plan-of-action-and-milestones`). (The byte-identical guarantee is covered by the unchanged `tests/test_oscal_validation.py` regression.)
- [ ] **Step 3: Run** `tests/test_oscal_builders.py` + `tests/test_oscal_validation.py` + `tests/test_boundary_oscal.py` + `tests/test_nist80053_oscal.py` — ALL must pass unchanged. ruff/mypy clean. **Commit:** `refactor(oscal): extract build_ssp_doc/build_poam_doc/build_component_definition_doc`.

---

### Task 2: SAR builder + routes + validation

**Files:** Modify `src/ccf/api/routes/oscal.py`; Test: `tests/test_oscal_sar.py`.

**Interfaces:** `async def build_sar_doc(session, assessment: Assessment) -> dict[str, Any]`; routes `GET /oscal/sar/{assessment_id}` and `GET /oscal/sar/system/{system_id}`.

- [ ] **Step 1: Write failing tests** `tests/test_oscal_sar.py` (mirror `tests/test_ato.py` DB setup + how `test_oscal_validation.py` hits routes). Build:
  - Organization + System + 3 `ControlImplementation` rows (control ids e.g. "AC-2", "AU-2", "SC-7") + an `Assessment(kind="internal", assessor="Jane 3PAO", started_on=..., finished_on=...)` + 3 `AssessmentResult` rows (one `satisfied`, one `other_than_satisfied`, one `not_applicable`, each `implementation_id` → one of the impls) + an `EvidenceObject(implementation_id=<the satisfied impl>, title="AC-2 screenshot", ...)` + an open `POAM(system_id=..., title=...)`.
  - `GET /oscal/sar/{assessment_id}` → assert: doc has `assessment-results`; a result with `reviewed-controls`; a `findings` entry with `target.status.state == "satisfied"`, one with `"not-satisfied"`, and the N/A finding carrying a prop `{"name":"applicability","value":"not-applicable"}`; an `observations` entry sourced from the evidence with a `methods` list; a `risks` entry from the POA&M; and `validate_document(doc, "assessment-results").ok` is True (import the helper or add an assertion via the route if it validates internally).
  - `GET /oscal/sar/system/{system_id}` → returns the latest finished assessment's SAR; 404 when the system has none.
  - Unauthorized/out-of-org → 404.
- [ ] **Step 2: Implement `build_sar_doc`** per spec §2. Key mappings:
  - Load results with their implementation+control: `select(AssessmentResult).where(AssessmentResult.assessment_id == assessment.id).options(selectinload(AssessmentResult.implementation).selectinload(ControlImplementation.control))`.
  - `oscal_cid(impl)` = the control identifier lowercased; if it canonicalizes (`from ...catalog.canonical import canonicalize, canonical_to_oscal_id`), use `canonical_to_oscal_id`.
  - Status map: `{"satisfied":"satisfied","other_than_satisfied":"not-satisfied","not_applicable":"not-satisfied"}`; for `not_applicable` add `props:[{"name":"applicability","value":"not-applicable"}]` on the finding.
  - Observations: load `EvidenceObject` for the assessment's implementation ids (`implementation_id in {...}`); each → `{"uuid":..., "title":..., "description":..., "methods":["EXAMINE"], "relevant-evidence":[{"href": f"#evidence-{e.id}", "description": e.title}]}`. Map `implementation_id -> [observation uuid]` for finding `related-observations`.
  - Risks: reuse `build_poam_doc`'s POA&M resolution (or a light query of open POAMs for `assessment.system_id`) → `{"uuid":..., "title":..., "description":..., "status":"open", "statement": ...}` shaped per the OSCAL `risk` schema (check the assessment-results schema for required risk fields — at minimum uuid/title/description/status/statement; if `deadline`/`related-observations` are optional, omit).
  - `import-ap`: `{"href": "#no-assessment-plan", "remarks": "No OSCAL assessment plan (SAP) generated in this release; results reported directly."}`.
  - metadata: title, `last-modified`=now iso, `version`, `oscal-version` (match what the other exports use — grep for `"oscal-version"` in the file), a party for the assessor with role `assessor`.
  - Return the full `{"assessment-results": {...}}`. Run it through `validate_document(doc, "assessment-results")` inside the route and, if `not report.ok`, still return the doc but ALSO — no: the route should return the doc; the TEST asserts validity. Do NOT swallow validation. (If you want a safety net, add a `?validate=1` that 422s on invalid — optional.)
- [ ] **Step 3: Routes** — `GET /oscal/sar/{assessment_id}`: resolve `Assessment`, scope via its `System.organization_id` vs `principal.org_id` (join or a second query), 404 otherwise, `return await build_sar_doc(session, assessment)`. `GET /oscal/sar/system/{system_id}`: resolve the system (scoped), pick `select(Assessment).where(system_id==...).order_by(Assessment.finished_on.desc().nullslast(), Assessment.id.desc()).limit(1)`, 404 if none.
- [ ] **Step 4:** Run `tests/test_oscal_sar.py`. ruff/mypy clean. **Commit:** `feat(oscal): assessment-results (SAR) export + routes`.

---

### Task 3: Authorization-package bundle

**Files:** Modify `src/ccf/api/routes/oscal.py` (import `zipfile`, `io`, `StreamingResponse`); Test: `tests/test_oscal_package.py`.

**Interfaces:** `async def build_package_zip(session, sys: System, *, now_iso: str) -> bytes`; route `GET /oscal/package/{system_id}`.

- [ ] **Step 1: Write failing tests** `tests/test_oscal_package.py` — a System with an SSPProject + an Assessment (+ optionally boundary/POA&M). `GET /oscal/package/{system_id}` → status 200, `content-type: application/zip`, body starts with `b"PK"`. Unzip (`zipfile.ZipFile(io.BytesIO(resp.content))`) and assert `namelist()` contains `ssp.json`, `sar.json`, `poam.json`, `component-definition.json`, `README.txt`; `json.loads` each JSON and assert `validate_document(...).ok` per doc (ssp / assessment-results / plan-of-action-and-milestones / component-definition). A second test: a System with NO SSPProject and NO assessment still returns a zip containing `poam.json`, `component-definition.json`, `README.txt` (and the README notes SSP/SAR absent). Role-gated (unauthorized → 404).
- [ ] **Step 2: Implement `build_package_zip`**:
  - Resolve the system's SSP project: `select(SSPProject).where(system_id==sys.id).order_by(SSPProject.id.desc()).limit(1)`. If present → `ssp.json` = `build_ssp_doc(session, proj)`.
  - Resolve the latest finished assessment (as in Task 2) → `sar.json` = `build_sar_doc(session, assessment)`.
  - Always: `poam.json` = `build_poam_doc(session, sys)`, `component-definition.json` = `build_component_definition_doc(session, sys)`.
  - `README.txt` — a manifest listing system name, `now_iso`, which artifacts are present, and a note. Include an explicit line for any absent artifact.
  - Write into a `zipfile.ZipFile(BytesIO(), "w", ZIP_DEFLATED)`; `writestr(name, json.dumps(doc, indent=2))`. Return `buf.getvalue()`.
- [ ] **Step 3: Route** `GET /oscal/package/{system_id}` — scope+auth like other export routes; `now_iso = datetime.now(UTC).isoformat()`; `data = await build_package_zip(session, sys, now_iso=now_iso)`; `return StreamingResponse(io.BytesIO(data), media_type="application/zip", headers={"content-disposition": f'attachment; filename="authorization-package-{system_id}.zip"'})`.
- [ ] **Step 4:** Run `tests/test_oscal_package.py`. ruff/mypy/bandit clean (bandit: zipfile is fine; ensure no `writestr` of untrusted paths). **Commit:** `feat(oscal): authorization-package ZIP bundle (SSP+SAR+POA&M+component-def)`.

---

### Task 4: Golden e2e + full-suite verification

**Files:** Test: `tests/test_oscal_package_golden.py`.

- [ ] **Step 1: Golden test** — build a fully-populated system: Organization + System(baseline="moderate") + an `SSPProject(framework="nist-800-53r5")` seeded via `seed_80053_project` + a boundary (2 components via `ccf.boundary.service`) + ControlImplementations + an Assessment with AssessmentResults + an EvidenceObject + an open POA&M. Then:
  - `GET /oscal/sar/{assessment_id}` → validates as assessment-results, has ≥1 finding + ≥1 observation + ≥1 risk.
  - `GET /oscal/package/{system_id}` → zip with all 5 members; each of the 4 JSON docs validates against its schema; the SSP's system-implementation has the boundary components (Keystone #1 composition); the SSP has 800-53 `ac-2` control-ids (Keystone #2 composition).
- [ ] **Step 2: Full pipeline + regression sweep:**
```bash
PYTHONPATH=src pytest tests/test_oscal_builders.py tests/test_oscal_sar.py tests/test_oscal_package.py \
  tests/test_oscal_package_golden.py tests/test_oscal_validation.py tests/test_boundary_oscal.py \
  tests/test_nist80053_oscal.py -q
```
- [ ] **Step 3: Commit** `test(oscal): golden e2e SAR + authorization package bundle`.

---

## Final verification (after all tasks)
- [ ] `ruff check .` + `mypy src` + `bandit -r src -ll -x tests` clean.
- [ ] Full suite green (`pytest -q`; baseline 699 + new).
- [ ] Manual: `GET /oscal/package/{id}` downloads a zip; unzip → four OSCAL JSONs + README, each validating.

## Self-Review
**Spec coverage:** builder refactor ✔(T1); SAR export + routes + validation ✔(T2); package ZIP ✔(T3); golden ✔(T4). **Placeholders:** honest `import-ap` placeholder + README gap-notes are explicit, not TODOs; code given for the non-obvious mappings (status, observations, risks). **Type consistency:** `build_ssp_doc`/`build_poam_doc`/`build_component_definition_doc` (T1) reused by `build_package_zip` (T3); `build_sar_doc` (T2) reused by the package (T3) and golden (T4); all return `dict[str, Any]`; N/A encoded as a prop (finding status state is only satisfied/not-satisfied). No migration — read-only over existing models.
