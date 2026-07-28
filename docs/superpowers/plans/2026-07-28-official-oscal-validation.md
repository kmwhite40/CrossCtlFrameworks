# Official OSCAL Schema Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Vendor the pinned NIST OSCAL v1.1.2 schemas, make `validate_document` run REAL official-schema validation by default via a small adapter, gate it in CI, and fix the conformance gaps the schemas surface in the SSP/SAR/POA&M/component-definition exports.

**Architecture:** In-package schemas + a validation adapter (`validator_for` auto-detects OSCAL's draft-07 and resolves `#anchor` refs; translate ECMA `\p{...}` patterns so Python `re` compiles them) + default schema-dir resolution + per-export conformance fixes + a CI require-official gate.

**Tech Stack:** Python 3.12, `jsonschema` (core dep), FastAPI, pytest.

**Spec:** `docs/superpowers/specs/2026-07-28-official-oscal-validation-design.md` (authoritative). A feasibility spike already proved the adapter works and surfaced real SSP gaps.

## Global Constraints

- **Sequencing / intermediate red:** Task 1 turns official validation ON by default (packaged schemas auto-resolve). That will make export tests for still-non-conformant docs FAIL until their conformance task lands. So through Tasks 2-4, the gate for each task is that task's OWN export test (validating official), NOT the full suite. The full suite is only required green at Task 5. Do not "fix" a red unrelated export test by weakening it — its conformance is fixed in its own task.
- **Adapter must not crash:** `\p{L}`/`\p{N}` patterns crash Python `re` (`bad escape \p`); the adapter MUST translate them. Never hardcode `Draft202012Validator` — use `jsonschema.validators.validator_for(schema)`.
- **Never fabricate** to pass schema validation: fill genuinely-derivable fields; use honest `remarks` placeholders where data is absent (as the existing exports already do), not invented values.
- **Pinned + provenance:** vendored schemas carry a `MANIFEST.json` (version 1.1.2, source URL, per-file sha256).
- **Test harness:** `PYTHONPATH=src`, `CCF_DATABASE_URL[_SYNC]=...localhost:5433/ccf_test`; no `db_session` fixture. Style: ruff + mypy-strict + bandit clean; line-length 100; no function-level imports (the existing `import jsonschema` inside `_validate_against_schema` already carries `# noqa: PLC0415` — keep that pattern). **Stage only your own files (never `git add -A`).** Commit on branch `feat/official-oscal-validation`.

---

### Task 1: Vendor schemas + validation adapter + default resolution

**Files:** Create `src/ccf/oscal/schemas/*.json` (downloaded) + `MANIFEST.json`; Modify `src/ccf/oscal/validation.py`, `pyproject.toml`; Test: `tests/test_oscal_schema_adapter.py`.

- [ ] **Step 1: Vendor the schemas.** Download the OSCAL v1.1.2 release assets into `src/ccf/oscal/schemas/`:
```bash
mkdir -p src/ccf/oscal/schemas
B="https://github.com/usnistgov/OSCAL/releases/download/v1.1.2"
for f in oscal_complete_schema.json oscal_ssp_schema.json oscal_component_schema.json \
         oscal_poam_schema.json oscal_assessment-results_schema.json; do
  curl -sSL --max-time 60 "$B/$f" -o "src/ccf/oscal/schemas/$f"
done
PYTHONPATH=src python - <<'PY'
import hashlib, json, datetime
from pathlib import Path
d = Path("src/ccf/oscal/schemas")
files = sorted(p.name for p in d.glob("*.json") if p.name != "MANIFEST.json")
(d / "MANIFEST.json").write_text(json.dumps({
    "oscal_version": "1.1.2",
    "source_url": "https://github.com/usnistgov/OSCAL/releases/tag/v1.1.2",
    "retrieved_at": datetime.date.today().isoformat(),
    "files": {f: hashlib.sha256((d / f).read_bytes()).hexdigest() for f in files},
}, indent=2) + "\n")
print("manifest written", files)
PY
```
- [ ] **Step 2: package-data** — add to `pyproject.toml` `[tool.setuptools.package-data]`: `"ccf.oscal" = ["schemas/*.json"]`.
- [ ] **Step 3: Write failing adapter tests** `tests/test_oscal_schema_adapter.py` (no DB):
```python
from ccf.oscal.validation import _translate_ecma_pattern, official_schema_path, validate_document


def test_translate_ecma_pattern():
    out = _translate_ecma_pattern(r"^(\p{L}|_)(\p{L}|\p{N}|[.\-_])*$")
    assert r"\p{" not in out
    import re
    re.compile(out)  # must compile under Python re


def test_official_schema_resolves_from_package_by_default(monkeypatch):
    # No CCF_OSCAL_SCHEMA_DIR set -> resolves the in-package schemas dir.
    from ccf.config import get_settings
    get_settings.cache_clear()
    p = official_schema_path("ssp")
    assert p is not None and p.name.endswith(".json")


def test_token_populated_ssp_does_not_crash_and_runs_official():
    doc = {"system-security-plan": {
        "uuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "metadata": {"title": "t", "last-modified": "2026-01-01T00:00:00Z", "version": "1",
                     "oscal-version": "1.1.2", "props": [{"name": "x", "value": "y"}]},
    }}
    report = validate_document(doc)  # must NOT raise (the \p regex bug)
    assert report.mode == "official"      # packaged schema resolved
    assert not report.ok                  # this partial doc is genuinely invalid
    assert report.errors
```
- [ ] **Step 4: Implement** in `src/ccf/oscal/validation.py`:
  - `def _translate_ecma_pattern(pattern: str) -> str` — replace `\p{Lu}`→`[A-Z]`, `\p{Ll}`→`[a-z]`, `\p{L}`→`[^\W\d_]`, `\p{Nd}`→`[0-9]`, `\p{N}`→`[0-9]` (apply the two-letter classes BEFORE `\p{L}`/`\p{N}` so they aren't partially replaced). Idempotent, pure.
  - In `official_schema_path`, when `get_settings().oscal_schema_dir` is None, fall back to `Path(__file__).with_name("schemas")` before the "not found" return, so the packaged dir resolves by default.
  - Rewrite `_validate_against_schema(doc, schema_path)`:
    ```python
    _ADAPTED_CACHE: dict[str, Any] = {}
    def _load_adapted_schema(schema_path):
        key = str(schema_path)
        if key not in _ADAPTED_CACHE:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            _walk_translate_patterns(schema)   # recursively _translate_ecma_pattern every "pattern"
            _ADAPTED_CACHE[key] = schema
        return _ADAPTED_CACHE[key]

    def _validate_against_schema(doc, schema_path):
        import jsonschema  # noqa: PLC0415
        from jsonschema.validators import validator_for  # noqa: PLC0415
        schema = _load_adapted_schema(schema_path)
        validator = validator_for(schema)(schema)
        return sorted(e.message for e in validator.iter_errors(doc))[:50]
    ```
    Add `_walk_translate_patterns(node)` recursing dicts/lists, translating any `str` `pattern` value in place.
- [ ] **Step 5: Run** `tests/test_oscal_schema_adapter.py` — all pass. `python -c "from ccf.oscal.validation import validate_document; ..."` sanity. ruff/mypy clean. **Commit:** `feat(oscal): vendor OSCAL v1.1.2 schemas + official-validation adapter (draft-07 + \p patterns)`.
  (NOTE: after this commit, export tests calling `validate_document(doc).ok` may go red until Tasks 2-4 — expected.)

---

### Task 2: SSP export conformance

**Files:** Modify `src/ccf/api/routes/oscal.py` (`build_ssp_doc` + helpers); Test: `tests/test_ssp_conformance.py` (+ existing SSP export tests now run official).

- [ ] **Step 1: Measure.** Run `tests/test_boundary_oscal.py` + `tests/test_nist80053_oscal.py` (they call `validate_document`) — read the official-mode errors. Also add a quick script: build an SSP doc, print `validate_document(doc).errors`. The spike already found: missing `authorization-boundary` under `system-characteristics`, and required non-empty arrays.
- [ ] **Step 2: Failing test** `tests/test_ssp_conformance.py` — build a realistic SSP (via `build_ssp_doc` for a seeded project or the export route) and assert `validate_document(doc).ok` with `mode == "official"`.
- [ ] **Step 3: Fix `build_ssp_doc`** to satisfy the schema WITHOUT fabricating: add `system-characteristics.authorization-boundary` = `{"description": <boundary text from metadata_json, else a _placeholder remark>}`; ensure required arrays are present and non-empty where the schema demands (or restructured to satisfy minItems — e.g. if `props`/`responsible-roles` must be non-empty, only include the key when populated). Fix uuid formats to v4 if any are non-conformant. Address each schema error; use honest placeholders (the file's `_placeholder`) for genuinely-absent data.
- [ ] **Step 4: Run** `tests/test_ssp_conformance.py` + `tests/test_boundary_oscal.py` + `tests/test_nist80053_oscal.py` — all green (official). ruff/mypy clean. **Commit:** `fix(oscal): SSP export conforms to official OSCAL schema`.

---

### Task 3: SAR export conformance

**Files:** Modify `src/ccf/api/routes/oscal.py` (`build_sar_doc`); Test: `tests/test_sar_conformance.py` (+ `tests/test_oscal_sar.py` now official).

- [ ] **Step 1: Measure** — build a SAR (from a seeded assessment) and read `validate_document(doc).errors` (now against `oscal_assessment-results_schema.json`).
- [ ] **Step 2: Failing test** `tests/test_sar_conformance.py` — a populated assessment → SAR → `validate_document(doc).ok` with `mode == "official"`.
- [ ] **Step 3: Fix `build_sar_doc`** for every schema error: result `start` datetime format, `reviewed-controls` shape, finding `target`/`status.state` enum, observation required `uuid`/`methods` enum (EXAMINE/INTERVIEW/TEST/TEST-* must match the schema's method tokens), risk required fields (`status`, `statement`, etc.), metadata parties/roles. Honest placeholders where needed.
- [ ] **Step 4: Run** `tests/test_sar_conformance.py` + `tests/test_oscal_sar.py` green. ruff/mypy clean. **Commit:** `fix(oscal): SAR export conforms to official OSCAL schema`.

---

### Task 4: POA&M + component-definition conformance

**Files:** Modify `src/ccf/api/routes/oscal.py` (`build_poam_doc`, `build_component_definition_doc`); Test: `tests/test_poam_component_conformance.py`.

- [ ] **Step 1: Measure** — build a POA&M doc and a component-definition doc; read official errors for each (`oscal_poam_schema.json`, `oscal_component_schema.json`).
- [ ] **Step 2: Failing tests** — a system with an open POA&M → poam doc `validate_document(doc).ok` official; a system → component-definition `validate_document(doc).ok` official.
- [ ] **Step 3: Fix** both builders per the schema errors (uuid formats, required props, minItems on `poam-items`/`components`/`control-implementations`, `import-ssp` presence for POA&M if required). Honest placeholders where absent.
- [ ] **Step 4: Run** `tests/test_poam_component_conformance.py` + `tests/test_oscal_package.py` + `tests/test_oscal_validation.py` green (official). ruff/mypy clean. **Commit:** `fix(oscal): POA&M + component-definition exports conform to official schema`.

---

### Task 5: CI gate + official-mode assertions + full-suite verification

**Files:** Modify `.github/workflows/ci.yml`; update export tests to assert `mode == "official"`; Test: `tests/test_oscal_require_official.py`.

- [ ] **Step 1: CI gate** — in `.github/workflows/ci.yml` `quality` job env, add `CCF_OSCAL_REQUIRE_OFFICIAL_SCHEMA: "1"` (so a missing schema / no-jsonschema env fails loudly, not silently structural).
- [ ] **Step 2: Assert official** — in the key export tests (`test_oscal_validation.py`, `test_oscal_sar.py`, `test_boundary_oscal.py`, `test_nist80053_oscal.py`, `test_oscal_package_golden.py`) add/strengthen an assertion that `validate_document(doc).mode == "official"` alongside `.ok`, proving they run against the real schema.
- [ ] **Step 3: require-official unit test** `tests/test_oscal_require_official.py` — with `oscal_require_official_schema=True` and a bogus `oscal_schema_dir` (monkeypatch settings so no schema resolves) → `validate_document(doc).ok is False` and an error states official schema unavailable (NOT a silent structural pass).
- [ ] **Step 4: FULL suite** — `CCF_OSCAL_REQUIRE_OFFICIAL_SCHEMA=1 pytest -q` must be green. ruff + mypy + bandit clean. **Commit:** `ci(oscal): require official OSCAL schema validation + assert official mode`.

---

## Final verification (after all tasks)
- [ ] `ruff check .` + `mypy src` + `bandit -r src -ll -x tests` clean.
- [ ] `CCF_OSCAL_REQUIRE_OFFICIAL_SCHEMA=1 PYTHONPATH=src pytest -q` — full suite green.
- [ ] Manual: `GET /oscal/package/{id}` → unzip → each of ssp/sar/poam/component-definition validates against the official NIST schema (mode official).
- [ ] Rebuild `docker compose build api migrator` (schemas ship via package-data / `COPY src`).

## Self-Review
**Spec coverage:** vendor + adapter + default resolution ✔(T1); SSP conformance ✔(T2); SAR ✔(T3); POA&M+component ✔(T4); CI gate + official-mode assertions + require-official test ✔(T5). **Placeholders:** honest `_placeholder`/`remarks` for absent data, never fabricated values — explicit. **Sequencing risk** (Task 1 flips official-on → intermediate red) is called out in Global Constraints with per-task gating. **Type consistency:** `_translate_ecma_pattern`/`_walk_translate_patterns`/`_load_adapted_schema` in T1 used by `_validate_against_schema`; `validate_document(...).mode == "official"` assertion consistent T2-T5; no hardcoded Draft202012 anywhere after T1.
