# Official OSCAL Schema Validation — Design

- **Date:** 2026-07-28
- **Status:** Approved (brainstorming + feasibility spike → spec)
- **Related:** `src/ccf/oscal/validation.py`; the OSCAL exports (SSP/SAR/POA&M/component-def) in
  `src/ccf/api/routes/oscal.py`; multiple whole-branch reviews flagged "validation is structural-only".

## Problem

Concord's OSCAL exports (SSP, SAR, POA&M, component-definition, and the authorization-package bundle) are
validated only by **structural** checks — `validate_document` falls back to Concord's own checks because no
official NIST OSCAL JSON Schema is vendored. Two whole-branch reviews found real conformance defects that
structural validation could not catch (invalid SSP `statement-id` tokens for enhancements; unverified SAR
finding/enum/format conformance). For a tool whose core value is OSCAL conformance, "schema-valid" must be
**machine-proven**, not asserted.

The validation machinery already exists (`CCF_OSCAL_SCHEMA_DIR`, `oscal_require_official_schema`, per-kind
`KINDS` schema registration, structural fallback) — it just has no schemas and its jsonschema call is wired for
the wrong dialect.

## Feasibility spike (settled the approach)

- The NIST OSCAL v1.1.2 JSON schemas are fetchable as GitHub release assets (complete + per-kind ssp/component/
  poam/assessment-results). The exports already emit `oscal-version: 1.1.2`.
- The schemas declare **draft-07** and use draft-07 `$id: "#anchor"` fragment anchors. `jsonschema`'s current
  hardcoded `Draft202012Validator` fails with `NoSuchAnchor`. Using
  `jsonschema.validators.validator_for(schema)` auto-detects draft-07 and **resolves the anchors natively.**
- OSCAL patterns use ECMA Unicode-property classes (`\p{L}`, `\p{N}`) that Python `re` cannot compile
  (`bad escape \p`) — this crashes validation once token fields are populated. Translating those classes to
  Python-`re` equivalents (`\p{L}`→`[^\W\d_]`, `\p{N}`/`\p{Nd}`→`[0-9]`, `\p{Lu}`→`[A-Z]`, `\p{Ll}`→`[a-z]`)
  makes the schema compile and validate correctly (tokens are ASCII in practice).
- With the adapter (validator_for + pattern translation), validating a real SSP surfaces **genuine conformance
  gaps** (e.g. missing `authorization-boundary`, empty required arrays) — the payoff.

## Goal

Vendor the pinned OSCAL v1.1.2 schemas, make `validate_document` run **official schema validation by default** via
a small schema adapter, gate it in CI, and **fix the conformance gaps** the real schemas surface across all four
export types.

### Decisions (from brainstorming)
| Decision | Choice |
|---|---|
| Default posture | **Official-by-default** (in-package schemas auto-resolve) + **require-official in CI** (a non-conformant export fails the build). |
| Fix scope | **All four export types** (SSP, SAR, POA&M, component-definition). |

### Non-goals (v1)
Bundling non-OSCAL validation (SCAP etc.); validating the ZIP package as a single OSCAL object (it's a delivery
container, not one doc); upgrading to a newer OSCAL version than 1.1.2; a `regex`-module-backed exact pattern
engine (the translation approximation is sufficient for token/uuid/date patterns).

## 1. Vendor the pinned schemas

- Add `src/ccf/oscal/schemas/` (in-package → ships in the wheel + Docker `COPY src`, mirroring
  `src/ccf/catalog/oscal_data/`): `oscal_complete_schema.json`, `oscal_ssp_schema.json`,
  `oscal_component_schema.json`, `oscal_poam_schema.json`, `oscal_assessment-results_schema.json`, plus a
  `MANIFEST.json` (oscal_version "1.1.2", source URL, per-file sha256, retrieved date).
- `pyproject.toml` `[tool.setuptools.package-data]`: `"ccf.oscal" = ["schemas/*.json"]`.

## 2. Schema adapter + default resolution (`src/ccf/oscal/validation.py`)

- **Default the schema dir to the packaged location.** In `official_schema_path`, when
  `settings.oscal_schema_dir` is None, fall back to `Path(__file__).with_name("schemas")` (the packaged dir).
  So official validation runs with no env config; `CCF_OSCAL_SCHEMA_DIR` still overrides for a custom dir.
- **Fix `_validate_against_schema`** to be OSCAL-correct:
  1. Load the schema JSON.
  2. Recursively translate every `pattern` string via a small `_translate_ecma_pattern` (the class map above).
     Cache the adapted schema per path (module-level dict) so repeated validations don't re-walk a 200KB schema.
  3. Build the validator with `jsonschema.validators.validator_for(schema)(schema)` (auto-detects draft-07;
     resolves `#anchor` refs). Do NOT hardcode Draft202012.
  4. Return `[e.message for e in validator.iter_errors(doc)]` (bounded/sorted as today).
- Keep the structural fallback for when schemas are absent (defensive) and the `require_official` behavior.

## 3. Enable official-by-default + CI gate

- With the packaged schemas resolving by default, `validate_document(doc)` now returns `mode == "official"`.
- Update the OSCAL export/validation tests to assert `report.mode == "official"` (proving they run against the
  real schema) in addition to `report.ok`.
- CI (`.github/workflows/ci.yml`): set `CCF_OSCAL_REQUIRE_OFFICIAL_SCHEMA=1` for the test job so a missing schema
  OR a jsonschema-unavailable environment fails loudly rather than silently downgrading to structural.

## 4. Fix conformance gaps (the payoff)

Run each export through official validation and fix every conformance error, per export type:
- **SSP** (`build_ssp_doc`): the spike found missing `authorization-boundary` under `system-characteristics`, and
  required non-empty arrays. Populate `authorization-boundary` (from `metadata_json` boundary text, or a
  `remarks` placeholder when absent — never fabricate), ensure required fields/arrays are present, uuid-v4 format.
- **SAR** (`build_sar_doc`): validate against `oscal_assessment-results_schema.json`; fix required fields (result
  `start` datetime, `reviewed-controls`, finding `target`/`status`, observation `methods`/`uuid`, risk required
  fields) the schema flags.
- **POA&M** (`build_poam_doc`) and **component-definition** (`build_component_definition_doc`): fix whatever the
  schemas surface (uuid formats, required props, minItems).
Each fix is TDD: the test asserts `validate_document(doc).ok` in official mode.

## Testing (TDD; `session_scope()`/`fresh_engine`)

- **Adapter unit tests:** `_translate_ecma_pattern` maps the classes; a real vendored schema loads via
  `validator_for` and validates a hand-built minimal-valid doc (mode official, ok True) and rejects an invalid one
  with schema errors; a token-field-populated doc does NOT crash (regression for the `\p` bug).
- **Default resolution:** `official_schema_path("ssp")` resolves the packaged schema with no env set;
  `validate_document(ssp_doc).mode == "official"`.
- **Per-export conformance:** each of SSP/SAR/POA&M/component-def exports validates `ok` in official mode
  (these are the fixes from §4). The existing export tests already call `validate_document`; they now run official
  and must pass.
- **CI-gate behavior:** with `oscal_require_official_schema=True` and schemas present, validation is official; a
  unit test simulates a missing schema dir → `require_official` yields an error (not silent structural).

## Rollout
Additive but STRICTER by default: `validate_document` now truly validates. Any export that was silently
non-conformant will now fail its test until fixed (§4) — that's the point. Rebuild images to ship the schemas
(package-data). No migration.

## Success criteria
1. The pinned OSCAL v1.1.2 schemas ship in-package; `validate_document(doc)` runs official validation by default
   (`mode == "official"`), no env needed.
2. The adapter resolves OSCAL's draft-07 anchors and `\p{...}` patterns without crashing (tested, incl. the
   token-field regression).
3. All four export types validate `ok` against their official NIST schema (tested) — real conformance gaps fixed.
4. CI requires official validation (`CCF_OSCAL_REQUIRE_OFFICIAL_SCHEMA=1`), so a future non-conformant export fails
   the build.
5. Full suite green; ruff + mypy-strict + bandit clean.
