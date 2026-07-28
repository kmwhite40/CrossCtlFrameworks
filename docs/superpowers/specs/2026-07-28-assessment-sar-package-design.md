# Assessment SAR + Authorization-Package Bundle — Design (Keystone #3)

- **Date:** 2026-07-28
- **Status:** Approved (brainstorming → spec)
- **Related:** `docs/superpowers/assessments/2026-07-27-holistic-capability-map.md` (Keystone #3); the 800-53r5 SSP
  pipeline (Keystone #2), boundary/inventory (Keystone #1); `src/ccf/api/routes/oscal.py`, `src/ccf/oscal/validation.py`

## Problem

A FedRAMP authorization package is **SSP + SAP/SAR + POA&M** together. Concord's OSCAL exports cover SSP,
POA&M, and component-definition — but there is **no assessment-results (SAR) export** and **no single
downloadable package**. An assessor cannot get the SAR side in OSCAL, and there is no one artifact to hand an
Authorizing Official. `src/ccf/oscal/validation.py` already registers the `assessment-results` schema, so the
SAR side is validatable — it just isn't generated. This is the lifecycle's final gap: it turns everything built
(SSP, boundary, POA&Ms, assessments) into a **deliverable authorization package**.

## Goal

Add an **OSCAL Assessment-Results (SAR) export** and a **single authorization-package bundle** (a ZIP of the OSCAL
docs), reusing the assessment, evidence, and POA&M models already present.

### Decisions (from brainstorming)

| Decision | Choice |
|---|---|
| SAR granularity | **Control-level findings** — one OSCAL finding per assessed control from `AssessmentResult`. Objective-level (800-53A) is v2. |
| Package contents | **ZIP: SSP + SAR + POA&M + component-definition** + a manifest README. |
| SAP | **Deferred** — SAR + package only in v1. |

### Non-goals (v1)
Objective-level (800-53A determination-statement) findings; a generated OSCAL assessment-plan (SAP); digital
signatures / detached signing of the package; multi-assessment aggregation.

## Data sources (all existing)

- `Assessment` (`assessments`): `system_id`, `name`, `kind` (self/internal/3pao/ig/audit), `started_on`,
  `finished_on`, `assessor`, `summary`.
- `AssessmentResult` (`assessment_results`): `assessment_id`, `implementation_id` → `ControlImplementation`
  (→ `control`), `finding` (satisfied | other_than_satisfied | not_applicable), `rationale`, `observed_on`.
- `EvidenceObject` (`evidence_objects`): `title`, `description`, `control_id` (tag), `implementation_id` (FK),
  `owner`, `system_id`.
- `POAM` (system's open items — the existing `poam_export` already resolves these).

## 1. Refactor: extract OSCAL doc builders (no behavior change)

The existing exports live inside route handlers. Extract their doc-building into callable functions so the
package assembler can compose them in-process:
- `async def build_ssp_doc(session, project) -> dict` (from `ssp_export`)
- `async def build_poam_doc(session, system, *, open_only=True) -> dict` (from `poam_export`)
- `async def build_component_definition_doc(session, system) -> dict` (from `component_definition`)
The route handlers become thin wrappers calling these. **No output change** — existing OSCAL tests must pass
unchanged. Place builders in `src/ccf/api/routes/oscal.py` (or a new `src/ccf/oscal/builders.py` if cleaner).

## 2. SAR builder + route

- `async def build_sar_doc(session, assessment) -> dict` — build an OSCAL `assessment-results` document:
  - `metadata`: title "Security Assessment Report", `last-modified`/`version`/`oscal-version`, a party for the
    assessor (`assessment.assessor`) with role-id `assessor`, and props for `assessment-kind` = `assessment.kind`.
  - `import-ap`: `{"href": "#no-assessment-plan", "remarks": "No OSCAL assessment plan (SAP) is generated in this
    release; results are reported directly."}` (schema requires `import-ap`; honest placeholder — never fabricate a
    SAP).
  - `results`: a single result object:
    - `uuid`, `title` (assessment name), `start` (started_on or now), `end` (finished_on, optional), `description`
      (assessment.summary).
    - `reviewed-controls`: `{"control-selections": [{"include-controls": [{"control-id": <oscal id>} for each
      distinct assessed control]}]}`. Control id = the implementation's control identifier lowercased/OSCAL form
      (reuse `canonical_to_oscal_id` when the id canonicalizes; else lowercased).
    - `observations`: one per `EvidenceObject` tied to the assessment's implementations (or the system + a control
      tag matching an assessed control): `uuid`, `title`, `description`, `methods` (default `["EXAMINE"]`;
      derive INTERVIEW/TEST from a tag/prop if present), `collected` (a date), and `relevant-evidence`
      (`[{"href": <evidence uri or "#evidence-{id}">, "description": title}]`). Keep an id→uuid map for linking.
    - `findings`: one per `AssessmentResult`: `uuid`, `title` (control id + control title), `description`
      (rationale), `target`: `{"type": "statement-id", "target-id": f"{oscal_cid}_smt", "status": {"state": ...}}`
      where state = `satisfied` for satisfied, `not-satisfied` for other_than_satisfied; `not_applicable` →
      state `not-satisfied` with a prop `applicability=not-applicable` (OSCAL finding status has only
      satisfied/not-satisfied — encode N/A as a prop, don't drop it). `related-observations`:
      `[{"observation-uuid": <uuid>}]` for evidence on that implementation.
    - `risks`: one per open `POAM` for the system: `uuid`, `title`, `description` (weakness), `status`
      (`{"state": "open"}`), `statement`. (Reuse the POA&M resolution logic.)
  - Validate: the route runs `validate_document(doc, "assessment-results")` and the doc must be `report.ok`.
- Route `GET /oscal/sar/{assessment_id}` — resolve the assessment (org-scope via its system, 404 otherwise; mirror
  the existing export routes' scoping + auth), return `build_sar_doc`. Add `GET /oscal/sar/system/{system_id}` that
  picks the system's most recent finished assessment (404 if none).

## 3. Authorization-package bundle

- `async def build_package_zip(session, system) -> bytes` — assemble a ZIP (in-memory `zipfile.ZipFile` over a
  `BytesIO`) containing:
  - `ssp.json` — from the system's SSP project (the most recent `SSPProject` with `system_id == system.id`; skip
    with a note in the manifest if none).
  - `sar.json` — from the system's most recent finished assessment (skip + note if none).
  - `poam.json` — `build_poam_doc(session, system)`.
  - `component-definition.json` — `build_component_definition_doc(session, system)`.
  - `README.txt` — a manifest: system name, generation timestamp (passed in — do NOT call `datetime.now` at import),
    each artifact's presence/version, and a one-line note that this is a machine-readable OSCAL authorization
    package (SSP + SAR + POA&M + component-definition).
  Each JSON is `json.dumps(doc, indent=2)`.
- Route `GET /oscal/package/{system_id}` — org-scoped + auth like the other export routes; returns a
  `StreamingResponse(BytesIO(zip_bytes), media_type="application/zip", headers={"content-disposition":
  f'attachment; filename="authorization-package-{system_id}.zip"'})`.

## Testing (TDD; `session_scope()`/`fresh_engine`, no `db_session`)

- **Refactor:** existing `tests/test_oscal_validation.py` + the SSP/POA&M export tests pass UNCHANGED (byte-identical
  output). Add a direct-call test that `build_ssp_doc`/`build_poam_doc` return the same doc the route returns.
- **SAR:** create a System + ControlImplementations + an Assessment with AssessmentResults (one satisfied, one
  other_than_satisfied, one not_applicable) + an EvidenceObject on an implementation + an open POA&M. Export
  `/oscal/sar/{id}`; assert: a finding with `status.state == "satisfied"`, one with `"not-satisfied"`, the N/A one
  carries the applicability prop; an observation from the evidence with a method; a risk from the POA&M; and
  `validate_document(doc, "assessment-results").ok` is True. Test `/oscal/sar/system/{system_id}` picks the latest.
  Role-gated (unauthorized → 403/404).
- **Package:** `GET /oscal/package/{system_id}` returns a zip (magic `PK`); unzip and assert it contains
  `ssp.json`, `sar.json`, `poam.json`, `component-definition.json`, `README.txt`; each JSON parses and validates
  against its schema. A system with no SSP/assessment still returns a zip (poam + component-def + README noting the
  gaps). Role-gated.
- **Golden e2e:** a fully-populated system (SSP project + boundary + assessment + evidence + POA&M) → SAR validates
  → package zip holds all four docs, each schema-valid.

## Rollout
Additive, read-only (no migration). Reuses existing models + the registered assessment-results schema. Rebuild
images not required for schema (no migration), but rebuild to ship the new routes.

## Success criteria
1. `/oscal/sar/{assessment_id}` produces a schema-valid OSCAL assessment-results doc with control-level findings,
   evidence observations, and POA&M risks (tested).
2. Finding status maps correctly (satisfied / not-satisfied + N/A prop); evidence → observations → findings linked
   (tested).
3. `/oscal/package/{system_id}` returns a ZIP with SSP + SAR + POA&M + component-definition + README, each JSON
   schema-valid (tested).
4. The refactor leaves existing OSCAL exports byte-identical; full suite green; ruff + mypy-strict + bandit clean.
