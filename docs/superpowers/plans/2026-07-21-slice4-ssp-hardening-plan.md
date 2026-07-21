# Slice 4 — SSP Engine & Lifecycle Hardening — Implementation Plan

Executes the highest-value SSP/ISSM findings from
`docs/superpowers/assessments/2026-07-21-consolidated-findings-register.md`.
Tasks run **sequentially** (each sees the prior task's committed migrations).

## Global Constraints

- **Test DB:** run tests with `PYTHONPATH=src` and
  `CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5433/ccf_test`,
  `CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5433/ccf_test`.
  The `clean_migrated_db` conftest fixture resets to base→head automatically.
- **Migrations:** the current head is `0037_ai_provider_configs`. If a task needs a
  schema change, add exactly one new Alembic migration whose `down_revision` is the
  **current head at the time you run** (check `alembic heads`), following the RLS
  pattern in `migrations/versions/0032_ai_actions.py` (ENABLE + FORCE RLS + a
  `tenant_isolation` policy with the `(ccf.current_tenant() IS NULL OR <predicate>)`
  form) for any new tenant-owned table. Add the ORM model to the matching
  `src/ccf/models*.py`. New columns on existing tenant tables need no new policy.
- **Tenant scope:** every new query filters by `organization_id`/`system_id` in
  addition to RLS (defense-in-depth). Every state mutation must be reachable through
  the audit trail (HTTP mutations are covered by `audit_middleware`).
- **Style:** match surrounding code; `ruff check` and `mypy` must pass on changed
  files. Follow TDD — write a failing test first.
- **Do not** change unrelated code, weaken existing tests, or alter the SSP control
  catalog (FR-01 is explicitly out of scope for this slice).
- **Enums/status:** reuse existing status vocabularies; do not invent new ones.

## Task 1 — FR-02: Completeness must gate on evidence and reject draft/placeholder narratives

**File:** `src/ccf/ssp/completeness.py` (+ `tests/test_ssp_completeness.py`).

**Problem:** `_entry_gaps()` counts any non-empty narrative as complete, so an SSP of
auto-composed `[DRAFT]` statements with zero evidence scores 100% ready.

**Requirements:**
1. Treat an entry as gapped ("draft narrative — needs review") when its narrative
   still carries the draft marker `DRAFT_PREFIX` (import from `ssp/statements.py`)
   or contains an unresolved ODP placeholder (`[Assignment:`/`[Selection:`/
   `[ORGANIZATION-DEFINED:` — match the tokens the codebase actually uses; verify by
   reading `ssp/odp.py` and `statements.py`).
2. Treat an entry with `implementation_status` in {"Implemented","Partially
   Implemented"} (verify exact values used in the code) as gapped ("implemented
   without evidence") when it has no linked evidence. Determine the evidence linkage
   the SSP entry actually has (control implementation → evidence, or an evidence
   reference on the entry) by reading the models; if no linkage exists at the entry
   level, gate on the control implementation's evidence.
3. These new gaps must lower the readiness score and set `ready=False`, exactly like
   existing gaps.

**Acceptance:** a project whose entries are all auto-`[DRAFT]` with no evidence scores
not-ready and reports the new gap reasons per control; an entry with a real narrative,
filled ODPs, and linked evidence reports no new gap.

**Tests:** extend `tests/test_ssp_completeness.py` — one test for the DRAFT/ODP gate,
one for the evidence gate (implemented-without-evidence), one confirming a fully
complete entry still passes.

## Task 2 — FR-08: Crypto (SC) statements must reference FIPS-validated modules

**File:** `src/ccf/ssp/platforms.py` (+ a test, e.g. `tests/test_statements.py` or a new
`tests/test_ssp_platforms.py`).

**Problem:** SC service strings ("AWS KMS… and enforced TLS", "Microsoft Purview
encryption…") name no FIPS 140-2/140-3 validated module and no key custody, so every
crypto control reads as boilerplate (automatic changes-required).

**Requirements:**
1. For SC-family controls (SC-8, SC-13, SC-28 — identify how platform statements key
   on control family in `platforms.py`), the composed statement must include a
   FIPS 140-2/140-3 validated-module reference appropriate to the platform (e.g. AWS
   KMS FIPS 140-2 validated endpoints; Azure/Microsoft FIPS 140-2 validated
   cryptographic modules) and a key-custody/partition phrase.
2. Do not fabricate specific FIPS certificate numbers — use the validated-module
   language and leave a clearly-marked placeholder for the cert/endpoint the org must
   confirm, consistent with how the codebase marks manual fields.
3. Keep non-SC statements unchanged.

**Acceptance:** a composed SC-13 statement for an AWS platform names a FIPS-validated
module and key custody; a non-SC statement is byte-identical to before.

**Tests:** assert SC statements contain the FIPS + key-custody language for each
supported platform; assert a non-SC statement is unchanged.

## Task 3 — FR-09 & FR-10: OSCAL SSP export must match the human SSP and use one baseline

**File:** `src/ccf/api/routes/oscal.py` (+ `tests/test_oscal_validation.py`).

**Problem:** `ssp_export` hardcodes sensitivity "cui", a single "CUI" info type, status
"operational", omits the authorization boundary, and emits no system-implementation —
while the docx renders boundary/FIPS-categorization/roles from `project.metadata_json`.
Separately, the SSP export cites 800-171r2 while the component-definition export cites
800-53r5.

**Requirements:**
1. Source OSCAL system-characteristics (security-sensitivity-level, information types,
   status, authorization boundary, responsible roles) from the **same**
   `project.metadata_json` the docx generator uses (read `ssp/generator.py` for the
   exact keys), rather than hardcoding. When a value is absent from metadata, emit a
   clearly-marked placeholder rather than a false constant.
2. Emit a minimal but present `system-implementation` (at least the components/users
   the metadata supports) so the artifact is structurally an SSP.
3. Make the baseline/profile consistent between `ssp_export` and
   `component_definition` — both reference the same catalog the project is actually
   built against. (The catalog is CMMC/800-171 today; do not change the catalog —
   just make the two exports agree and stop the SSP export from claiming a different
   baseline than the system is built on.)

**Acceptance:** for one project, the OSCAL SSP export and the docx report the same
categorization, boundary, and roles; the OSCAL SSP and component-definition cite the
same profile/source; OSCAL schema validation (if wired in the test) still passes.

**Tests:** extend `tests/test_oscal_validation.py` — assert the export reflects
metadata (not hardcoded "cui"/"operational"), includes an authorization boundary and a
system-implementation, and that both OSCAL artifacts reference the same baseline.

## Task 4 — ISSM-01: Authorization write path (ATO status transitions)

**File:** `src/ccf/api/routes/systems.py` (+ `tests/` — new `tests/test_ato.py` or extend
an existing systems test).

**Problem:** nothing ever assigns `systems.ato_status`; the Authorize lifecycle stage is
unreachable in-app.

**Requirements:**
1. Add an authorize endpoint (e.g. `POST /api/systems/{id}/authorize`) that transitions
   `ato_status` (read the existing enum/values on the `System` model — do not invent
   new states) toward "authorized", and a way to set the authorization expiration
   (`ato_expires_on` if it exists; check the model).
2. Refuse authorization (HTTP 409) when the system has an open POA&M of critical/high
   severity (read the POAM severity + status vocabularies). The check must be real
   (query POA&Ms for the system).
3. Gate the endpoint with the existing `require_role` dependency at an appropriate
   authority level (e.g. admin) consistent with other write routes.
4. The mutation flows through the normal HTTP path so `audit_middleware` records it; do
   not bypass it.

**Acceptance:** authorize on a system with an open critical POA&M returns 409; on a clean
system it sets `ato_status`="authorized" and stamps the expiration; the change appears in
`/api/audit` (the middleware covers it). Do not add a separate approval table in this
task — approval-gating is ISSM-08, a later slice.

**Tests:** one test for the 409-on-open-critical-POAM path, one for the success path
asserting `ato_status` changed.

## Task 5 — ISSM-02 & ISSM-10: Assessment findings auto-generate provenanced POA&Ms with a milestone

**Files:** `src/ccf/api/routes/assessments.py`, and if a finding→POA&M back-reference
column is needed, `src/ccf/models.py` + a new migration (current head at run time).

**Problem:** `poams_from_findings` is manual, creates POA&Ms with no source/owner/due/
control link/back-reference and no milestone; idempotency is a fragile title match.

**Requirements:**
1. When generating POA&Ms from other-than-satisfied findings, stamp each with
   `source='assessment'`, the originating control, a default owner (system owner if
   available, else leave null but record provenance), a scheduled completion/due date
   (a sensible default, e.g. 30/90 days from creation — reuse any existing default in
   the code), and a **stable back-reference** to the assessment/control-result that
   raised it (add a column if none exists — e.g. `source_ref`/`finding_uid`), so
   re-running is idempotent on that reference rather than on the title string.
2. Seed at least one milestone (`poam_milestones`) on each generated POA&M so it is
   exportable with a scheduled completion.
3. Idempotency: re-running generation for the same finding does not create duplicates.

**Acceptance:** an other-than-satisfied finding yields exactly one POA&M carrying
source='assessment', the control, a due date, a milestone, and a back-reference
reachable both ways; re-running is a no-op.

**Tests:** one test asserting the provenance fields + milestone are set, one asserting
idempotency (run twice → one POA&M).

## Task 6 — ISSM-03: ConMon and control-test failures open POA&Ms

**Files:** `src/ccf/governance/conmon.py`, `src/ccf/governance/control_tests.py` (+ tests
`tests/test_reliability.py`/a new `tests/test_conmon_poam.py` — pick the fitting file).

**Problem:** ConMon overdue controls and failed automated control tests emit only Tasks/
Notifications, never POA&Ms/risks, so monitoring-discovered weaknesses never reach the
remediation register.

**Requirements:**
1. When ConMon marks a control overdue/at-risk (`conmon.scan`) or an automated control
   test fails (`control_tests._alert_on_failure`/`run_due`), open (idempotently) a POA&M
   with `source='conmon'` (or `'control_test'`), the affected control, a severity derived
   from the signal, and a default milestone — in addition to the existing Task/
   Notification, not replacing them.
2. Idempotency: a control that stays overdue across scans must not accrue duplicate
   POA&Ms — dedupe on (system, control, source) open POA&M.
3. Preserve all existing ConMon/control-test behavior and tests.

**Acceptance:** forcing a control overdue (or a control test to fail) produces a POA&M in
`/api/poams` with the right source; a second scan does not duplicate it.

**Tests:** one test per path (overdue → POA&M, failed test → POA&M) + a dedupe test.

## Task 7 — Slice 3b: Organization AI settings (backend + minimal admin UI)

**Files:** new `src/ccf/api/routes/ai_settings.py`; register it where routers are
included (read `src/ccf/api/main.py` / the routes package); a minimal admin template
under `src/ccf/api/templates/` following the existing HTMX/Alpine style; tests
`tests/test_ai_settings.py`.

**Problem:** the org-scoped AI credential vault + gateway exist (`src/ccf/ai/`,
`ai_provider_configs`, migration 0037) but there is no way for an org admin to manage
them.

**Requirements:**
1. Admin-gated (`require_role`) JSON endpoints scoped to the caller's organization that
   use the gateway service (`src/ccf/ai/gateway.py`) — do NOT call providers directly:
   - list configs (masked — via `gateway.masked_view`; never return the token),
   - upsert/add a provider credential (`gateway.set_credential`) — accepts api_key,
     enabled, default_model, allowed_models,
   - test connection (`gateway.validate_credential`),
   - rotate (set_credential with a new api_key),
   - revoke/disable (set enabled False and/or clear the credential).
2. The API must never return `encrypted_credential`; only `key_last4` and metadata.
   Credential storage requires `CCF_AI_CREDENTIAL_MASTER_KEY`; when unset, the add/rotate
   endpoints return a clear error (the cipher already raises `CredentialStorageError`).
3. A minimal server-rendered admin page listing configured providers (masked), with
   add/test/rotate/revoke actions, consistent with existing admin UI patterns.

**Acceptance:** an org admin can add a key (stored encrypted, returns masked), test it,
rotate it, and disable it, all scoped to their org; a non-admin is refused; another org
cannot see or affect the first org's config; the token is never in any response.

**Tests:** add/list/mask, org isolation, non-admin refused, missing-master-key error,
rotate updates key_last4. Use a MockTransport or monkeypatched provider for the
test-connection path (no real network), following `tests/test_ai_gateway.py`.
