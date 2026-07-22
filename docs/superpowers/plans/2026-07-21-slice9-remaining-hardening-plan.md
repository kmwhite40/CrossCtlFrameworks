# Slice 9 — Remaining Hardening (reliability, security, governance) — Plan

Clears the highest-value tracked follow-ups: the audit-middleware reliability bug, two
tenant-isolation gaps (DATA-03, IA-06), and two governance-completeness items (IA-10,
ISSM-07). Sequential (migrations chain from head `0045`).

## Global Constraints

- **Test DB:** `PYTHONPATH=src`, `CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5433/ccf_test`,
  `CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5433/ccf_test`.
- **Migrations:** confirm head with `alembic heads`; set `down_revision`; verify up→down→up;
  handle existing rows safely.
- **TDD**, production-path tests. `ruff` + `mypy` clean on changed files. Keep the full suite
  deterministic (clean up any global/reference rows a test seeds). Only acceptable full-suite
  failure: the known audit-chain middleware bug in
  `test_enterprise.py::test_audit_chain_verifies_and_detects_tampering` — **Task 1 fixes it**,
  so after Task 1 there should be ZERO failures.
- **COMMIT as soon as tests are green, before writing the report** (agents have been
  interrupted mid-run).

## Task 1 — Audit-middleware double-invocation-on-exception bug (reliability)

**Files:** `src/ccf/api/audit.py`, possibly `src/ccf/api/main.py` (+ tests).

**Problem:** `audit_middleware` is a Starlette `BaseHTTPMiddleware`. On a request that raises,
`BaseHTTPMiddleware` can invoke the downstream app twice / mishandle the response — a real,
deterministic bug (root-caused earlier; it surfaces as the intermittent
`test_audit_chain_verifies_and_detects_tampering` failure). Under an exception the audit path
can double-record or corrupt the chain/response.

**Requirements:**
1. Reproduce first: write a test that issues a request which raises an exception inside a route
   (or triggers the double-invocation) and asserts the audit behavior is correct — the audit
   row is written **exactly once** for a successful mutation, and a raising request does not
   double-invoke the handler / double-write. Confirm it fails (or is flaky) on the current code.
2. Fix the middleware so it is exception-safe and single-invocation. Preferred approaches, in
   order: (a) guard the audit recording so it runs exactly once per request regardless of the
   Starlette re-entry (e.g. an idempotency flag on `request.state`); or (b) convert
   `audit_middleware` from `BaseHTTPMiddleware` to a pure ASGI middleware / a dependency that
   doesn't suffer the double-invocation. Keep behavior identical for the normal path (record on
   2xx/3xx mutations only, skip prefixes, hash chain unchanged). Do NOT record audit rows for
   requests that ultimately error (5xx) unless that was already the behavior.
3. `/api/audit/verify` must still pass; the hash chain semantics are unchanged.

**Acceptance:** the reproducer passes deterministically (3 repeats); a normal mutation writes
exactly one audit row; the full suite has ZERO failures (the previously-flaky test is now green).
If a full pure-ASGI rewrite is too large/risky, the idempotency-guard approach is acceptable —
state which you chose and why.

## Task 2 — DATA-03: `framework_controls` org-scoping (cross-tenant leak/overwrite)

**Files:** `src/ccf/models.py` (FrameworkControl), the upload path
(`src/ccf/api/routes/automation.py` `_upsert_controls`), a new migration (+ tests).

**Problem:** `framework_controls` has no `organization_id` and no RLS, yet a tenant-facing upload
(`_upsert_controls`) writes to it, and its unique key is global `(framework_code, identifier)`.
So one tenant's uploaded framework overwrites another's and every tenant sees every tenant's
uploaded controls.

**Requirements:**
1. Add `organization_id` (FK to organizations, nullable to allow existing global/seeded rows —
   confirm whether framework_controls also holds globally-seeded reference data; if so, keep
   NULL-org rows visible to all and scope only tenant-uploaded rows). Add an RLS policy
   `(current_tenant() IS NULL OR organization_id IS NULL OR organization_id = current_tenant())`.
   Include organization_id in the unique constraint: `(organization_id, framework_code,
   identifier)` (drop/replace the old global unique). Migration handles existing rows (backfill
   org NULL) + dedupe if the new unique would collide.
2. `_upsert_controls` writes `organization_id = <caller org>` and scopes its upsert query by
   organization_id (so a tenant can't overwrite another's or a global row).
3. Verify up→down→up. Confirm the RLS coverage test picks up the new policy.

**Acceptance:** two tenants can hold the same `framework_code` independently; a cross-tenant
SELECT returns 0 of the other tenant's uploaded rows; globally-seeded rows (if any) stay visible.
Tests assert the isolation + independent upsert.

## Task 3 — IA-06: Scheduler runs per-tenant

**Files:** `src/ccf/governance/scheduler.py`, `src/ccf/governance/collection.py` (+ tests).

**Problem:** `run_cycle` opens a session with tenant None (RLS bypass) and calls
`collect_all(session)` with no org, so background captures/notifications are written
`organization_id=None` and every job runs with RLS disabled — no tenant attribution, no backstop.

**Requirements:**
1. Change the scheduler's collection/scan cycle to iterate organizations and run each org's
   work under `set_session_tenant(session, org.id)` (read how collect_all + scan take/expect an
   org_id; per Slice 7, connector capture is already per-org — thread the org through). Snapshots
   / drift notifications must carry the correct `organization_id`.
2. Do not break the catalog-currency poll / alert-digest steps that are genuinely global — only
   the per-tenant work (collection/conmon/control-tests) needs the per-org loop. Be precise about
   which steps are global vs per-org.
3. Keep the advisory-lock/single-flight behavior.

**Acceptance:** running one scheduler cycle with two orgs writes each snapshot/notification with
the correct non-null org; a job scoped to org A cannot write org B rows. Tests drive the real
cycle with two orgs (mock providers; no real cloud).

## Task 4 — IA-10: Honor the AI safety flags

**Files:** `src/ccf/ai_actions/service.py`, `src/ccf/config.py` (read) (+ tests).

**Problem:** `ai_require_human_approval` and `ai_store_prompts` config flags are inert — approval
gating derives only from the registry, and prompt/input payloads are always persisted regardless
of `ai_store_prompts`.

**Requirements:**
1. Honor `ai_store_prompts=False`: do NOT persist the prompt/input payload (skip or redact the
   `AiActionInput.payload`) when the flag is off. Keep the run record + hashes; just don't store
   the raw prompt content.
2. Honor `ai_require_human_approval=True` as an override that FORCES `requires_approval` for any
   action (so an operator can require approval globally even for actions the registry marks
   auto). When the flag is default (True) behavior must not regress.
3. Do not change the citation-first / mutation-gating behavior otherwise.

**Acceptance:** with `ai_store_prompts=False`, running an action stores no prompt body
(`AiActionInput.payload` empty/redacted); with `ai_require_human_approval=True`, an action the
registry would auto-apply instead requires approval. Tests assert both flags.

## Task 5 — ISSM-07: Approval decisions reflect onto the governed record

**Files:** `src/ccf/governance/approvals.py` (+ tests).

**Problem:** `decide()` writes the Approval row and only stamps status for `entity_type='ssp_project'`;
approving a `poam`/`risk`/`assessment` leaves the entity's own status untouched, so approval state
lives only in a sidecar and is invisible on the record/exports.

**Requirements:**
1. In `decide()` (or a small reflect helper it calls), when an approval is decided, reflect the
   decision onto the governed entity for the other entity types where it makes sense — at minimum
   surface an approval-state on `poam`/`risk`/`assessment` (either set a status/approval field, or
   ensure the entity serializer exposes the linked approval state). Read the models to choose the
   cleanest: a dedicated `approval_state` field vs. reusing existing status. Do NOT fabricate a
   terminal transition the gate elsewhere should own (e.g. don't auto-close a POA&M) — just make
   the approval visible on the record.
2. Keep the existing ssp_project behavior.

**Acceptance:** approving a POA&M/risk surfaces an approved state in that entity's API payload
(not only in the Approval table). Tests assert the reflection for at least poam + risk.
