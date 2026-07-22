# Slice 8 — Clear the Remaining Go-Live Conditions — Implementation Plan

Clears the four remaining production-readiness conditions: DATA-06 (audit per-tenant
isolation), DATA-04 (destructive-delete safety), CISO-02 (AI provenance in the UI), and
dependency hygiene. Tasks run **sequentially** (migrations chain from head `0043`).

## Global Constraints

- **Test DB:** `PYTHONPATH=src`, `CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5433/ccf_test`,
  `CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5433/ccf_test`.
- **Migrations:** confirm head with `alembic heads` (ccf DB); set `down_revision`; verify
  up → down → up; handle existing rows safely.
- **TDD**, production-path tests. Reuse existing vocabularies. `ruff` + `mypy` clean on changed
  files. **Keep the full suite deterministic** — clean up any GLOBAL/reference rows a test
  seeds (prior slices leaked ScoringControl/Ksi/Control rows). Only acceptable full-suite
  failure: the known-flaky `test_enterprise.py::test_audit_chain_verifies_and_detects_tampering`.
- Widened guardrail: run related suites; fix a stale assertion only when your change correctly
  supersedes it; STOP + report a real regression.
- **COMMIT as soon as tests are green, before writing the report** (long agents have been
  interrupted mid-run).

## Task 1 — DATA-06: Per-tenant audit-log isolation

**Files:** `src/ccf/models.py` (AuditLog), `src/ccf/api/audit.py` (middleware writes org),
`src/ccf/api/routes/audit.py` (scope reads), a new migration (+ tests).

**Problem:** `audit_log` has no `organization_id`, so the (now role-gated) trail still spans
every tenant and can't be row-isolated or exported per tenant.

**Requirements:**
1. Add `organization_id` (nullable — system/global events keep NULL) to `audit_log` (model +
   migration). Add an RLS `tenant_isolation` policy:
   `(ccf.current_tenant() IS NULL OR organization_id IS NULL OR organization_id =
   ccf.current_tenant())` — so a scoped tenant sees its own rows + system (NULL-org) rows, and
   the global/unauth principal (tenant NULL) sees all. ENABLE + FORCE RLS (follow the 0032
   pattern). Index `organization_id`.
2. **Preserve the hash chain:** `organization_id` is a SCOPING column only — do NOT add it to
   the hashed payload (`row_hash`/`prev_hash` computation in `api/audit.py`), so existing chains
   and `/api/audit/verify` are unaffected. Write `organization_id` from the request principal's
   org (read how the middleware resolves the principal; when there is no org/principal, leave
   NULL).
3. The audit-read endpoints already `require_role`; with the RLS policy + the tenant-scoped
   session they now also row-isolate. Confirm the read path runs under the tenant clamp.

**Acceptance:** a mutation by an org-A principal writes an `audit_log` row with
`organization_id = A`; under tenant A the audit query returns A's + system rows only, not B's;
`/api/audit/verify` still verifies (chain unchanged). Extend `tests/test_rls_coverage.py` +
add an audit-scoping test.

## Task 2 — DATA-04: Destructive-delete safety (soft-delete systems & organizations)

**Files:** `src/ccf/models.py` (System, Organization), the delete routes
(`src/ccf/api/routes/systems.py`, and the org delete path — find it), a new migration
(+ tests).

**Problem:** deleting a System/Organization hard-`CASCADE`s away all authorization records
(POA&Ms, assessments, evidence, implementations) irreversibly.

**Requirements:**
1. Add `deleted_at: datetime | None` (nullable) to `systems` and `organizations` (model +
   migration).
2. Change the System delete route (and the Organization delete path, if one exists) to
   **soft-delete** (set `deleted_at = now()`) instead of issuing the hard `DELETE` — so the
   cascade never fires and the authorization record is preserved. If a hard delete must remain
   available, gate it behind an explicit `?hard=true` + a guard that refuses when dependent
   authorization records exist.
3. Filter `deleted_at IS NULL` in the System/Organization list + get queries and in the
   tenant-scope helper if appropriate, so soft-deleted rows disappear from normal views but are
   preserved in the DB. Verify you are not breaking `org_systems_subq`/RLS.
4. Keep it minimal: this task is about not wiping authorization history on delete — you do NOT
   need to convert every FK's ON DELETE to RESTRICT (note that as a follow-up).

**Acceptance:** deleting a System with open POA&Ms/assessments sets `deleted_at`, hides it from
the inventory, and **preserves** its POA&Ms/assessments/evidence rows in the DB (query them
directly to confirm they still exist); the system no longer appears in `GET /api/systems`.
Tests assert the records survive and the system is hidden.

## Task 3 — CISO-02: AI-generated content is visibly distinguishable in the UI

**Files:** SSP + POA&M templates (`src/ccf/api/templates/ssp_detail.html`, `poams.html`, and
`_ssp_entry.html` if per-entry), and wherever the render context is built
(`src/ccf/api/routes/ui.py` / `ui_grc.py`); possibly a small serializer helper (+ tests).

**Problem:** AI-drafted/draft content is indistinguishable from human-approved content in the
UI, so an unreviewed AI statement can appear authoritative.

**Requirements:**
1. Surface a clear **"AI-assisted / draft — needs review"** badge wherever content may be
   AI-generated or unreviewed: SSP control statements whose narrative still carries the draft
   marker (`DRAFT_PREFIX` from `ssp/statements.py`) or whose entry state is not
   approved/needs_review; and POA&M `remediation_plan` text written by an AI action (the
   `ai_action_runs`/approved-mutation records, or an `[AI ...]` marker the ai_actions layer
   writes — read `ai_actions/service.py` for how AI-written fields are marked).
2. The badge must be visually distinct (use an existing chip class, e.g. `chip--warn`/
   `chip--info`) and appear per-entry, not just once per page. Approved/human content shows no
   badge (or a distinct "approved" chip).
3. Do not change the underlying data or the generation logic — this is a display/provenance
   surfacing task. If a per-field "is this AI-sourced" signal is not already available, derive
   it from the draft marker / needs_review state (do not fabricate provenance).

**Acceptance:** an SSP with `[DRAFT]`/needs-review entries renders a visible AI/draft badge on
those entries and none on approved ones; a POA&M whose remediation was AI-written shows an
AI-assisted marker. Test the badge appears in the rendered HTML for a draft entry and is absent
for an approved one (render the real template/route).

## Task 4 — Dependency hygiene (keep the blocking pip-audit green)

**Files:** `pyproject.toml` (+ lockfile/constraints if the repo has one).

**Problem:** the now-blocking `pip-audit` (CISO-08) will fail CI on transitive advisories the
current pins allow.

**Requirements:**
1. Run `pip-audit` (in the project venv) and identify advisories in the RESOLVED dependency
   tree that come from the project's own dependencies (ignore the local editable `ccf` "not on
   PyPI" line and pure dev-tooling like `pip` itself if not pinned by the project).
2. Bump the offending direct/transitive pins in `pyproject.toml` to a patched range (minimal,
   compatible ranges — do not blanket-widen). Where a fix requires a major bump that risks
   breakage, verify the affected import still works (run the relevant tests) or, if genuinely
   unfixable, add a documented `--ignore-vuln <ID>` in `.github/workflows/ci.yml` with a
   comment (last resort only).
3. Re-run `pip-audit` and confirm the project-owned advisories are cleared. Run the FULL test
   suite to confirm no dependency bump broke anything.

**Acceptance:** `pip-audit` reports no advisories attributable to the project's declared
dependencies (or only documented, justified ignores); the full suite still passes (except the
known-flaky test). Report the before/after advisory list.
