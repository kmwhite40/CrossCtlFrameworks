# Security Slice — Tenant Isolation, Integrity & Secrets — Implementation Plan

Executes the highest-value IA + DATA findings from the consolidated register.
Tasks run **sequentially** (migrations must chain; several touch `models.py`).
Current Alembic head at slice start: `0038_poam_source_ref` (confirm with
`alembic heads` — a prior slice added no migration, so 0038 should be head).

## Global Constraints

- **Test DB:** `PYTHONPATH=src`, `CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5433/ccf_test`,
  `CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5433/ccf_test`. The
  `clean_migrated_db` conftest fixture resets base→head automatically.
- **Migrations:** before writing one, run `alembic heads` against the ccf DB to get the
  CURRENT head and set `down_revision` to it (tasks run in order, so head advances). Follow
  the RLS pattern in `migrations/versions/0032_ai_actions.py` (ENABLE + FORCE RLS +
  `tenant_isolation` policy with the `(ccf.current_tenant() IS NULL OR <predicate>)` form).
  Verify every migration up → down → up against the ccf DB before finishing.
- **TDD**, production-path tests (real records / real RLS session, not synthetic shapes).
- Reuse existing vocabularies. `ruff` + `mypy` clean on changed files. Widened guardrail:
  run the related existing suites; fix a stale assertion only when your change correctly
  supersedes it; STOP + report a real regression.
- Do not weaken existing tests or RLS. Do not break auth.

## Task 1 — IA-03: RLS coverage regression test (no migration)

**File:** `tests/test_rls.py` (extend) or a new `tests/test_rls_coverage.py`.

**Problem:** RLS policies exist on ~68 tables but only ~2 are tested, so a bad predicate
would isolate nothing and still pass CI.

**Requirements:**
1. Add a test that enumerates every table in the `ccf` schema that has a `tenant_isolation`
   policy (query `pg_policy`/`pg_class`, or `information_schema`), seeds two organizations
   with a row in as many of those tables as is practical, and asserts that under
   `set_session_tenant(A)` a query returns zero of B's rows for each policy-bound table.
2. For tables that are impractical to seed directly (deep child tables), at minimum assert
   the policy EXISTS and RLS is ENABLED + FORCED (`relrowsecurity`/`relforcerowsecurity`)
   for every tenant-owned table — a structural guard that catches a dropped/missing policy.
3. The test must be deterministic and clean up after itself (no leaked global rows — see
   the prior slice's isolation lesson).

**Acceptance:** the test fails if any currently-policied table loses its policy or RLS
enforcement; it passes on the current schema.

## Task 2 — IA-04 / DATA-01: RLS policies on `poam_milestones` and `organizations`

**Files:** a new migration; no model change needed (RLS is DB-level). Extend the Task 1
test to cover the two tables.

**Problem:** `poam_milestones` (tenant child of `poams`) and `organizations` (tenant root)
have no RLS policy, so at the DB layer milestones are cross-tenant readable and any scoped
tenant can enumerate all organizations.

**Requirements:**
1. Migration adds `tenant_isolation` to `poam_milestones` with a parent-scoped predicate:
   `poam_id IN (SELECT p.id FROM ccf.poams p JOIN ccf.systems s ON s.id = p.system_id
   WHERE s.organization_id = ccf.current_tenant())` (verify the real FK column names), and
   ENABLE + FORCE RLS. Grant is already broad; follow the 0032 pattern.
2. Migration adds `tenant_isolation` to `organizations` with predicate
   `id = ccf.current_tenant()` (plus the `ccf.current_tenant() IS NULL OR …` bypass), ENABLE
   + FORCE RLS. Confirm this does not break unauthenticated/global flows (global principal
   has tenant NULL → bypass).
3. Verify migration up/down/up; verify the Task 1 coverage test now includes these tables.

**Acceptance:** under tenant A, direct selects on `poam_milestones` and `organizations`
return only A's rows; the RLS coverage test passes with the two tables included.

## Task 3 — IA-02: Gate the audit-read API by role (org-column deferral noted)

**Files:** `src/ccf/api/routes/audit.py` (+ tests).

**Problem:** `list_audit` and `verify_chain` have no `require_role` and query `audit_log`
globally; any authenticated user of any tenant can read every tenant's audit trail (and it
is public when auth is off).

**Requirements:**
1. Add `require_role("admin", "auditor")` (verify these role names exist; use the closest
   existing privileged roles) to both endpoints.
2. `audit_log` has no `organization_id` column today, so true per-tenant row scoping is a
   larger change (a separate follow-up, DATA-06): DO NOT add that column in this task.
   Instead, document in a code comment that cross-tenant audit isolation requires the
   `organization_id` column + RLS (DATA-06) and is deferred, and — if the principal is
   non-global and the platform can already derive scope from `entity`/system linkage — apply
   any scoping that is cheaply available; otherwise leave a clear TODO. Do not fabricate a
   filter that silently drops rows.
3. Keep the existing hash-chain verify behavior intact.

**Acceptance:** a non-admin/non-auditor principal gets 403 from the audit endpoints; an
admin still gets the trail; the chain-verify endpoint still works. Tests cover the role gate.

## Task 4 — DATA-08 / DATA-10: Missing unique constraints on natural keys

**Files:** a new migration + `models.py`/`models_packs.py`/`models_people.py`
`__table_args__` (+ tests).

**Problem:** `vendors(org,name)`, `policies(org,name)`, `fedramp_dependencies(system,name)`,
`pack_mappings(pack,control,framework)`, `people(org,email)` allow duplicate rows.

**Requirements:**
1. Before adding each unique constraint, the migration MUST de-duplicate any existing
   violating rows (keep the lowest id, delete/merge the rest) so the constraint can be
   created — a naive `ADD CONSTRAINT` will fail on dirty data. Do the dedupe in the
   migration `upgrade()`.
2. Add the `UniqueConstraint` to both the migration and the ORM model `__table_args__`
   (verify the exact column names first).
3. Verify migration up/down/up.

**Acceptance:** inserting a second row with the same natural key raises `IntegrityError`;
the integrity validator (`docs/superpowers/assessments/integrity_checks.py`) no longer
reports these under `unique_keys`. Tests assert the constraint for at least two of the tables.

## Task 5 — IA-09: Store bearer tokens hashed at rest

**Files:** `src/ccf/models.py` (User), `src/ccf/models_portal.py` (ExternalAccessGrant),
`src/ccf/api/auth_deps.py`, `src/ccf/portal/service.py`, a new migration (+ tests).

**Problem:** `User.api_token` and portal grant tokens are stored in plaintext and matched by
equality — a DB read, backup, or the audit leak yields directly usable credentials.

**Requirements:**
1. Store a one-way hash (SHA-256 or HMAC with the app secret — match `src/ccf/auth.py`'s
   existing primitives; read it) instead of the plaintext token. Look up by hashing the
   presented token and comparing (constant-time where practical). Show the plaintext token
   only once, at issuance (return it from the create/rotate call, never store or re-return).
2. Migration: add the hash column(s); for existing rows, either hash-in-place the current
   plaintext value (so existing tokens keep working) OR invalidate them — hashing in place
   is preferred to avoid breaking live sessions; do it in the migration. Then drop/retire
   the plaintext column (or keep it null and stop reading it — but do not read plaintext for
   auth anymore).
3. Update `auth_deps` token auth and `portal/service` grant resolution to use the hash path.
4. Verify migration up/down/up; verify auth still works end-to-end (a token issued after the
   change authenticates; the stored value is a hash, not the token).

**Acceptance:** the DB holds no reversible token; issuing a token returns the plaintext once,
and authenticating with that plaintext succeeds; a test confirms the stored column is a hash
and not equal to the token. Do not break existing auth tests.
