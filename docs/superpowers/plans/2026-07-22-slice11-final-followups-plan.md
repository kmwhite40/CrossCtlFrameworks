# Slice 11 — Final Follow-ups — Plan

Clears the remaining safe follow-ups: SSP connector routes fully per-org, portal magic-link
hardening, a non-breaking finding-vocabulary unification (ISSM-13/DATA-05), and the safe
FR-14 FedRAMP-2026 display labels. Sequential; migrations chain from head `0050` if any.

## Global Constraints

- **Test DB:** `PYTHONPATH=src`, `CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5433/ccf_test`,
  `CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5433/ccf_test`.
- **Migrations:** confirm head with `alembic heads`; revision id ≤32 chars; verify up→down→up.
  Most of this slice needs NO migration (app/display-layer changes).
- **TDD**, production-path tests. `ruff` + `mypy` clean on changed files. **Keep the full suite at
  0 failures** (currently 539 passed, 0 failures — do not regress; clean up any global rows a test
  seeds).
- Widened guardrail: run related suites; fix a stale assertion only when your change correctly
  supersedes it; STOP + report a real regression.
- **COMMIT as soon as tests are green, before writing the report.**

## Task 1 — SSP connector routes fully wired to per-org credentials

**Files:** `src/ccf/api/routes/ssp.py` (`/connectors/{key}/verify`, `/projects/{id}/autofill`)
(+ tests). No migration.

**Problem:** Slice 7 (IA-05) made connector credentials per-org and the ssp connector routes were
partially wired, but the review noted the interactive verify/autofill path is only fully reachable
via a DB-seeded credential. Confirm and finish: these routes must resolve the CALLER's org
credential (`resolve_credential(session, principal.org_id, key)`), so a configured org's verify +
autofill genuinely works over HTTP, and an org without a bound credential gets a clear
"not configured".

**Requirements:**
1. Read the current state of `ssp.py` `/connectors/{key}/verify` and `/projects/{id}/autofill`
   (they may already call `resolve_credential` after the Slice-7 fix — verify). If any path still
   instantiates the connector without the per-org credential, fix it to resolve + pass the
   caller's org credential.
2. The autofill path must attribute any captured values to the caller's org and only use that
   org's connectors (no global fallback).
3. If the routes are ALREADY correct (Slice-7 fix covered them), say so, add a production-path test
   proving verify/autofill work for a configured org and return "not configured" for an
   unconfigured one, and commit the test.

**Acceptance:** an org that has bound a connector credential (via the connector-settings API) can
verify and autofill over HTTP using its own credential; an org without one gets "not configured";
no cross-org credential use. Tests via the real routes with two orgs (mock provider, no cloud).

## Task 2 — Portal magic-link token-in-URL hardening

**Files:** `src/ccf/api/routes/portal.py` (the public portal auth path) (+ tests). Likely no migration.

**Problem:** the external portal access link is `…/portal?token=<plaintext>`. The token is hashed
at rest (Slice 7) but travels in the URL on first use, so it lands in portal access logs / browser
history.

**Requirements:**
1. Reduce the token-in-URL exposure: on the FIRST successful portal request carrying `?token=`,
   exchange the link-token for a short-lived signed session cookie (scoped to the grant) and
   redirect to the same page WITHOUT the token query param — so subsequent navigation uses the
   cookie, not the URL. Read how the portal currently authenticates a request (token lookup →
   grant) and how the app already signs session cookies (`src/ccf/auth.py` session signing) to
   reuse that primitive. Keep the token-link entry working (it must still authenticate on first
   use); just don't keep echoing the token in the URL after.
2. If a full cookie-exchange is too large/risky for this scope, the minimal acceptable version is:
   accept the token via an `Authorization`/header path in addition to the query param, and make the
   admin-issued link the only place the query-param form is produced — plus a redirect that strips
   the token. State which you did.
3. Do not weaken the grant's scope/expiry/revocation checks.

**Acceptance:** visiting a valid `?token=` link authenticates, then the browser lands on a URL
without the token (cookie carries the session); an expired/revoked/invalid token still fails; the
grant scope is unchanged. Tests via the real public portal route.

## Task 3 — ISSM-13 / DATA-05: non-breaking finding-vocabulary unification

**Files:** a new `src/ccf/constants.py` (or extend an existing constants module) + the serializers/
rollups that read finding/status values (`src/ccf/analytics/`, assessment/SSP serializers) (+ tests).
No DB enum migration (non-breaking, app-layer only).

**Problem:** "finding" status is modeled 3 ways (AssessmentResult enum {satisfied,
other_than_satisfied, not_applicable}; AssessmentControlResult free String incl. 'not_assessed';
ScoringStatus free String), so cross-table rollups must reconcile vocabularies.

**Requirements:**
1. Define ONE canonical set of finding/status constants + a normalization helper
   (`normalize_finding(value) -> canonical`) that maps the known variants to a single vocabulary.
   Do NOT change the DB columns/enums (that's the breaking part — out of scope); this is an
   app-layer normalization used where rollups/serializers combine the sources.
2. Apply the normalizer where cross-source finding counts are computed (identify the rollup(s) that
   currently union these — analytics/reporting), so a mixed-vocabulary set rolls up consistently.
3. Keep existing per-source behavior; only the combined rollup uses the canonical mapping.

**Acceptance:** a rollup over rows using the different vocabularies produces consistent canonical
counts (e.g. 'other_than_satisfied' and a free-string equivalent count as the same canonical
"finding"); no DB migration; existing tests still pass. Test the normalizer + one rollup.

## Task 4 — FR-14: safe FedRAMP-2026 display labels (fedramp20x surfaces only)

**Files:** `src/ccf/fedramp20x/` display helpers + `src/ccf/api/templates/fedramp20x.html`
(+ tests). No enum/DB change.

**Problem:** FedRAMP CR26 (effective 2026-07-04, enforced 2027-01-01) renames "Authorized"→
"Certified" and "Continuous Monitoring"→"Ongoing Certification". These are FedRAMP-20x-specific
surfaces. (The impact-level→Certification-Class A/B/C/D mapping is NOT included — it needs
primary-source confirmation per the terminology review; do NOT hardcode it.)

**Requirements:**
1. Add a display-label layer for the fedramp20x UI so the underlying status ENUM VALUES stay
   `authorized`/`continuous_monitoring` (no DB change) but render as "Certified" / "Ongoing
   Certification" (with the enum value shown or tooltipped for continuity). Read
   `src/ccf/fedramp20x/__init__.py` (READINESS_STATUSES / DEPENDENCY_STATUSES) and
   `fedramp20x.html` for where the raw values render.
2. Do NOT touch the agency `ato_status` (unchanged by CR26), the generic FISMA baseline selector,
   the platform-wide POA&M feature, or `ccf.governance.conmon` — only the FedRAMP-20x-specific
   display strings.
3. Do NOT add the Certification-Class A/B/C/D mapping (needs primary-source validation) — leave a
   code comment noting it as a follow-up.

**Acceptance:** the fedramp20x UI shows "Certified"/"Ongoing Certification" display labels while the
stored enum values are unchanged; nothing outside fedramp20x surfaces is relabeled. Test the
display mapping.
