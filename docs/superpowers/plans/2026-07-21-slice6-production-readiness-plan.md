# Slice 6 — Production Readiness (CISO aggregation + go/no-go) — Implementation Plan

Fixes the code-level CISO findings (decision-support accuracy) from the register, then
the controller issues the consolidated production-readiness recommendation. Tasks run
**sequentially** (analytics files overlap). No new migration expected.

## Global Constraints

- **Test DB:** `PYTHONPATH=src`, `CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5433/ccf_test`,
  `CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5433/ccf_test`.
- **TDD**, production-path tests (assert on the real aggregation functions / real records).
- Reuse existing status/enum vocabularies. `ruff` + `mypy` clean on changed files.
- Widened guardrail: run related suites; fix a stale assertion only when your change
  correctly supersedes it; STOP + report a real regression. The only acceptable full-suite
  failure is the known-flaky `test_enterprise.py::test_audit_chain_verifies_and_detects_tampering`
  (passes in isolation).
- Do not weaken existing tests. Keep the full suite deterministic (no leaked global rows).

## Task 1 — CISO-04: `/readyz` must reflect the reliability checks

**Files:** `src/ccf/api/routes/health.py` (+ tests).

**Problem:** `/readyz` runs only `SELECT 1`, so a container with auth disabled or pending
migrations reports "ready" and gets put in rotation.

**Requirements:**
1. Have `/readyz` run the BLOCKING reliability checks (read `src/ccf/reliability/checks.py`
   — use the existing check suite; determine which checks are "blocking" e.g. migrations
   drift, auth posture, RLS) and return **503** with a JSON body listing the failing checks
   when any blocking check FAILs; **200** when all pass.
2. Keep `/healthz` (liveness) as the cheap `SELECT 1`-style probe — do not make liveness
   depend on the full suite (that would cause restart loops). Only `/readyz` gates rotation.
3. Do not slow `/readyz` unreasonably; if the reliability suite is expensive, run only the
   blocking subset.

**Acceptance:** with a FAILing blocking reliability check, `/readyz` returns 503 and names
it; with all passing, 200. `/healthz` still returns 200 cheaply. Tests cover both.

## Task 2 — CISO-01 & CISO-06: residual-risk visibility + honest overdue counting

**Files:** `src/ccf/analytics/posture.py`, `src/ccf/analytics/overview.py` (+ tests).

**Problem:** (CISO-01) risk-accepted/completed POA&Ms are excluded from every metric —
`open` is hard-coded to `("open","in_progress")` and MTTR only counts `closed_on` — so a
`risk_accepted`/`completed`-without-`closed_on` POA&M appears in NO metric; there is no
residual/accepted bucket. (CISO-06) overdue keys only on `due_on`, so a POA&M tracked via
`scheduled_completion` with null `due_on` is silently counted "on track", inflating the
on-track %.

**Requirements:**
1. Add an explicit **accepted/residual** bucket to the POA&M aging/posture output and
   surface it (count of `risk_accepted` — verify the exact enum value) so leadership sees
   residual risk; a `completed` POA&M with a null `closed_on` should be a visible
   data-quality signal, not invisible.
2. Overdue: fall back to `scheduled_completion` (or `original_due_on` — read the model) when
   `due_on` is null; add a **"no due date"** bucket that is EXCLUDED from `on_track` so
   `on_track + overdue + no_due_date == open_total` and nothing is defaulted to on-track.
3. Keep existing dashboard fields working; add the new buckets without breaking consumers.

**Acceptance:** a `risk_accepted` POA&M is counted in a residual bucket somewhere; a null-due
open POA&M lands in "no due date", not "on track"; the aging buckets sum to the open total.
Tests assert on the real posture/overview functions.

## Task 3 — CISO-05 & CISO-11: reconcile dashboard populations + defense-in-depth org scope

**Files:** `src/ccf/analytics/overview.py`, `src/ccf/analytics/posture.py` (+ tests).

**Problem:** (CISO-05) the risk heatmap (`_risk_by_band`, excludes only `closed`) and the
risk-status counts (`org_summary.risks_by_status`, counts ALL incl. closed) use different
populations on the same dashboard; several `_block` functions ignore `org_id` and query
globally, relying entirely on RLS. (CISO-11) `findings_by_severity` iterates a fixed
severity list over POA&M-only data, so any out-of-vocabulary severity is dropped and the
chart can diverge from the headline total.

**Requirements:**
1. Make the risk heatmap and the risk-status breakdown agree on population (pick one
   consistent rule — e.g. both exclude `closed`, or both include it and label clearly) so
   the two risk views on the dashboard reconcile.
2. Thread `org_id` through the dashboard `_block` functions that currently query globally
   (defense-in-depth beyond RLS) — a scoped dashboard must be provably org-filtered in the
   query, not only via RLS. (Verify how `dashboard_overview` receives `org_id`.)
3. `findings_by_severity`: compute from the same rows as the headline findings total with a
   catch-all "other" bucket so `sum(findings_by_severity) == findings_total` for any data.

**Acceptance:** the heatmap open-risk total reconciles to the status breakdown; a scoped
dashboard query is org-filtered without relying on RLS; the severity chart sums to the
total. Tests assert reconciliation on real records.

## Task 4 — CISO-08: CI supply-chain gate

**Files:** `.github/workflows/ci.yml`.

**Problem:** `pip-audit --strict || true` never fails the build, and pytest runs without
applying migrations first (relies on fixtures).

**Requirements:**
1. Make dependency vulnerabilities gate the build: drop the `|| true` from `pip-audit`
   (or, if a known-unfixable advisory exists, add an explicit `--ignore-vuln <ID>` allowlist
   with a comment — do NOT blanket-ignore). Keep the existing Trivy gate.
2. Apply migrations before pytest in the quality job if the tests need a migrated DB (check
   whether CI's pytest currently migrates; the conftest `clean_migrated_db` runs
   base→head, so this may already be covered — verify and only add if genuinely missing).
3. Do not break the existing CI matrix/steps; this is a workflow-hardening change only.

**Acceptance:** a seeded vulnerable dependency would fail CI (pip-audit non-zero fails the
job); the change is minimal and documented. (No runtime test — this is CI config; verify by
reading the workflow and confirming the gate is now blocking.)
