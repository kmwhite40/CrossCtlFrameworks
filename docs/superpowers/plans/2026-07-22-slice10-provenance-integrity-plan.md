# Slice 10 — Governance Provenance & Integrity Closure — Plan

Clears the remaining higher-value follow-ups: finding→risk/POA&M provenance (ISSM-04/05)
+ the `risk_accepted`-POA&M gate, external-portal FK integrity (DATA-07/11), the evidence-
store bridge (DATA-09), and decision-support polish (CISO-09/10). Sequential (migrations
chain from head `0047`).

## Global Constraints

- **Test DB:** `PYTHONPATH=src`, `CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5433/ccf_test`,
  `CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5433/ccf_test`.
- **Migrations:** confirm head with `alembic heads`; set `down_revision`; a migration revision id
  must be ≤32 chars (alembic_version.version_num is VARCHAR(32)); verify up→down→up; handle
  existing rows safely (orphans/dupes). New tenant tables/columns follow the RLS pattern where
  applicable.
- **TDD**, production-path tests. `ruff` + `mypy` clean on changed files. **Keep the full suite at
  0 failures** (it is currently 513 passed, 0 failures — do not regress; clean up any global rows a
  test seeds).
- Widened guardrail: run related suites; fix a stale assertion only when your change correctly
  supersedes it; STOP + report a real regression.
- **COMMIT as soon as tests are green, before writing the report.**

## Task 1 — ISSM-04, ISSM-05 (+ risk_accepted-POA&M gate): finding/risk provenance

**Files:** `src/ccf/models.py` / `src/ccf/models_grc.py` (Risk, AuditFinding), routes
(`src/ccf/api/routes/risks.py`, `grc.py`, `assessments.py`), a new migration (+ tests).

**Problem:** (ISSM-05) `risks` has no FK to the originating finding — provenance is a free-text
`source`. (ISSM-04) `audit_findings` has no `poam_id`/`risk_id`/`system_id` link, so audit
findings are orphaned from the remediation program. And a POA&M can be set to `risk_accepted`
via generic PATCH with none of the owner/expiry/approval gate that Risk acceptance requires.

**Requirements:**
1. **Risk provenance (ISSM-05):** add a nullable origin reference to `risks` (e.g.
   `source_ref`/`finding_uid` string, or a real FK to the assessment result / audit finding if
   the id space allows — pick what's clean; read the models). Add a route action that creates a
   Risk *from* a finding (accept-finding → Risk) carrying its origin, OR at minimum let risk
   create/update record the origin ref. A Risk should be traceable back to what generated it.
2. **Audit-finding linkage (ISSM-04):** add nullable `poam_id`/`risk_id` and `system_id` (+ org
   scope if the model lacks it) to `audit_findings`, and a "promote to POA&M" action that opens a
   provenanced POA&M from an audit finding (reuse the assessment→POA&M provenance pattern from
   ISSM-02). Require an evidence/closure artifact for close (it currently closes on a free-text
   string) if cheap.
3. **risk_accepted-POA&M gate:** moving a POA&M to `status='risk_accepted'` must require the same
   owner + expiry (and, auth-on, AO approval) as Risk acceptance — reuse the gate logic from
   `poams.py`/`risks.py` so this parallel path can't bypass it (block 409 otherwise).
4. Migration for the new columns/FKs; verify up→down→up.

**Acceptance:** accepting a finding creates a Risk carrying its origin (visible from the finding);
an audit finding can promote to a provenanced POA&M reachable both ways; a POA&M can't reach
`risk_accepted` without owner+expiry(+approval). Tests cover each.

## Task 2 — DATA-07, DATA-11: external-portal grant foreign keys + width

**Files:** `src/ccf/models_portal.py` (ExternalComment, ExternalQuestionnaireRequest,
ExternalPortalAuditEvent — the `grant_id` columns), a new migration (+ tests).

**Problem:** these three tables' `grant_id` is a plain `BigInteger` with **no FK** (dangling-pointer
risk) and a width mismatch vs `external_access_grants.id` (Integer) (DATA-11).

**Requirements:**
1. Normalize `grant_id` to Integer and add a real FK → `ccf.external_access_grants.id`
   `ON DELETE SET NULL` (these are historical/audit rows — SET NULL, not CASCADE, so the record
   survives if the grant is revoked/deleted). Update the ORM columns.
2. Migration first deletes/repairs orphan rows whose `grant_id` doesn't resolve (or, since SET
   NULL, set the dangling ones to NULL) so the FK can be added; verify up→down→up.

**Acceptance:** inserting one of these rows with a non-existent `grant_id` fails (or is nulled per
SET NULL semantics on delete); deleting a grant nulls the reference rather than dangling. Tests
assert the FK behavior.

## Task 3 — DATA-09: bridge the two evidence stores

**Files:** `src/ccf/models_evidence.py` (EvidenceObject) and/or `src/ccf/models.py` (Evidence), a
new migration (+ tests).

**Problem:** the legacy control-linked `Evidence` (FK to control_implementations) and the versioned
`EvidenceObject`/`EvidenceVersion` repository (confidence/review/retention) are two parallel stores
with NO link, so "evidence supporting control X" and its trustworthiness can't be answered
consistently. `evidence_objects.control_id` is a free-text tag, not an FK.

**Requirements:**
1. Add a real linkage so a control-linked evidence item resolves to its confidence/review state:
   the cleanest minimal bridge — add a nullable `implementation_id` FK on `evidence_objects` (→
   `control_implementations`), OR a nullable FK from the legacy `Evidence` to `evidence_objects`.
   Pick whichever matches how the repository is actually populated (read the evidence service). Do
   NOT merge the two models — just make control→evidence→confidence a traceable join.
2. Migration for the FK (nullable — existing rows stay unlinked); verify up→down→up.
3. Optionally expose the linkage in the control/evidence serializer if cheap.

**Acceptance:** a control-linked evidence item can be joined to a confidence score via the new FK;
the join has no fabricated linkage (nullable, backfilled only where a real relationship exists).
Tests assert the bridge resolves for a linked item and is null for an unlinked one.

## Task 4 — CISO-09, CISO-10: leadership decision-support polish

**Files:** `src/ccf/analytics/posture.py` (org_summary), `src/ccf/reporting/export.py`,
`src/ccf/api/routes/reports.py` (+ tests).

**Problem:** (CISO-09) `avg_sprs_score` is a mushy average that masks a failing system — leadership
should see the worst. (CISO-10) the exported "compliance report" is a control catalog with no
POA&M/risk posture (can't be reconciled to the dashboard) and no AI/last-editor provenance column.

**Requirements:**
1. Add `min_sprs_score` / worst-system to `org_summary` alongside the average (surface the lowest-
   scoring assessed system), so leadership sees the weakest system, not just the mean. No schema
   change.
2. Add a POA&M/risk posture summary section to the report export, reconciled to `org_summary`
   (same numbers as the dashboard for the same scope), and — where implementation_status can be
   AI-sourced — an AI/last-editor provenance indicator column (reuse the CISO-02 provenance
   signal). Keep the existing export formats (xlsx/docx/csv) working.

**Acceptance:** `org_summary` exposes the worst/min SPRS; the export includes a risk/POA&M summary
whose numbers equal the dashboard's for the same scope, and flags AI-sourced rows. Tests assert the
worst-SPRS value and the export summary reconciliation.
