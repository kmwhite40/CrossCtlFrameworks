# Flaw Remediation Implementation Plan (CC&E #7)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Measure flaw remediation against a declared timeframe, and organize patching into ordered waves with a recorded completion — without pretending a patch was applied.

**Architecture:** A pure SLA calculation over scan-sourced POA&Ms and a per-org severity→days policy; a campaign of ordered waves whose completion is recorded, optionally referencing an enforcement plan.

**Tech Stack:** Python 3.12, SQLAlchemy 2 async, pytest. One migration.

**Spec:** `docs/superpowers/specs/2026-09-15-flaw-remediation-design.md`

## Global Constraints

- **`unknown` is never folded into a passing bucket.** A POA&M with no
  `identified_on` cannot be shown to have been remediated in time.
- **Only `source='scan'` POA&Ms are measured.** An assessment finding is not a
  flaw, and including it would distort the SI-2 number.
- **The policy measures; it never rewrites a human's `due_on`.** A breach is
  reported, not corrected.
- **No patch execution and no fabricated provider.** A wave records completion
  or references an enforcement plan; nothing pretends a patch was applied.
- **`reconcile_findings` is untouched.** Campaigns read POA&Ms.
- **No scheduler automation.**
- **RLS:** three new tables (`remediation_policies`, `patch_campaigns`,
  `patch_waves`) → guard count **134 → 137**. Waves are parent-chained through
  the campaign, so they carry no `organization_id` — matching
  `control_test_resource_results`.
- **Test database is on port 5434.** `CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5434/ccf_test CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5434/ccf_test`. Never two pytest sessions at once. App-driving scripts need `CCF_ENV=test`.
- Two rows wherever a filter is tested; a direct call wherever a branch is keyed
  on something the HTTP client holds constant (`principal.org_id`,
  `principal.role`).
- `ruff check .` and `mypy src` clean; `alembic heads` shows one.

---

### Task 1: The SLA calculation (pure)

**Files:**
- Create: `src/ccf/patching/__init__.py`, `src/ccf/patching/sla.py`
- Test: `tests/test_patching_sla.py`

**Interfaces:**
- Produces: `FEDRAMP_TIMEFRAMES`, `SLA_BUCKETS`, `RemediationWindow` (severity →
  days), `classify(poam, *, allowed_days, today) -> str`,
  `measure(poams, *, window, today) -> SlaReport`

- [x] **Step 1: Write the failing test.** Table-driven over every bucket and
  both boundaries:

```python
def test_exactly_at_the_limit_is_within_sla() -> None:
    """An organization that says 30 days means 30, not 29."""

def test_one_day_past_the_limit_is_breached() -> None: ...
def test_closed_inside_the_window_is_on_time() -> None: ...
def test_closed_outside_the_window_is_late() -> None: ...

def test_no_identified_on_is_unknown_not_on_time() -> None:
    """Latency is unmeasurable, and counting it as on-time would overstate the
    exact number SI-2 is about."""

def test_closed_with_no_closed_on_is_unknown() -> None:
    """A data-quality signal, never on-time -- the same stance poam_aging takes
    toward a completed POA&M with a null closure date."""

def test_each_severity_uses_its_own_window() -> None: ...
def test_the_fedramp_defaults_are_pinned() -> None:
    assert FEDRAMP_TIMEFRAMES == {"critical": 30, "high": 30, "moderate": 90, "low": 180}

def test_an_assessment_sourced_poam_is_excluded() -> None:
    """It is not a flaw; including it would distort the SI-2 number."""

def test_the_buckets_sum_to_the_input_count() -> None:
    """The invariant that makes the report trustworthy -- nothing is silently
    dropped, the way poam_aging asserts on_track + overdue + no_due_date."""

def test_median_latency_ignores_the_unmeasurable() -> None: ...
def test_an_empty_input_reports_zeroes_not_a_perfect_score() -> None:
    """No findings is not 100% compliance with a remediation timeframe."""
```

- [x] **Step 2: Run it.** Expect `ImportError`.
- [x] **Step 3: Implement.** `classify` takes the already-resolved
  `allowed_days` so it needs no policy lookup; `measure` resolves per severity.
- [x] **Step 4: Run tests. Lint, mypy, commit.**

---

### Task 2: Policy, campaign and wave models + migration 0073

**Files:**
- Create: `src/ccf/models_patching.py`,
  `migrations/versions/0073_flaw_remediation.py`
- Modify: `src/ccf/models.py`, `tests/test_rls_coverage.py`
- Test: `tests/test_patching_models.py`

**Interfaces:**
- `RemediationPolicy(organization_id, critical_days, high_days,
  moderate_days, low_days, source, created_at)`
- `PatchCampaign(organization_id, system_id, name, status, window_start,
  window_end, created_by, created_at, notes)` with `CAMPAIGN_STATUSES`
- `PatchWave(campaign_id, sequence, name, status, poam_ids (JSONB),
  window_start, window_end, completed_at, completed_by, evidence_ref,
  remediation_plan_id, notes)` with `WAVE_STATUSES`

- [x] **Step 1: Write the failing test** — round-trips; policy defaults match
  the FedRAMP numbers at the DB level too; statuses pinned by
  `CheckConstraint`; `(campaign_id, sequence)` unique so two waves cannot claim
  one position; `remediation_plan_id` is `ON DELETE SET NULL` so deleting a
  plan never deletes the record that a wave ran.
- [x] **Step 2: Run it.** Expect `ImportError`.
- [x] **Step 3: Write the models.** Waves carry no `organization_id` —
  parent-chained through the campaign, as `control_test_resource_results` is.
- [x] **Step 4: Bind into `CROSS_MODULE_MODEL_MODULES`.**
- [x] **Step 5: Migration 0073**, `down_revision = "0072_remediation_plans"`.
  Direct policy on the two org-owned tables; parent-chain policy on waves.
- [x] **Step 6: RLS guard 134 → 137. `alembic heads`. Commit.**

---

### Task 3: The campaign service

**Files:**
- Create: `src/ccf/patching/service.py`
- Test: `tests/test_patching_service.py`

**Interfaces:**
- `resolve_window(session, org_id) -> RemediationWindow` (policy row, else defaults)
- `measure_system(session, *, system_id, today) -> SlaReport`
- `create_campaign(session, *, system_id, name, window_start, window_end, actor, wave_size) -> PatchCampaign`
- `complete_wave(session, wave, *, actor, evidence_ref=None, remediation_plan_id=None) -> PatchWave`
- `PatchingError`

- [x] **Step 1: Write the failing test:**

```python
async def test_a_campaign_waves_the_open_scan_findings() -> None:
    """Ordered, smallest first -- the first wave is a canary, and the blast
    radius of a bad patch is bounded by the wave."""
    assert [len(w.poam_ids) for w in waves] == [1, 3, 3]

async def test_a_campaign_with_no_open_findings_is_refused() -> None: ...
async def test_overlapping_windows_on_one_system_are_refused() -> None:
    """Two campaigns patching the same assets in the same window is how a
    maintenance window becomes an outage."""

async def test_a_non_overlapping_window_on_the_same_system_is_allowed() -> None: ...
async def test_another_system_may_be_patched_in_the_same_window() -> None: ...
async def test_completing_a_wave_records_who_when_and_the_evidence() -> None: ...
async def test_completing_a_wave_twice_is_refused() -> None: ...
async def test_completing_out_of_order_is_refused() -> None:
    """Sequencing is the control; a later wave before its canary defeats it."""
async def test_completing_the_last_wave_completes_the_campaign() -> None: ...
async def test_a_wave_may_reference_an_enforcement_plan() -> None:
    """The seam. It is recorded, not executed here."""
async def test_only_this_tenants_findings_are_waved() -> None: ...
async def test_assessment_sourced_poams_are_not_waved() -> None: ...
```

- [x] **Step 2: Run it.** Expect `ImportError`.
- [x] **Step 3: Implement.** Waves are built smallest-first: wave 1 gets one
  POA&M, the rest are split evenly by `wave_size`. Audit every transition
  through `ccf.api.audit.record_event`.
- [x] **Step 4: Run tests. Commit.**

---

### Task 4: API and CLI

**Files:**
- Create: `src/ccf/api/routes/patching.py`
- Modify: `src/ccf/api/main.py`, `src/ccf/cli.py`
- Test: `tests/test_patching_api.py`

**Interfaces:**
- `GET /api/systems/{system_id}/flaw-remediation` — the SLA report
- `GET/PUT /api/remediation-policy` — read and set the org's window
- `POST /api/systems/{system_id}/patch-campaigns`, `GET /api/patch-campaigns`,
  `GET /api/patch-campaigns/{id}`
- `POST /api/patch-waves/{id}/complete`
- `ccf flaw-remediation [--system-id N]` (read-only)

- [x] **Step 1: Write the failing test** — the report; setting a policy changes
  the buckets; creating a campaign; completing a wave is role-gated; another
  tenant's campaign is 404; `organization_id` comes from the principal.
- [x] **Step 2: Run it.** Expect 404s.
- [x] **Step 3: Implement.** Completing a wave is an assertion that work was
  done, so it is role-gated like a waiver approval.
- [x] **Step 4: Run tests + the API suite. Commit.**

---

### Task 5: Verification, mutation testing, demonstration

- [x] **Step 1:** full suite, `ruff check .`, `mypy src`, `bandit -r src -ll -x tests`,
  `alembic heads`.
- [x] **Step 2: Mutate every guard.** At minimum: both SLA boundaries; the
  `unknown` paths; the scan-source filter; the bucket-sum invariant; the
  window-overlap refusal (and its boundary); the empty-campaign refusal; the
  out-of-order and double-completion refusals; the last-wave rollup; both
  `organization_id` filters; the policy-vs-default resolution.
- [x] **Step 3:** Report every ESCAPED honestly.
- [x] **Step 4: Demonstrate** — ingest a scan, show the SLA report breaching on
  two criticals, tighten the policy and show the buckets move, build a campaign
  of three waves, complete them in order, and show the campaign close.
- [x] **Step 5: Commit** with results recorded here.

---

## Results

All five tasks complete. Full suite **2164 passed**, 1 skipped, **zero
failures** — the first fully green run, because this branch is now based on the
analytics-test fix. `ruff check .` and `mypy src` clean, `bandit -r src -ll`
reports no medium or high findings, one migration head
(`0073_flaw_remediation`), RLS guard 134 → 137.

Commits: `5d78ba0` (T1), `b11bcd4` (T2), `f2835f2` (T3), `180b9c9` + `0b63a97`
(T4).

### The demonstration

```
1. AGAINST THE FEDRAMP DEFAULTS      window critical/high 30, moderate 90, low 180
   measured=6  compliance=33.3%  median closed latency=40d
     within_sla 1   breached 2   closed_on_time 1   closed_late 1   unknown 1

2. AFTER TIGHTENING HIGH TO 7 DAYS
   measured=6  compliance=16.7%
     breached 3   closed_on_time 1   closed_late 1   unknown 1

3. A CAMPAIGN OVER THE OPEN FLAWS
   wave 1 (canary) [57]   wave 2 [58, 59]   wave 3 [62]
   completing wave 2 first -> refused: wave 1 is still pending
   completed in order -> campaign completed
```

Tightening one severity moved a finding from `within_sla` to `breached` and
dropped compliance by half, which is the point: the declared timeframe is now a
number the platform measures against rather than a sentence in a document.

### Mutation testing: 31 guards, all caught, none escaped

The first pass reported 30 caught and one `SUSPECT` — my mutation had deleted
the only statement under an `if`, producing an `IndentationError` and a
collection error rather than a result. Re-done as `if False:` so the body
survives, it was caught. **A mutation that does not compile is not a result**,
and the harness's `SUSPECT` bucket is what made that visible instead of it
passing as a catch.

Nothing escaped, which is unusual across these sub-projects and worth
attributing rather than claiming as skill: the lessons accumulated in the
mutation-testing memory were applied up front this time — two rows wherever a
filter is tested, a fabricated scoped `Principal` for every branch keyed on
`principal.org_id` or `principal.role`, and absolute assertions on ordering
rather than comparing two runs.

### Scope: what this is, and what it is not

The brief said "patch orchestration". What is built is the **measurement and
governance** of patching:

- **SI-2 measurement is complete and exact.** The organization-defined
  timeframe existed only as free text in an SSP template; it now has a
  structured home, a FedRAMP default, and a calculation that reports
  `within_sla` / `breached` / `closed_on_time` / `closed_late` / `unknown` with
  the buckets summing to the measured count.
- **Campaigns organize the work** into ordered waves with a window, refusing
  overlaps, empty campaigns, and out-of-order or repeated completion.
- **Nothing applies a patch.** Concord has no endpoint-management provider, and
  two tests assert no route implies one. A wave records completion with
  evidence, or references an enforcement plan when a deployment supplies a
  provider — a seam, not a stub, and the same call made for SCN in #4.

Anyone reading "orchestration" and expecting Concord to push updates to
endpoints will not find that here, and should not: it needs an Intune / SSM /
WSUS connector, which is a separate deployment-specific integration on rails
that now exist.
