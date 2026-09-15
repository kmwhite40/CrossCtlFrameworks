# Resource Drift and Retention Implementation Plan (P2c / CC&E #2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Read the append-only resource history deliberately — as current state, as drift, as a timeline — and bound its growth without losing the series.

**Architecture:** One definition of "latest result per test" shared by every current-state read; a pure `diff_resources` for transitions; two read endpoints; and an explicit prune that windows per-resource detail while keeping every `ControlTestResult`.

**Tech Stack:** Python 3.12, SQLAlchemy 2 async, pytest + pytest-asyncio. No migration — everything reads `0068`'s rows.

**Spec:** `docs/superpowers/specs/2026-09-15-resource-drift-design.md`

## Global Constraints

- **No new tables and no migration.** If a task seems to need one, stop: the
  spec says the data already exists.
- **"Latest" is defined once** (`latest_result_ids`) and every current-state
  read joins it. A second definition is the bug this sub-project is fixing.
- **`MAX(id)`, not `run_at`.** Two scans in the same second tie on `run_at`.
- **Classification keys on `REQUIRES_COVER`** from `governance/waivers.py`, not
  a second verdict list.
- **`fail` → `not_applicable` is not a recovery.** Asserting recovery from an
  excluded verdict would claim a weakness cleared that was never re-observed.
- **Retention keeps every `ControlTestResult`** and prunes only resource rows,
  never the latest result's rows at any age, and never a row with a
  `waiver_id`.
- **Pruning is never automatic.** No scheduler wiring in this sub-project.
- **`record_result`, `_alert_on_failure`, recovery, and
  `ControlTest.last_status` are untouched.**
- **Test database is on port 5434.** `CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5434/ccf_test CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5434/ccf_test`. Never run two pytest sessions at once. Scripts driving the app need `CCF_ENV=test`.
- `ruff check src tests` and `mypy src` must be clean; `alembic heads` must show exactly one (`0070_waivers`).

---

### Task 1: `diff_resources` — the pure transition classifier

**Files:**
- Create: `src/ccf/posture/drift.py`
- Test: `tests/test_posture_drift.py`

**Interfaces:**
- Produces: `ResourceTransition` (frozen: `resource_id`, `kind`, `before`,
  `after`, `observed`), `TRANSITION_KINDS`,
  `diff_resources(before, after) -> list[ResourceTransition]`

- [ ] **Step 1: Write the failing test.** Table-driven over every kind, and
  the classifications that must be explicit rather than incidental:

```python
def test_a_pass_to_fail_is_a_regression() -> None: ...
def test_a_fail_to_pass_is_a_recovery() -> None: ...
def test_a_new_resource_is_an_appearance_not_a_regression() -> None:
    """When the weakness began is a different fact from that it exists."""
def test_a_vanished_resource_is_a_disappearance() -> None:
    """Nothing in the platform notices this today; a truncated collection
    currently looks like an improvement."""
def test_the_same_verdict_with_new_observed_text_is_changed() -> None:
    """A resource failing for a new reason is still news."""
def test_an_unchanged_resource_produces_no_transition() -> None: ...
def test_fail_to_not_applicable_is_not_a_recovery() -> None:
    """It asserts a weakness cleared that was never re-observed."""
def test_not_applicable_to_fail_is_a_regression() -> None:
    """Explicit by choice: the resource now needs cover and did not before."""
def test_warn_to_fail_is_a_regression_not_unchanged() -> None:
    """Both need cover, but the posture got worse."""
def test_fail_to_warn_is_reported_not_silent() -> None: ...
def test_transitions_are_sorted_by_resource_id() -> None:
    """Regenerating a drift report must not reorder it."""
def test_both_sides_empty_yields_nothing() -> None: ...
```

- [ ] **Step 2: Run it.** Expect `ImportError`.
- [ ] **Step 3: Implement.** Index both sides by `resource_id`; walk the union
  of keys sorted; classify. Import `REQUIRES_COVER` from
  `ccf.governance.waivers`.
- [ ] **Step 4: Run tests. Lint, mypy, commit.**

---

### Task 2: One definition of "latest", and the `/failing-resources` fix

The bug comes second only because Task 1 is pure; it is the task that matters
most.

**Files:**
- Create: `src/ccf/posture/latest.py`
- Modify: `src/ccf/api/routes/posture.py`
- Test: `tests/test_posture_failing_resources.py`

**Interfaces:**
- Produces: `latest_result_ids() -> Select` (rows of
  `(control_test_id, result_id)`)

- [ ] **Step 1: Write the failing test.** The regression test and its
  companion, because a fix that returns nothing would satisfy the first alone:

```python
async def test_a_resource_fixed_in_the_latest_scan_is_not_reported_failing() -> None:
    """The bug. Verified against the shipped endpoint before the fix."""
    ...
    assert mine == []


async def test_a_resource_still_failing_in_the_latest_scan_is_reported() -> None:
    """The companion. Without it, "return nothing" passes the test above."""
    ...
    assert [r["resource_id"] for r in mine] == ["still-broken@acme.gov"]


async def test_the_observed_text_comes_from_the_latest_scan() -> None:
    """Stale observed text is what makes a stale row actively misleading."""
    ...
    assert mine[0]["observed"] == "second scan: still no MFA"


async def test_a_resource_failing_on_one_test_and_passing_another_is_reported_once() -> None:
    """Latest is per test, not per resource -- two checks on one resource are
    two independent judgements."""


async def test_another_tenants_failing_resource_is_not_returned() -> None:
    """The existing org filter must survive the rewrite."""
```

- [ ] **Step 2: Run it.** Expect the first test to FAIL (the bug) and the
  second to pass.
- [ ] **Step 3: Implement `latest_result_ids`:**

```python
def latest_result_ids() -> Select:
    """``(control_test_id, result_id)`` for the most recent result per test.

    ``MAX(id)`` rather than ``MAX(run_at)``: two scans in the same second tie
    on ``run_at``, and a tie makes "latest" ambiguous -- which is how an
    append-only table came to be read as current state in the first place.
    """
    return (
        select(
            ControlTestResult.control_test_id.label("control_test_id"),
            func.max(ControlTestResult.id).label("result_id"),
        )
        .group_by(ControlTestResult.control_test_id)
        .subquery()
    )
```

- [ ] **Step 4: Join it in `failing_resources`** and correct the docstring to
  say what it now does.
- [ ] **Step 5: Run the new tests plus `tests/test_posture_api.py`** — the
  existing posture API tests must pass unedited unless one of them asserted
  the buggy behaviour, in which case **fix the test and say so in the commit**.
- [ ] **Step 6: Commit.**

---

### Task 3: The drift and timeline reads

**Files:**
- Modify: `src/ccf/posture/drift.py`, `src/ccf/api/routes/posture.py`
- Test: `tests/test_posture_drift_api.py`

**Interfaces:**
- Produces:
  - `async latest_drift(session, *, test_id: int) -> list[ResourceTransition]`
  - `async resource_timeline(session, *, test_id: int, resource_id: str, limit: int = 50) -> list[dict]`
  - `GET /api/control-tests/{test_id}/drift`
  - `GET /api/control-tests/{test_id}/resources/{resource_id}/timeline`

- [ ] **Step 1: Write the failing test** — drift between the two most recent
  results reports each kind; a test with only one result reports **no drift
  rather than everything appeared** (there is no baseline, and inventing one
  would report a first scan as wholesale change); an unknown test is 404;
  another tenant's test is 404 (never confirm existence); the timeline is
  newest-first and carries `waiver_id`.
- [ ] **Step 2: Run it.** Expect 404s.
- [ ] **Step 3: Implement** the two queries, then the two endpoints following
  `result_resources`' existing ownership check.
- [ ] **Step 4: Run tests. Commit.**

---

### Task 4: Retention

**Files:**
- Create: `src/ccf/posture/retention.py`
- Modify: `src/ccf/config.py`, `src/ccf/cli.py`
- Test: `tests/test_posture_retention.py`

**Interfaces:**
- Produces: `async prune_resource_detail(session, *, retain_days: int | None = None, dry_run: bool = False) -> dict[str, int]`;
  setting `posture_resource_retention_days: int = 400`;
  `ccf posture-prune [--retain-days N] [--dry-run]`

- [ ] **Step 1: Write the failing test:**

```python
async def test_rows_inside_the_window_survive() -> None: ...
async def test_rows_outside_the_window_are_deleted() -> None: ...
async def test_the_latest_results_rows_survive_at_any_age() -> None:
    """A check that last ran 18 months ago must still say which resources
    failed, or "3 of 47" becomes unexplainable."""
async def test_a_waived_row_survives_at_any_age() -> None:
    """It is the record of which resource an acceptance covered -- the audit
    question a waiver exists to answer."""
async def test_no_control_test_result_is_ever_deleted() -> None:
    """The aggregate series is what an authorization package draws on."""
async def test_dry_run_deletes_nothing_and_reports_the_same_count() -> None:
    """An operator must be able to see the blast radius first."""
async def test_pruning_twice_is_idempotent() -> None: ...
async def test_another_tenants_rows_are_not_pruned_by_a_scoped_call() -> None:
    """If a per-org prune is offered it must be scoped; if not, assert the
    whole-deployment contract explicitly rather than leaving it implied."""
```

- [ ] **Step 2: Run it.** Expect `ImportError`.
- [ ] **Step 3: Implement.** Delete `ControlTestResourceResult` where the
  parent result's `run_at < cutoff`, **excluding** result ids in
  `latest_result_ids()` and rows with a non-null `waiver_id`. Return counts.
- [ ] **Step 4: Add the setting and the CLI command**, following an existing
  `ccf` command's shape.
- [ ] **Step 5: Run tests. Commit.**

---

### Task 5: Verification, mutation testing, demonstration

- [ ] **Step 1:** full suite, `ruff check src tests`, `mypy src`,
  `alembic heads`. Only the known
  `test_dashboard_overview_sla_excludes_no_due_date_from_on_track` failure.
- [ ] **Step 2: Mutate every guard.** At minimum: each of the five transition
  classifications; the `REQUIRES_COVER` keying; the sort; the
  single-result no-drift guard; the `latest_result_ids` join in
  `failing_resources`; the org filter there; `MAX(id)` → `MIN(id)`; the
  retention cutoff comparison; the latest-result exemption; the waiver-id
  exemption; the dry-run guard. Harness invariants: assert the perl-alarm
  watchdog, hash the files, **key backups by full path**, restore on a trap.
- [ ] **Step 3:** Report every ESCAPED honestly. For each, ask whether the
  fixture could express the bug, and whether the guard is redundant — both
  have been the answer before.
- [ ] **Step 4: Demonstrate** — three scans over one check where a resource
  regresses, one recovers, one appears and one disappears; print the drift
  report and one resource's timeline; then prune with a short window and show
  the aggregate series intact and the latest detail retained.
- [ ] **Step 5: Commit**, recording results, the mutation outcome, and the
  bug's before/after in the plan.
