# Config-Change Impact and Drift Telemetry Implementation Plan (CC&E #6, #11)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Say what a desired-state change would affect before it is adopted, and count drift and suppression so the signal is observable.

**Architecture:** `packs/impact.py` follows `catalog/impact.py`'s shape over a `PostureRuleDiff`; metrics are defined in `api/metrics.py` and incremented at write time from `scan_for_system`, `record_result` and `prune_resource_detail`.

**Tech Stack:** Python 3.12, SQLAlchemy 2 async, prometheus_client, pytest. No migration.

**Spec:** `docs/superpowers/specs/2026-09-15-config-change-impact-and-telemetry-design.md`

## Global Constraints

- **No new tables, no migration.** Both parts read existing rows.
- **Impact is read-only.** It computes for review and applies nothing — the
  same contract `AdoptionImpact` has.
- **An unknown baseline yields an empty impact with a stated reason**, never a
  speculative one. `packs/diff.py` already refuses to guess from missing
  history; impact must not undo that.
- **No `resource_id` or `check_key` label on any metric.** A structural test
  asserts it, so a later addition cannot break the cardinality rule.
- **Drift is counted during a scan, never in a read.** A counter incremented
  by a read double-counts dashboard refreshes.
- **Instrumentation cannot break what it measures.** Every increment is
  guarded; a metrics failure must not fail a scan or lose a recorded result.
- **Tenant scoping:** impact takes an `org_id` and never reports another
  tenant's checks or waivers.
- **Test database is on port 5434.** `CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5434/ccf_test CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5434/ccf_test`. Never run two pytest sessions at once. Scripts driving the app need `CCF_ENV=test`.
- `ruff check src tests` and `mypy src` clean; `alembic heads` shows exactly one (`0070_waivers`).

---

### Task 1: `build_config_change_impact`

**Files:**
- Create: `src/ccf/packs/impact.py`
- Test: `tests/test_packs_impact.py`

**Interfaces:**
- Consumes: `PostureRuleDiff` (`packs/diff.py`), `capabilities_for_control`
  (`capability/service.py`), `checks_for` (`posture/checks.py`)
- Produces: `ConfigChangeImpact`,
  `async build_config_change_impact(session, *, org_id: int | None, diff: PostureRuleDiff) -> ConfigChangeImpact`

- [ ] **Step 1: Write the failing test:**

```python
async def test_an_added_rule_reports_the_controls_it_would_evidence() -> None: ...
async def test_a_changed_rule_reports_its_controls() -> None: ...
async def test_a_removed_rule_reports_the_check_it_would_retire() -> None:
    """With its current status: retiring a failing check is a different
    decision from retiring a passing one."""
    ...
    assert impact.checks_retired[0]["last_status"] == "fail"
async def test_a_removed_rule_reports_a_waiver_left_orphaned() -> None:
    """A waiver keyed on check_key survives removal of the check it accepts --
    a formal acceptance of a finding that can no longer be produced."""
async def test_an_added_rule_orphans_no_waiver() -> None: ...
async def test_capabilities_covering_an_affected_control_are_reported() -> None:
    """A rule change reaches authored SSP prose through the capability."""
async def test_an_unknown_baseline_yields_an_empty_impact_with_a_reason() -> None:
    assert impact.is_empty()
    assert impact.reason == "no retained manifest to compare"
async def test_another_tenants_check_is_not_reported_as_retiring() -> None: ...
async def test_another_tenants_waiver_is_not_reported_as_orphaned() -> None: ...
async def test_a_form_a_rule_inherits_the_platform_checks_controls() -> None:
    """A parameterized rule restates no control ids; the evaluator's apply."""
async def test_an_empty_diff_is_an_empty_impact() -> None: ...
```

- [ ] **Step 2: Run it.** Expect `ImportError`.
- [ ] **Step 3: Implement.** Resolve each changed rule key to its control ids —
  Form B from `definition["control_ids"]`, Form A from the named platform
  check. Then: capabilities per control, `ControlTest` rows whose `check_key`
  matches a removed key (scoped to `org_id`), and `Waiver` rows whose
  `check_key` matches a removed key (scoped to `org_id`).
- [ ] **Step 4: Run tests. Lint, mypy, commit.**

---

### Task 2: The impact endpoint

**Files:**
- Modify: `src/ccf/api/routes/packs.py`
- Test: `tests/test_packs_impact_api.py`

- [ ] **Step 1: Write the failing test** — `GET /api/packs/{pack_key}/impact`
  with `from_version`/`to_version` returns the impact; an unknown pack is 404;
  an unknown version is 404 naming which; omitting `from_version` compares the
  two most recent versions; another tenant's pack is 404.
- [ ] **Step 2: Run it.** Expect 404 on the route itself.
- [ ] **Step 3: Implement**, loading the two `CompliancePackVersion` rows,
  diffing their manifests, and passing the diff to
  `build_config_change_impact`.
- [ ] **Step 4: Run tests + the packs API suite. Commit.**

---

### Task 3: The metrics

**Files:**
- Modify: `src/ccf/api/metrics.py`, `src/ccf/posture/scan.py`,
  `src/ccf/governance/control_tests.py`, `src/ccf/posture/retention.py`
- Test: `tests/test_posture_metrics.py`

**Interfaces:**
- Produces: `POSTURE_CHECK_RESULTS`, `POSTURE_DRIFT_TRANSITIONS`,
  `WAIVER_SUPPRESSIONS`, `POSTURE_DETAIL_PRUNED`, `POSTURE_FAILING_RESOURCES`

- [ ] **Step 1: Write the failing test:**

```python
def test_no_posture_metric_carries_a_resource_or_check_label() -> None:
    """Structural, so a later addition cannot break the cardinality rule: a
    fleet of 10,000 users would put 10,000 series into Prometheus."""
    for metric in POSTURE_METRICS:
        labels = set(metric._labelnames)
        assert not (labels & {"resource_id", "resource", "check", "check_key"})


async def test_a_scan_counts_one_result_per_check_by_verdict() -> None: ...
async def test_a_scan_counts_drift_transitions_by_kind() -> None: ...
async def test_a_first_scan_counts_no_drift() -> None:
    """There is no baseline, so there is nothing to count."""
async def test_a_suppressed_finding_increments_the_waiver_counter() -> None: ...
async def test_an_unsuppressed_failure_does_not() -> None: ...
async def test_pruning_counts_the_rows_it_deleted() -> None: ...
async def test_a_dry_run_counts_nothing() -> None:
    """It deleted nothing, so reporting deletions would be a lie in a graph."""
async def test_the_failing_gauge_reflects_the_latest_scan() -> None: ...
async def test_a_failing_metrics_call_does_not_fail_a_scan() -> None:
    """Monkeypatch an increment to raise; the scan must still record."""
```

- [ ] **Step 2: Run it.** Expect `ImportError`.
- [ ] **Step 3: Define the metrics** in `api/metrics.py` with a
  `POSTURE_METRICS` tuple so the structural test has something to enumerate.
- [ ] **Step 4: Increment them**, each behind a guard, with local imports
  (`# noqa: PLC0415`) exactly as `fedramp20x/monitoring.py` does:

```python
def _observe(fn: Callable[[], None]) -> None:
    """Telemetry must never break what it measures."""
    try:
        fn()
    except Exception as e:  # pragma: no cover - defensive
        log.warning("posture.metrics_failed", error=str(e)[:200])
```

- [ ] **Step 5: Run the new tests plus the posture, waiver and retention
  suites.** All pre-existing tests unedited.
- [ ] **Step 6: Commit.**

---

### Task 4: Verification, mutation testing, demonstration

- [ ] **Step 1:** full suite, `ruff check src tests`, `mypy src`,
  `alembic heads`. Only the known
  `test_dashboard_overview_sla_excludes_no_due_date_from_on_track` failure.
- [ ] **Step 2: Mutate every guard.** At minimum: the Form A control-id
  inheritance; the removed-key filter for checks and for waivers; both
  `org_id` filters; the unknown-baseline guard; each metric increment; the
  dry-run guard on the prune counter; the `_observe` guard; the
  no-drift-on-first-scan path.
- [ ] **Step 3:** Report every ESCAPED honestly. Ask of each: could the fixture
  express the bug, and is the guard redundant?
- [ ] **Step 4: Demonstrate** — tighten a pack's threshold and remove a rule
  that has a waiver, print the impact, then run two scans and print the
  resulting metric samples.
- [ ] **Step 5: Commit** with results recorded in this plan.
