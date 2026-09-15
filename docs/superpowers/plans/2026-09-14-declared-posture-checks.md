# Declared Posture Checks Implementation Plan (P2b / CC&E #1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A tenant can declare a posture check in a pack manifest and have the existing posture runtime evaluate it — giving `PackRule` its first reader.

**Architecture:** Two rule forms (spec §2). Form A names a platform evaluator and supplies parameters; Form B supplies a closed, fail-closed predicate. A pure `posture/declared.py` evaluates Form B; `posture/resolve.py` merges platform checks with a tenant's declared ones into `ResolvedCheck`, which `connectors/msgraph.scan()` iterates instead of `m365.CHECKS`.

**Tech Stack:** Python 3.12, SQLAlchemy 2 async, pytest + pytest-asyncio. One migration (Task 6 only).

**Spec:** `docs/superpowers/specs/2026-09-14-declared-posture-checks-design.md`

## Global Constraints

- **A check that cannot be evaluated never reports `pass`.** Missing path, wrong
  type, unreadable collection → `manual_review_required` naming the reason.
  Asserting `pass` about something never observed is the one unrecoverable
  failure mode in an authorization package.
- **Fail closed at install, not at scan.** An unknown `op`/`mode`, a malformed
  path, or a missing required key is a `validate_manifest` error. A pack that
  installs must be evaluable.
- **A colliding check key is an install error**, never an override in either
  direction (spec §4).
- **Platform behaviour is byte-identical.** Re-expressing `mfa_registered` and
  `legacy_auth_blocked` as Form B must produce findings identical to the
  hand-written evaluators over the same rows (Task 1 Step 6). Existing posture
  tests must pass unedited.
- **No new findings table, scheduler, manifest format, or verdict.** Results go
  through `record_result`; verdicts stay within `VALIDATION_STATUSES`.
- **`posture/declared.py` stays pure** — no DB, no network, no clock. `now` is a
  parameter, as in `providers/m365.py`.
- **Test database is on port 5434.** `CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5434/ccf_test CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5434/ccf_test`. Never run two pytest sessions at once.
- `ruff check src tests` and `mypy src` must be clean.

---

### Task 1: The predicate evaluator (pure)

**Files:**
- Create: `src/ccf/posture/declared.py`
- Test: `tests/test_posture_declared.py`

**Interfaces:**
- Produces:
  - `PredicateError(ValueError)`
  - `resolve_path(row: dict, path: str) -> Any` — dotted traversal, missing → `None`
  - `evaluate_predicate(predicate: dict, row: dict) -> bool | None` — `None` = undeterminable
  - `evaluate_declared(spec: DeclaredSpec, rows: list[dict]) -> list[ResourceFinding]`
  - `DeclaredSpec` (frozen dataclass): `mode`, `resource_type`, `resource_id_field`, `predicate`, `expected`, `pass_observed`, `fail_observed`
  - `OPS: frozenset[str]`, `MODES: frozenset[str]`

- [ ] **Step 1: Write the failing test** — table-driven over `resolve_path`,
  every op, both modes, and every fail-closed path. Key cases that must be
  present, because each is a way to wrongly report `pass`:

```python
def test_a_missing_path_is_undeterminable_not_false() -> None:
    assert evaluate_predicate({"op": "truthy", "path": "absent"}, {}) is None


def test_an_undeterminable_row_is_manual_review_not_pass() -> None:
    findings = evaluate_declared(_spec(predicate={"op": "truthy", "path": "absent"}), [{"id": "u1"}])
    assert [f.verdict for f in findings] == ["manual_review_required"]
    assert "absent" in findings[0].observed


def test_any_row_mode_with_no_matching_row_fails_once() -> None:
    findings = evaluate_declared(_spec(mode="any_row", predicate={"op": "equals", "path": "state", "value": "enabled"}),
                                 [{"state": "disabled"}, {"state": "reportOnly"}])
    assert len(findings) == 1 and findings[0].verdict == "fail"


def test_contains_on_a_non_list_is_undeterminable() -> None:
    """A string "contains" a substring; treating that as list membership is how
    a check silently passes."""
    assert evaluate_predicate({"op": "contains", "path": "x", "value": "block"}, {"x": "blocked"}) is None


def test_an_unknown_op_raises_rather_than_returning_false() -> None:
    with pytest.raises(PredicateError):
        evaluate_predicate({"op": "matches_regex", "path": "x", "value": "y"}, {"x": "y"})
```

- [ ] **Step 2: Run it** — `pytest tests/test_posture_declared.py -v`. Expect
  `ImportError`.
- [ ] **Step 3: Implement `resolve_path` + `evaluate_predicate`** — ops
  `truthy`, `falsy`, `equals`, `not_equals`, `contains`, `intersects`,
  `all_of`, `any_of`. Return `None` wherever the row cannot answer; raise
  `PredicateError` on an unknown op (install-time validation is what prevents
  this reaching a scan).
- [ ] **Step 4: Implement `evaluate_declared`** — `per_resource` maps each row
  to one finding (`True`→pass, `False`→fail, `None`→`manual_review_required`);
  `any_row` returns exactly one finding, `pass` on the first `True`, and
  `manual_review_required` when no row was determinable at all.
- [ ] **Step 5: Run tests** — all pass.
- [ ] **Step 6: The golden equivalence test** — re-express `MFA_REGISTERED` and
  `LEGACY_AUTH_BLOCKED` as `DeclaredSpec`s and assert the findings equal the
  hand-written evaluators' output over the same recorded rows:

```python
def test_declared_form_reproduces_the_platform_mfa_check() -> None:
    rows = [{"userPrincipalName": "a@x.gov", "isMfaRegistered": True},
            {"userPrincipalName": "b@x.gov", "isMfaRegistered": False}]
    hand = m365.evaluate_mfa_registered(rows)
    declared = evaluate_declared(MFA_AS_DECLARED, rows)
    assert [(f.resource_id, f.verdict) for f in declared] == [(f.resource_id, f.verdict) for f in hand]
```

  `detail` legitimately differs (the hand-written check records `userType`/
  `isAdmin`); assert on `(resource_id, verdict)` and state that in the test
  docstring. **If the declarative form cannot reproduce these two, the form is
  wrong — stop and revise the spec rather than weakening the test.**
- [ ] **Step 7: Lint, mypy, commit.**

---

### Task 2: Parameterized platform evaluators (Form A)

**Files:**
- Modify: `src/ccf/posture/providers/m365.py`
- Create: `src/ccf/posture/parameters.py`
- Test: `tests/test_posture_parameters.py`

**Interfaces:**
- Produces: `PARAMETERIZABLE: dict[str, tuple[str, ...]]` (evaluator key →
  accepted parameter names); `evaluate_stale_accounts(rows, *, now, threshold_days=STALE_ACCOUNT_DAYS)`

- [ ] **Step 1: Failing test** — a 60-day threshold fails an account idle 75
  days that the 90-day default passes; an unknown parameter name is rejected;
  the default call is unchanged (byte-identical findings to before).
- [ ] **Step 2: Run** — expect `TypeError: unexpected keyword argument`.
- [ ] **Step 3: Add the keyword** with the module constant as default, and
  update the `expected` text to interpolate the threshold actually used —
  otherwise a 60-day check renders prose claiming 90.
- [ ] **Step 4: Declare `PARAMETERIZABLE`** so validation can reject an unknown
  parameter at install rather than `TypeError` at scan.
- [ ] **Step 5: Run existing posture tests** — `tests/test_posture*.py` unedited.
- [ ] **Step 6: Commit.**

---

### Task 3: Manifest validation for posture rules

**Files:**
- Modify: `src/ccf/packs/catalog.py`
- Test: `tests/test_packs_posture_validation.py`

**Interfaces:**
- Produces: `validate_posture_rule(definition: dict, *, platform_keys: frozenset[str]) -> list[str]`,
  called from `validate_manifest` for every rule with `kind == "posture"`

- [ ] **Step 1: Failing test** — one case per error: missing `evaluator` and
  `predicate` (exactly one required), both supplied, unknown evaluator, unknown
  parameter, unknown `op`, unknown `mode`, missing `endpoint` on Form B, missing
  `control_ids`, a control id that does not canonicalize, and a key colliding
  with a platform check. Each asserts the specific message, because a
  fail-closed validator that reports the wrong reason is unusable.
- [ ] **Step 2: Run** — expect `ImportError`.
- [ ] **Step 3: Implement**, reusing `catalog.canonical.canonicalize` for
  control ids and `posture.declared.OPS`/`MODES` and
  `posture.parameters.PARAMETERIZABLE` as the vocabularies — so adding an op in
  one place cannot leave validation behind.
- [ ] **Step 4: Assert `validate_manifest` still accepts all three bundled
  packs** (they have no posture rules; this proves the change is additive).
- [ ] **Step 5: Commit.**

---

### Task 4: Resolution — platform checks plus this tenant's declared checks

**Files:**
- Create: `src/ccf/posture/resolve.py`
- Test: `tests/test_posture_resolve.py`

**Interfaces:**
- Produces: `ResolvedCheck` (frozen: `check: PostureCheck`, `endpoint: str`,
  `evaluator_key: str | None`, `parameters: dict`, `spec: DeclaredSpec | None`,
  `source: str`) and
  `async resolve_checks(session, *, provider: str, org_id: int | None) -> tuple[ResolvedCheck, ...]`

- [ ] **Step 1: Failing test** — platform checks are returned for an org with
  no packs; a declared Form A rule appears with its parameters; a declared Form
  B rule appears with its `DeclaredSpec`; **another tenant's declared check
  never appears** (the leak test); a rule for a different provider is excluded;
  a rule whose definition is unevaluable is **skipped with a warning, not
  returned** (it should have been caught at install, so reaching here means the
  row predates validation — dropping it is safer than scanning with it).
- [ ] **Step 2: Run** — expect `ImportError`.
- [ ] **Step 3: Implement** — one query joining `PackRule` → `CompliancePack`
  filtered on `organization_id` and `kind == "posture"`; platform checks from
  `checks_for(provider)`; `source` is `"platform"` or `"pack:<pack_key>"` so a
  finding can say where its expectation came from.
- [ ] **Step 4: Run tests + the P1/P2a posture suites.**
- [ ] **Step 5: Commit.**

---

### Task 5: Execute resolved checks in the connector

**Files:**
- Modify: `src/ccf/connectors/msgraph.py`, `src/ccf/posture/scan.py`
- Test: `tests/test_msgraph_declared_scan.py`

- [ ] **Step 1: Failing test** — a stubbed Graph returning recorded rows, with
  one platform check and one declared check registered, produces two outcomes;
  a declared check that 403s produces `manual_review_required` naming its
  required permission (reusing `_unrunnable`, unchanged).
- [ ] **Step 2: Run** — expect failure (`scan()` iterates `m365.CHECKS`).
- [ ] **Step 3: Change `scan()` to take resolved checks** rather than reading
  the module registry, keeping per-check isolation and `_unrunnable` exactly as
  they are. `ConfigConnector.scan()`'s signature gains an optional
  `checks: tuple[ResolvedCheck, ...] | None = None`; `None` resolves nothing and
  falls back to the platform registry, so a caller that has not been updated
  behaves as today.
- [ ] **Step 4: Pass resolved checks from `scan_for_system`**, which already has
  the session and the org.
- [ ] **Step 5: Run the full posture + connector suites.**
- [ ] **Step 6: Commit.**

---

### Task 6: Desired-state history and diff

**Files:**
- Create: `alembic/versions/0069_pack_version_manifest.py`, `src/ccf/packs/diff.py`
- Modify: `src/ccf/models_packs.py`, `src/ccf/packs/service.py`
- Test: `tests/test_packs_diff.py`

**Interfaces:**
- Produces: `CompliancePackVersion.manifest` (JSONB, default `{}`);
  `diff_posture_rules(old: dict, new: dict) -> PostureRuleDiff` with
  `added` / `removed` / `changed` keyed by rule key

- [ ] **Step 1: Failing test** — adding, removing and re-parameterizing a rule
  between two versions each appear in the right bucket; an unchanged rule
  appears in none; a version row written before this task (`manifest == {}`) is
  reported as **unknown rather than as "everything removed"** — a diff that
  fabricates deletions from missing history is worse than admitting the gap.
- [ ] **Step 2: Run** — expect `ImportError`.
- [ ] **Step 3: Migration** — `add_column` nullable with a `{}` server default;
  no backfill is possible (the manifests were never stored).
- [ ] **Step 4: Store the manifest** on the version row in `install_pack`.
- [ ] **Step 5: Implement the diff** in the `catalog/diff.py` shape.
- [ ] **Step 6: Check the RLS guard lists** — `compliance_pack_versions` is
  already covered via its parent chain; confirm
  `EXPECTED_TENANT_ISOLATION_TABLES`' hardcoded count does not change (no new
  table).
- [ ] **Step 7: `alembic heads`** — exactly one. Commit.

---

### Task 7: Full verification and mutation testing

- [ ] **Step 1:** full suite, `ruff check src tests`, `mypy src`,
  `alembic heads`. Only the known
  `test_dashboard_overview_sla_excludes_no_due_date_from_on_track` failure.
- [ ] **Step 2: Mutate every guard** — the harness asserts its perl-alarm
  watchdog and hashes files around each mutation (see the mutation-testing
  memory). At minimum: each `None`-return in `evaluate_predicate`; the
  `contains`-on-non-list guard; the unknown-op raise; the
  `manual_review_required` mapping in both modes; the `any_row`
  no-determinable-row case; each validation error; the collision check; the
  `organization_id` filter in `resolve_checks`; the unevaluable-row skip; the
  empty-manifest diff guard.
- [ ] **Step 3:** Report every ESCAPED honestly and strengthen until caught.
- [ ] **Step 4: Demonstrate** — install a pack declaring a 60-day stale-account
  check and a Form B guest-admin check against recorded Graph rows, scan, and
  print the outcomes beside the platform checks'. Read the output; the P4a
  double-period defect was found this way and no test.
- [ ] **Step 5: Commit.**
