# Enforcement Implementation Plan (CC&E #4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A configuration change can be planned, reviewed, approved by a second person, applied within a blast radius, and undone — and cannot happen any other way.

**Architecture:** A `RemediationProvider` protocol separate from `ConfigConnector`; a `RemediationPlan` whose lifecycle carries every refusal; write credentials as a distinct `connector_type` in the existing encrypted store; approval reusing `governance.waivers.can_approve`.

**Tech Stack:** Python 3.12, SQLAlchemy 2 async, httpx, pytest. One migration.

**Spec:** `docs/superpowers/specs/2026-09-15-enforcement-design.md`

## Global Constraints

- **Every refusal is tested by observing that nothing was written**, using a
  provider double that records calls. "Did not apply" is observed, never
  assumed.
- **Refusals happen at plan time**, so no approvable plan can fail on apply —
  and `apply` re-checks anyway, because approval may be hours old.
- **A step without reversal data is not planned.** A plan with no steps is
  `refused`, not approvable.
- **The requester cannot approve** (`can_approve`), and approval is role-gated
  to the same roles that approve waivers.
- **`is_write_configured()` is separate from `is_configured()`**, keyed on a
  distinct `connector_type`. No code path may fall back to the read credential.
- **Nothing in the scheduler applies anything.** No auto-remediate flag exists
  in this sub-project.
- **`ConfigConnector` is untouched.**
- **No SCN workflow.** An applied plan emits a bus event; that is the seam.
- **RLS:** `remediation_plans` carries `organization_id` → guard list gains it,
  count **133 → 134**.
- **Test database is on port 5434.** `CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5434/ccf_test CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5434/ccf_test`. Never two pytest sessions at once. App-driving scripts need `CCF_ENV=test`.
- Two rows wherever a filter is tested; a direct call wherever a branch is keyed
  on something the HTTP client holds constant.
- `ruff check src tests` and `mypy src` clean; `alembic heads` shows one.

---

### Task 1: The provider protocol and the plan builder (pure where it can be)

**Files:**
- Create: `src/ccf/enforcement/__init__.py`, `src/ccf/enforcement/types.py`,
  `src/ccf/enforcement/registry.py`
- Test: `tests/test_enforcement_types.py`

**Interfaces:**
- Produces: `RemediationStep`, `StepOutcome`, `RemediationProvider` (Protocol),
  `PlanRefusal`, `build_steps(findings, provider, *, max_resources, only) -> tuple[list[RemediationStep], str | None]`,
  `PROVIDER_REGISTRY`, `provider_for(check_key)`

- [x] **Step 1: Write the failing test.** The refusal logic is the product, so
  it is tested as a pure function first:

```python
async def test_a_plan_within_the_blast_radius_is_built() -> None: ...

async def test_a_plan_exceeding_the_blast_radius_is_refused_with_the_numbers() -> None:
    steps, refusal = await build_steps(_findings(11), _provider(), max_resources=10)
    assert steps == []
    assert refusal == "11 resources exceeds the enforcement limit of 10"


async def test_only_narrows_a_plan_to_named_resources() -> None:
    """The intended path for "just this one account"."""


async def test_a_step_without_reversal_data_is_excluded() -> None:
    """It could not be undone, so it is not offered."""


async def test_a_plan_with_no_steps_is_refused_not_empty() -> None:
    """An approvable plan that would do nothing invites an approval that means
    nothing."""
    assert refusal == "no resources to remediate"


async def test_only_failing_findings_are_planned() -> None:
    """A passing resource has nothing to remediate, and planning one would
    mean writing to something that was already correct."""


async def test_the_registry_maps_a_check_to_at_most_one_provider() -> None:
    """Two providers claiming one check would make the applied change depend on
    registry order."""
```

- [x] **Step 2: Run it.** Expect `ImportError`.
- [x] **Step 3: Implement.** `build_steps` filters to findings needing cover
  (reuse `governance.waivers.REQUIRES_COVER`), applies `only`, calls the
  provider's `plan`, drops steps with empty `current_state`, then checks the
  count against `max_resources`.
- [x] **Step 4: Run tests. Lint, mypy, commit.**

---

### Task 2: The `RemediationPlan` model and migration 0072

**Files:**
- Create: `src/ccf/models_enforcement.py`,
  `migrations/versions/0072_remediation_plans.py`
- Modify: `src/ccf/models.py` (metadata binding), `tests/test_rls_coverage.py`
- Test: `tests/test_enforcement_models.py`

**Interfaces:**
- Produces: `RemediationPlan` with `organization_id`, `system_id`, `check_key`,
  `provider_key`, `status`, `steps` (JSONB), `outcomes` (JSONB),
  `resource_count`, `refusal_reason`, `requested_by`, `approved_by`,
  `approved_at`, `applied_at`, `reversed_at`, `result_id`, `created_at`;
  `PLAN_STATUSES`

- [x] **Step 1: Write the failing test** — a plan round-trips; `status`
  defaults to `draft`; a DB `CheckConstraint` pins the status vocabulary;
  `steps`/`outcomes` default to `[]`; `resource_count` defaults to 0.
- [x] **Step 2: Run it.** Expect `ImportError`.
- [x] **Step 3: Write the model**, nullable `organization_id` per convention,
  `result_id` FK to `control_test_results` with `ON DELETE SET NULL` — deleting
  a result must never delete the record of what was done about it.
- [x] **Step 4: Bind into `CROSS_MODULE_MODEL_MODULES`.**
- [x] **Step 5: Migration 0072**, `down_revision = "0071_pack_sources"`, direct
  tenant policy.
- [x] **Step 6: RLS guard 133 → 134. `alembic heads`. Commit.**

---

### Task 3: The lifecycle service — every refusal

**Files:**
- Create: `src/ccf/enforcement/service.py`
- Test: `tests/test_enforcement_service.py`

**Interfaces:**
- Produces: `create_plan`, `approve_plan`, `apply_plan`, `reverse_plan`,
  `EnforcementError`

- [x] **Step 1: Write the failing test.** Each refusal observed through a
  recording double:

```python
async def test_no_write_credential_refuses_and_never_calls_apply() -> None:
    assert plan.status == "refused"
    assert "write credential" in plan.refusal_reason
    assert provider.applied == []


async def test_apply_without_approval_is_refused() -> None: ...
async def test_the_requester_cannot_approve_their_own_plan() -> None: ...
async def test_applying_twice_is_refused() -> None: ...

async def test_a_credential_revoked_between_approval_and_apply_refuses() -> None:
    """Approval may be hours old; a stale authorisation must not be honoured."""


async def test_a_blast_radius_tightened_after_approval_refuses_at_apply() -> None: ...

async def test_one_failing_step_does_not_abandon_the_others() -> None:
    assert {o["status"] for o in plan.outcomes} == {"applied", "failed"}
    assert plan.status == "applied"   # partially, and fully described


async def test_every_step_outcome_is_recorded() -> None: ...
async def test_reverse_restores_the_captured_state() -> None: ...
async def test_reversing_an_unapplied_plan_is_refused() -> None: ...
async def test_every_transition_is_audited() -> None: ...
async def test_an_applied_plan_emits_an_enforced_event() -> None: ...
async def test_another_tenants_plan_is_not_reachable() -> None: ...
```

- [x] **Step 2: Run it.** Expect `ImportError`.
- [x] **Step 3: Implement**, auditing through `ccf.api.audit.record_event` and
  emitting through `governance.bus.emit`.
- [x] **Step 4: Run tests. Commit.**

---

### Task 4: The M365 provider

**Files:**
- Create: `src/ccf/enforcement/providers/__init__.py`,
  `src/ccf/enforcement/providers/m365.py`
- Modify: `src/ccf/enforcement/registry.py`
- Test: `tests/test_enforcement_m365.py`

- [x] **Step 1: Write the failing test** — `plan` reads each user's current
  `accountEnabled` and captures it; the PATCH body is exactly
  `{"accountEnabled": false}`; reversal is exactly `{"accountEnabled": true}`;
  a 403 is a `failed` outcome naming `User.ReadWrite.All`, not an exception;
  `is_write_configured` is False with only a read credential;
  `handles` matches only the stale-account check.
- [x] **Step 2: Run it.** Expect `ImportError`.
- [x] **Step 3: Implement**, `write_credential_type = "msgraph_write"`.
- [x] **Step 4: Run tests. Commit.**

---

### Task 5: API and CLI

**Files:**
- Create: `src/ccf/api/routes/enforcement.py`
- Modify: `src/ccf/api/main.py`, `src/ccf/cli.py`
- Test: `tests/test_enforcement_api.py`

**Interfaces:**
- `POST /api/systems/{system_id}/remediation-plans` (create, from a check key
  and optional `resource_ids`)
- `GET /api/remediation-plans`, `GET /api/remediation-plans/{id}`
- `POST /api/remediation-plans/{id}/approve`
- `POST /api/remediation-plans/{id}/apply`
- `POST /api/remediation-plans/{id}/reverse`
- `ccf enforcement-plans` (list, read-only)

- [x] **Step 1: Write the failing test** — the whole loop through HTTP; approve
  and apply are role-gated; another tenant's plan id is 404; a refused plan
  cannot be approved (409); `organization_id` comes from the principal.
- [x] **Step 2: Run it.** Expect 404s.
- [x] **Step 3: Implement.** **No CLI command applies anything** — the CLI is
  read-only here, deliberately: a shell one-liner is the wrong interface for an
  irreversible act on a production tenant.
- [x] **Step 4: Run tests + the API suite. Commit.**

---

### Task 6: Verification, mutation testing, demonstration

- [x] **Step 1:** full suite, `ruff check src tests`, `mypy src`,
  `alembic heads`. Only the known
  `test_dashboard_overview_sla_excludes_no_due_date_from_on_track` failure.
- [x] **Step 2: Mutate every guard**, and for each refusal assert the mutation
  is caught by a test that observes **no write**. At minimum: the
  write-credential check at plan and at apply; the blast-radius check at both;
  the reversal-data filter; the empty-plan refusal; `can_approve`; the
  approved-status check in `apply`; the already-applied check; the applied-status
  check in `reverse`; per-step isolation; both `organization_id` filters; the
  `handles` match; the PATCH bodies.
- [x] **Step 3:** Report every ESCAPED honestly.
- [x] **Step 4: Demonstrate** against a stubbed Graph — plan for three stale
  accounts, show the plan and its captured reversal data, try to approve as the
  requester (refused), approve as an AO, apply, show the outcomes, reverse, and
  show a fourth attempt refused by the blast radius. **No live tenant is
  involved and none can be from this environment.**
- [x] **Step 5: Commit** with results recorded here.

---

## Results

All six tasks complete. Full suite **2091 passed**, 1 skipped, and the one
pre-existing `test_dashboard_overview_sla_excludes_no_due_date_from_on_track`
failure that also fails on `main`. `ruff check src tests` and `mypy src` clean.
One migration head, `0072_remediation_plans`. RLS guard 133 → 134.

Commits: `4e4c8b5` (T1), `e551e5c` (T2), `0346cca` (T3), `d6796e1` + `44ed3bd`
(T4), `d848bbc` (T5).

### The demonstration

Against a **stubbed** Graph. No live tenant was involved and none is reachable
from this environment.

```
1. PLAN                     status=pending_approval  resources=3
                            graph writes so far: 0
2. REQUESTER APPROVES?      refused: the requester may not approve their own plan
                            graph writes so far: 0
3. AO APPROVES, APPLIES     all three accountEnabled True -> False
                            events emitted: ['enforced']   <- the SCN seam
4. REVERSE                  all three restored to True
5. PLAN OVER THE RADIUS     refused: 3 resources exceeds the limit of 2

total graph writes across the whole demo: 6   (3 apply + 3 reverse; none from
                                               planning or any refusal)
```

The last line is the property the whole sub-project exists for: every refusal
wrote nothing, and the only writes were the approved ones and their undo.

### Mutation testing: 32 guards, all caught

30 on the first pass; two escaped, both real, and one of them is the fourth
appearance of a familiar shape:

1. **The registry's duplicate-check refusal.** My test iterated the registry
   and asserted no check was claimed twice — which is a property of today's
   *content*, not of the guard. Now asserted by attempting a duplicate
   registration and expecting `ValueError`.
2. **The role gate on approve/apply/reverse.** Unreachable through the usual
   client, because the test principal is global and `is_global` bypasses
   `require_role` by design. Now driven with a scoped, non-enforcer identity
   asserting 403 on all three — and that the plan's status and outcomes are
   unchanged afterwards.

**Fourth sub-project where a branch keyed on something the test harness holds
constant went untested.** The standing lesson is now specific enough to act on:
any branch reading `principal.org_id` or `principal.role` needs a fabricated
scoped `Principal`, because the client never varies either.

### A test that failed because the code was right

The first API test could not drive plan → approve → apply at all: separation of
duties refused it, since one test client is one identity that both requested
and approved. That is the control working through HTTP. The routes are now
exercised with two identities via `dependency_overrides`, and the refusal is
asserted through HTTP as well, so it cannot be bypassed by calling the route
instead of the function.

### One correction to the spec's own wording, made before coding

§6.4 of the inventory said to reuse `ai_actions`' approval path. Reading it
showed that to be wrong: `approve_run` is bound to an LLM-drafted payload with
a citation guardrail, and its mutations are on GRC records. The waiver path
from #8 was reused instead, and `can_approve` is called with
`is_global=False` deliberately — enforcement gets no development exemption,
because "auth is disabled" is not a reason to skip the second pair of eyes on a
production change.

### Stated limitations

- **One provider.** Stale-account disable only. Conditional Access has no
  provider on purpose, and a test asserts it: a provider that can lock every
  administrator out of a tenant is not the one to learn on.
- **No SCN workflow.** An applied plan emits `enforced` with what a submission
  would need; the workflow is §2.19's own capability.
- **Nothing automatic.** The scheduler applies nothing, and no CLI command
  approves or applies — the API is the only path, because that is where the
  role gate and the identity live.
