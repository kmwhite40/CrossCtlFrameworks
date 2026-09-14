# P2a — Posture Validation Spine (design)

**Date:** 2026-09-14
**Status:** Design approved in brainstorming; awaiting spec review
**Programme context:** `docs/superpowers/assessments/2026-09-14-grc-capability-gap-analysis.md`
**Inventory (authoritative on what exists):** `docs/architecture/forge-capability-inventory.md`
**Sub-project:** P2a — the first of three pieces P2 decomposed into

## 0. Scope correction that shrank this sub-project

P2 was originally scoped as five pieces. Reading the code reduced it to three,
and this spec covers only the first:

| Originally planned | Reality |
|---|---|
| Append-only, time-series validation history | **Already exists.** `ControlTestResult` is one row per execution with `run_at` indexed and a composite `(control_test_id, run_at)` index. |
| Fix the POA&M/Task closure defect | **Already fixed and tested.** `_resolve_on_recovery` (`control_tests.py:270`) handles fail/warn -> pass as resolve-or-propose; covered by `tests/test_control_test_recovery.py`. Corrected in both prior documents. |
| Resource-level results + `scan()` contract | **This spec (P2a).** |
| Validation-as-code via `packs/` | **P2b.** Two thin rule dialects exist (`ControlTest.assertion` and the `fedramp20x` rule language); unifying them is its own piece. |
| Snapshots + point-in-time reconstruction | **P2c.** Validation results already have history; evidence and configuration snapshots do not. |

## 1. Problem

Concord can already define a repeatable control test, run it on a schedule,
derive a verdict, record an append-only result, alert on failure, open a
remediation task, and resolve it on recovery. What it cannot do is say **which
resources** failed.

`ControlTestResult` carries `status` plus a free-text `detail` for the whole
test. There is no way to express "47 storage accounts evaluated, 3 allow public
access, here are their ids", no structured expected-versus-observed, and no
resource-level trend. The connector contract compounds this: `capture()`
returns `CapturedParameter(odp_key, value, ...)` — a single scalar meant to
fill a blank in an SSP sentence, not an assessment of a fleet.

Measured live surface today: **12 ODP parameters across 2 providers**
(`msgraph` 6, `aws_govcloud` 6), only two of which are real reads.

## 2. Goals and non-goals

**Goals.**

1. Per-resource findings under each control-test result, queryable and indexed.
2. A `scan()` contract beside `capture()` that returns them.
3. Posture checks as declared content, instantiating `ControlTest` rows.
4. One verdict vocabulary across control tests and KSI validation.
5. A control test may evidence a `Capability` directly.

**Non-goals.**

- **No parallel posture tables.** `ControlTest`/`ControlTestResult` stay the
  only test-and-result spine; a second verdict vocabulary, history, POA&M
  writer, and recovery loop is the likeliest way this programme damages the
  platform.
- **No new POA&M or alerting path.** The existing failure and recovery
  machinery is reused as-is.
- **No pack format work.** Check definitions live in a code registry here and
  move to `packs/` in P2b — the registry is deliberately shaped so that is a
  relocation, not a redesign.
- **No provider adapters.** P2a fixes the contract; implementing Azure, GCP,
  and the AWS/M365 expansions is P3.
- **No feedback into `Capability.status`** (see §4.5).
- **No rewiring of the assessment engine** (see §4.6).

## 3. Data model

### 3.1 New: `control_test_resource_results`

```
control_test_resource_results
  id                bigint pk
  result_id         bigint  fk -> ccf.control_test_results.id ON DELETE CASCADE
  resource_id       varchar(512)   -- ARN, resource id, object path
  resource_type     varchar(64)    -- 's3_bucket', 'conditional_access_policy'
  verdict           varchar(32)    -- VALIDATION_STATUSES
  observed          text           -- what the provider actually reported
  detail            jsonb  not null default '{}'
  created_at        timestamptz not null default now()

  INDEX (result_id)
  INDEX (verdict)                  -- "every failing resource" is a core query
  INDEX (resource_type, verdict)
```

**Tenancy — the schema settled this, against my first assumption.** I expected
`organization_id` plus the direct predicate used for the P1 capability tables.
But `control_test_results` carries **no** `organization_id` and is policied
through its parent:

```sql
control_test_id IN (SELECT id FROM control_tests WHERE organization_id = current_tenant())
```

`poam_milestones` does the same two hops through `poams -> systems`. So this
table follows that established second predicate shape, chaining one hop
further:

```sql
result_id IN (
  SELECT r.id FROM control_test_results r
  JOIN control_tests t ON t.id = r.control_test_id
  WHERE t.organization_id = current_tenant()
)
```

Adding `organization_id` here would denormalize against the convention and
create a second source of truth for the row's tenant.

### 3.2 Altered: `control_tests`

```
  source        varchar(16) not null default 'authored'   -- authored | generated
  check_key     varchar(128)                              -- null for authored tests
  capability_id bigint fk -> ccf.capabilities.id ON DELETE SET NULL
  last_status   varchar(8) -> varchar(32)                 -- widened

  UNIQUE (system_id, check_key)    -- makes re-scanning idempotent
```

The unique constraint deliberately does **not** constrain authored tests.
`check_key` is null for them, and Postgres treats nulls as distinct in a unique
index, so any number of authored tests may coexist for one system while a
generated `(system_id, check_key)` pair can exist only once. `system_id` is
itself nullable on this table for org-wide authored tests; generated tests
always carry one, since a scan runs against a system.

`source` defaults to `authored`, so every existing row is correctly labelled
without a data migration. `capability_id` is `SET NULL` on delete rather than
`CASCADE`: deleting a capability must not destroy validation history.

### 3.3 Altered: `control_test_results`

```
  evaluated   integer not null default 0    -- resources considered
  failing     integer not null default 0    -- resources that failed
  expected    text                          -- structured expectation as evaluated
  status      varchar(8) -> varchar(32)     -- widened
```

## 4. Components

### 4.1 Check definitions — declared content

```python
@dataclass(frozen=True)
class PostureCheck:
    key: str                        # 'aws.s3.block_public_access'
    title: str
    provider: str                   # a ConfigConnector key
    resource_type: str
    expected: str                   # human-readable expectation
    control_ids: tuple[str, ...]    # canonical 800-53 ids
    capability_key: str | None = None
```

A per-provider registry, deliberately the same shape as
`etl.sources.DEFAULT_SOURCES`, so P2b's move into `packs/` relocates content
rather than redesigning it. `control_ids` are **canonical** (`AC-2`), matching
`CapabilityControl.control_id` and `SSPControlEntry.control_id`.

### 4.2 The `scan()` contract

```python
@dataclass(frozen=True)
class ResourceFinding:
    resource_id: str
    resource_type: str
    verdict: str                    # any VALIDATION_STATUSES value; in
                                    # practice pass | fail | warn |
                                    # not_applicable per resource
    observed: str
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CheckOutcome:
    check_key: str
    verdict: str                    # rolled up from findings
    expected: str
    findings: tuple[ResourceFinding, ...]

    @property
    def evaluated(self) -> int: ...
    @property
    def failing(self) -> int: ...
```

On `ConfigConnector`:

```python
async def scan(self) -> list[CheckOutcome]:
    """Read live configuration and assess it. Returns [] when unsupported."""
    return []
```

Defaulting to `[]` leaves `msgraph` and `aws_govcloud` working untouched — the
same courtesy the existing `verify()` extends by returning a
not-implemented dict. `capture()` is unchanged and keeps its ODP role.

### 4.3 Rollup — pure

```python
def roll_up_findings(verdicts: Iterable[str]) -> str
```

- `not_applicable` and `not_tested` are **excluded**, not ranked.
- With nothing left, the result is `not_applicable` — zero resources in scope
  is not a passing check.
- Otherwise the **worst** surviving verdict wins: 3 failing of 47 is `fail`.

Reuses `fedramp20x.validation._VERDICT_RANK`, promoted to public as
`VERDICT_RANK`. **The selection is deliberately opposite to its existing
use:** `evaluate_rule`'s `any_of` takes the *best* sub-result with `max`, where
posture rollup takes the *worst*. The exclusion matters for the same reason —
`not_applicable` and `not_tested` both rank **0, below `fail` at 1**, so a
naive `min` would report "not applicable" for a failing check.

### 4.4 Scan orchestration

```python
async def scan_for_system(session, *, system_id: int, connector_key: str) -> dict[str, Any]
```

1. Resolve the org's credential via `connectors.credentials.resolve_credential`
   — the only credential path, and it never falls back to a global value.
2. `scan()` the connector.
3. For each `CheckOutcome`, upsert the `ControlTest` on
   `(system_id, check_key)` with `source='generated'`.
4. Write one `ControlTestResult` plus its `ResourceFinding` rows.
5. Route failures through the **existing** `_alert_on_failure` / `_upsert_poam`
   path, and recoveries through the existing `_resolve_on_recovery`.

**Machine-owned fields only on re-scan.** An upsert writes `check_key`,
`control_id`, `capability_id`, and `description`. A human's edits to `name`,
`frequency`, and `active` survive, following the precedent tested in
`test_control_test_recovery.py::test_human_edited_task_and_poam_fields_survive_recovery`.

**Retiring a check deactivates its test; it never deletes it.** Validation
history is the product.

### 4.5 Capability linkage, and the loop left open

`ControlTest.capability_id` lets a check evidence a capability, and results are
readable against it. **`Capability.status` stays authored.** P1 already derives
*control* status from capability status; deriving capability status from
validation would make the same field both input and output of one pipeline.
Closing that loop is a separate decision with a real cycle risk and is out of
scope here.

### 4.6 Deterministic-check-wins

```python
async def effective_verdict(session, *, system_id: int, control_id: str) -> dict[str, Any]
```

Where a fresh deterministic `ControlTestResult` exists for a control, it
outranks an LLM `AssessmentObjectiveProposal` verdict; the model covers what no
check reaches. Implemented as a single read-side helper that reports which
source won and why. **The assessment engine is not rewired** — that is a larger
change than this sub-project should carry, and the helper makes the precedence
available wherever results are surfaced.

"Fresh" means within the test's own `frequency` window, falling back to 30 days
when a generated test has none.

### 4.7 API and CLI

Extends `api/routes/conmon.py` (control tests) rather than adding a module:

```
POST /api/systems/{system_id}/scan?connector=<key>     run a scan
GET  /api/control-tests/{test_id}/results/{result_id}/resources
GET  /api/posture/failing-resources                    org-wide, filterable
GET  /api/controls/{control_id}/effective-verdict?system_id=
```

`ccf posture scan --system <id> --connector <key>` on the existing CLI app.

**Namespace note:** `api/routes/posture.py` already serves *compliance*
posture (internal rollups). `GET /api/posture/failing-resources` is added to
that module so one prefix is not split across two files, and its docstring
records that the module now serves both senses.

## 5. Migration

One revision, `0068_posture_validation_spine`, revising
`0067_capability_ontology`:

1. Widen `control_test_results.status` and `control_tests.last_status` to
   `varchar(32)`. Backward-compatible: `pass`/`fail`/`warn` stay valid.
2. Add `source`, `check_key`, `capability_id` to `control_tests`, plus
   `UNIQUE (system_id, check_key)`.
3. Add `evaluated`, `failing`, `expected` to `control_test_results`.
4. Create `control_test_resource_results` with its three indexes.
5. `ENABLE` + `FORCE ROW LEVEL SECURITY` and the **two-hop parent-chain**
   `tenant_isolation` policy from §3.1.
6. The `pg_roles` GRANT guard.

`EXPECTED_TENANT_ISOLATION_TABLES` in `tests/test_rls_coverage.py` gains
`control_test_resource_results`; its hardcoded count moves **130 -> 131**.
`GLOBAL_TABLES` in `tests/test_rls_registry_no_gap.py` is **not** touched — the
new table is tenant-scoped, and having a policy is what keeps it out of that
guard's unpolicied-table query.

Confirm `alembic heads` returns exactly one head. No data migration.

## 6. Testing strategy

- **Rollup (pure)** — all pass; one fail among passes -> `fail`; `warn` among
  passes -> `warn`; `not_applicable` excluded, not ranked; empty and
  all-not-applicable -> `not_applicable`; and an explicit test that a mix of
  `fail` and `not_applicable` returns `fail`, pinning the exclusion that a
  naive `min` over `VERDICT_RANK` would get backwards.
- **Contract** — `scan()` returns `[]` on the base class, so both existing
  connectors are unaffected; `capture()` behaviour is unchanged.
- **Orchestration** — a scan creates a `generated` test and one result with its
  resource rows; re-scanning is idempotent on `(system_id, check_key)`; a
  human's edits to `name`/`frequency`/`active` survive re-scan; a failing
  result routes through the existing alert/POA&M path; recovery routes through
  the existing `_resolve_on_recovery`; retiring a check deactivates rather than
  deletes.
- **Queryability** — "every failing resource for this org" resolves through the
  `verdict` index, and returns nothing for another tenant.
- **RLS** — cross-tenant reads and writes on `control_test_resource_results`
  are refused through both hops; the two RLS guard tests still pass.
- **Vocabulary** — the widened column accepts `manual_review_required`, and
  legacy `pass`/`fail`/`warn` still round-trip.
- **Precedence** — `effective_verdict` prefers a fresh deterministic result
  over a model verdict, prefers the model verdict when no check exists, and
  treats a stale result as absent.

Every guard is mutation-tested: delete it, confirm a test fails, restore.
Tests must not assume an empty database (`session_scope` commits, the schema
migrates once per session), must use unique values for unique columns, and must
clean up rows other modules count.

## 7. Risks

| Risk | Mitigation |
|---|---|
| A second verdict vocabulary or result spine emerges | Non-goals forbid it; the migration widens the existing column rather than adding a status field, and `VERDICT_RANK` is shared |
| Generated tests clobber human edits | Upsert writes machine-owned fields only, with a test pinning it (§4.4) |
| `not_applicable` ranks below `fail`, so rollup reports the wrong verdict | Excluded rather than ranked, with a dedicated test for the fail/not-applicable mix (§4.3, §6) |
| Resource rows grow without bound | One row per resource per run; retention is a P2c concern and is named there rather than half-solved here |
| Scan latency inside a request | The POST endpoint runs one connector for one system; the scheduler path stays the bulk route, reusing the existing per-tenant SAVEPOINT shape |
| `posture` namespace now means two things | Both live in `api/routes/posture.py` with the dual meaning recorded in its docstring |

## 8. Open items

1. **Resource-result retention.** One row per resource per run grows quickly at
   fleet scale. Deliberately deferred to P2c, which owns snapshot and retention
   policy; P2a adds no retention mechanism rather than inventing half of one.
2. **Check-to-capability binding by key.** `PostureCheck.capability_key`
   resolves to a `Capability` by `(organization_id, key)` when one exists, and
   is left null otherwise. Settled: a missing capability is not an error, since
   checks ship as content and capabilities are authored per tenant.
