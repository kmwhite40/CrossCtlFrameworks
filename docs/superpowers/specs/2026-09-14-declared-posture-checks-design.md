# Declared Posture Checks — desired state as data (P2b / CC&E #1)

**Status:** design, awaiting implementation plan
**Supersedes nothing.** Extends `packs/` and `posture/`.
**Satisfies:** programme item P2b (validation-as-code via `packs/`) and the
Continuous Configuration & Enforcement directive's capability #1 (desired-state
declaration). These are the same work; building them separately would fork the
manifest format.

## 1. The finding that defines the scope

`PackRule` is written by `packs/service.install_pack`, deleted on upgrade, and
**never read by anything**. Three bundled packs declare `rules` entries
(`{"key": "unapproved_production", "kind": "assert", "definition": {"metric":
…, "op": "eq", "value": 0}}`) that no code evaluates.

Meanwhile `posture/checks.py` has the opposite problem: a working evaluation
runtime whose rules are hardcoded Python (`m365.CHECKS`, `m365.EVALUATORS`,
`m365.ENDPOINTS`), so declaring a new expectation requires a code release and
every tenant gets identical thresholds.

So the gap is **not** a declaration format (exists, validated, versioned,
per-tenant, audit-logged, replaced atomically on upgrade) and **not** an
evaluation runtime (exists, pure evaluators, per-resource findings, rolled up,
written through `record_result`). The gap is the bridge between them. That is
one sub-project, not two.

This also corrects §6.1 of `docs/architecture/forge-capability-inventory.md`,
which listed policy-as-code packaging as EXISTING without noting that the rules
it packages are inert.

## 2. What is declarable, and what is deliberately not

The three existing checks were chosen to span three resource shapes, so they
are the honest test of any declarative form:

| Check | Shape | Declarable? |
|---|---|---|
| `mfa_registered` | one finding per row, from one boolean field | **yes** — field truthiness |
| `legacy_auth_blocked` | one tenant-level finding, from "does any row match a compound condition" | **yes** — any-row-matches over nested paths, with equality / list-contains / set-intersects |
| `stale_accounts` | per row, needs a clock, date arithmetic, and two distinct `not_applicable` reasons | **no** — a declarative form expressive enough for this is a date DSL |

Therefore a declared check takes **one of two forms**, and the split is the
central design decision:

**Form A — parameterized platform evaluator.** The rule names a registered
evaluator and supplies metadata and parameters:

```json
{"key": "m365.identity.stale_accounts.60d", "kind": "posture",
 "definition": {"evaluator": "m365.identity.stale_accounts",
                "title": "No enabled account inactive past 60 days",
                "control_ids": ["AC-2", "AC-2(3)"],
                "parameters": {"threshold_days": 60}}}
```

This is where most of the value is. `posture/providers/m365.py` already says of
`STALE_ACCOUNT_DAYS`: *"Wants to be an organization-defined parameter — the ODP
machinery already exists for exactly this."* Form A is that, without inventing
a language.

**Form B — declarative predicate.** For the genuinely declarative shapes, so a
tenant can add a check with no code:

```json
{"key": "m365.identity.no_guest_admins", "kind": "posture",
 "definition": {"provider": "msgraph", "resource_type": "entra_user",
                "endpoint": "/v1.0/users?$select=id,userPrincipalName,userType",
                "expected": "no guest account holds a directory role",
                "control_ids": ["AC-2", "AC-6"],
                "mode": "per_resource",
                "resource_id_field": "userPrincipalName",
                "predicate": {"op": "not_equals", "path": "userType", "value": "Guest"}}}
```

Predicate vocabulary, closed and fail-closed — an unknown `op`, `mode`, or a
malformed path is a **validation error at install time**, never a silent pass:

- `mode`: `per_resource` (one finding per row) | `any_row` (one tenant-level
  finding; passes when at least one row matches)
- `op`: `truthy`, `falsy`, `equals`, `not_equals`, `contains` (list contains
  value), `intersects` (list shares a member with `values`), `all_of`, `any_of`
  (compose child predicates)
- `path`: dotted traversal (`signInActivity.lastSignInDateTime`), missing
  segment yields `None` rather than raising

No arithmetic, no dates, no regex, no negation-of-composites beyond the listed
ops. Every omission is deliberate: each one added is a form the predicate
evaluator must get right for an authorization package.

## 3. Verdict semantics — the part that must not be got wrong

A declared check that cannot be evaluated MUST NOT report `pass`. Concretely:

- Predicate references a path absent from every row → `manual_review_required`,
  observed text naming the path. Not `fail` (the resource may be fine) and
  never `pass`.
- `any_row` mode with zero rows → `fail` for an existence check is wrong when
  the collection could not be read; `msgraph._unrunnable` already draws this
  distinction ("403 is not empty") and declared checks reuse it unchanged.
- Zero rows on `per_resource` → no findings → `roll_up_findings` yields
  `not_applicable`, which is the existing, tested behaviour.

`CheckOutcome.from_findings` already raises on an unrecognised verdict, so a
declared check cannot introduce a verdict no reader understands.

## 4. Collision with platform checks is an error, not an override

A pack rule whose resolved check key equals a platform check key **fails
validation at install**. It is not silently overridden in either direction.

Rationale: the alternative lets a pack weaken a platform check invisibly — a
tenant installs a pack and `m365.identity.mfa_registered` starts reporting
`pass` against a different predicate, with the audit trail showing only "pack
installed". A tenant that genuinely wants different thresholds uses Form A with
its own key, which is additive and visible. Narrowing a platform check is then
an explicit act with its own key and its own rationale, and a waiver (CC&E #8)
is the mechanism for accepting the platform check's finding.

## 5. Resolution and scoping

```python
async def resolve_checks(session, *, provider: str, org_id: int | None)
    -> tuple[ResolvedCheck, ...]
```

Returns platform checks for the provider plus the tenant's installed declared
checks, each carrying enough to execute: the `PostureCheck`, the endpoint, and
the evaluation plan (a bound platform evaluator, or a predicate).

`ResolvedCheck` is what `connectors/msgraph.scan()` iterates, replacing its
direct use of `m365.CHECKS` / `m365.ENDPOINTS` / `m365.EVALUATORS`. The
connector keeps its per-check isolation and its `_unrunnable` path unchanged —
a declared check that 403s reports the missing permission exactly as a platform
check does.

Tenant scoping is inherited, not reinvented: declared checks come from
`CompliancePack` rows, which are already `organization_id`-scoped with RLS
behind them.

## 6. Versioning and desired-state diff

`CompliancePackVersion` records `version` and `manifest_sha` but **not the
manifest**, so "what changed in my desired state between v1 and v2" is
currently unanswerable. One migration adds `manifest JSONB` to
`compliance_pack_versions`, and `packs/diff.py` compares two versions'
posture rules in the shape `catalog/diff.py` already established
(`added` / `removed` / `changed`, per key).

This is the CC&E directive's configuration-timeline and change-impact asks for
*desired* state; observed-state history is `ControlTestResult` plus the pending
P2c retention work, and stays there.

## 7. What this does NOT do

- No enforcement, no write path, no remediation. Read-only, per §6.4 of the
  inventory.
- No new findings table. Declared check outcomes go through
  `governance/control_tests.record_result` like every other result.
- No new scheduler. `governance/scheduler.py` already runs the ConMon scan
  per tenant.
- No second manifest format, no new rule storage — `PackRule` with
  `kind="posture"`, which finally gives that table a reader.
- No LLM in the evaluation path. A declared predicate is deterministic or it is
  a validation error.

## 8. Testing strategy

- The predicate evaluator is pure: table-driven tests over recorded Graph
  shapes, including every fail-closed path (unknown op, missing path, empty
  rows, wrong type where a list was expected).
- A **golden equivalence test**: `mfa_registered` and `legacy_auth_blocked`
  re-expressed as Form B predicates must produce findings byte-identical to
  the hand-written evaluators over the same recorded rows. If the declarative
  form cannot reproduce the two checks that were chosen as declarable, the
  form is wrong — and this test is how that is discovered before shipping,
  not after.
- Validation tests: each malformed manifest shape produces a specific error,
  and a colliding key is rejected.
- Resolution tests: one tenant's declared checks never appear in another's
  (the leak test shape P4a used).
- Mutation testing on every guard, with the harness invariants now recorded in
  memory (assert the watchdog, hash the files).
