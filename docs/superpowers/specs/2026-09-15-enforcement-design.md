# Closed-loop enforcement (CC&E #4)

**Status:** design, awaiting implementation plan
**Gated by:** §6.4 of `docs/architecture/forge-capability-inventory.md`
**Depends on:** the posture spine (0068), waivers (#8), drift (#2)

## 0. What makes this different from everything before it

Every connector in this platform is read-only. A read-path bug produces a wrong
verdict, which review catches. **A write-path bug reconfigures a production
federal system** — possibly one mid-authorization, where an unplanned
configuration change is itself reportable.

So the design question is not "can we call the API" but "what must be true
before a write happens". Everything below is an answer to that, and each
answer is a refusal: refuse without write credentials, refuse without a plan,
refuse without approval by a second person, refuse beyond a blast radius,
refuse without the data to undo it.

## 1. A correction to the gate's own wording

§6.4 said enforcement should reuse "human approval reusing `ai_actions`'
approval path rather than a new one". Having read that path, **that is wrong.**

`ai_actions.approve_run` is bound to `AiActionRun` / `AiActionOutput` — an
LLM-drafted payload, a citation guardrail, an `uncited` flag — and its
mutations (`set_poam_remediation`, `create_task`) are on *GRC records*.
Routing an environment change through it would mean modelling a configuration
change as a model output, inheriting guardrails that are meaningless here
(there is no citation for "disable this account") while missing the one that
matters (separation of duties).

The right shape to reuse is the **waiver** approval path built for #8:
request → role-gated approval by a *different* actor → act, audited at each
transition, with `governance.waivers.can_approve` already implementing
separation of duties as a pure rule. That is reused directly.

## 2. Write credentials are a different credential

`connectors/credentials.resolve_credential(session, org_id, connector_type)`
is keyed on connector type. So a write credential is simply a **different
type**: `msgraph_write` beside `msgraph`.

This is the whole mechanism, and it is worth being explicit about why it is
enough:

- It reuses the existing envelope encryption, masking, per-org binding and RLS.
  No new secret storage.
- **A read-only deployment cannot write, structurally.** The write path asks
  for a credential that does not exist unless an operator deliberately created
  it with an app registration holding write scopes. There is no flag to flip,
  no fallback to the read credential, and no code path where a missing write
  credential degrades to using the read one.
- The Graph app registration for writes needs different permissions
  (`User.ReadWrite.All` versus `User.Read.All`), so the separation is real at
  the identity provider too, not only in this database.

A provider MUST implement `is_write_configured()` separately from
`is_configured()`, and `apply` MUST refuse when it is false.

## 3. Enforcement is not a method on `ConfigConnector`

Per §6.4. A new, deliberately small abstraction:

```python
@dataclass(frozen=True)
class RemediationStep:
    resource_id: str
    resource_type: str
    action: str              # what will be done, e.g. "disable_account"
    description: str         # for a human reading the plan
    current_state: dict      # captured BEFORE the change -- the reversal data
    target_state: dict

@dataclass(frozen=True)
class StepOutcome:
    resource_id: str
    status: str              # applied | failed | skipped
    detail: str

class RemediationProvider(Protocol):
    key: str
    write_credential_type: str
    required_permissions: tuple[str, ...]
    def handles(self, check_key: str) -> bool
    async def is_write_configured(self) -> bool
    async def plan(self, findings) -> list[RemediationStep]
    async def apply(self, step) -> StepOutcome
    async def reverse(self, step) -> StepOutcome
```

`plan` is side-effect free and may read; it captures `current_state` **from the
provider, now** — not from the stored finding, which may be stale. A step whose
`current_state` cannot be read is not planned, because it could not be undone.

## 4. The plan lifecycle, and where each refusal sits

```
draft ──plan()──► pending_approval ──approve()──► approved ──apply()──► applied
  │                      │                                              │
  └──► refused           └──► rejected                                  └──► reversed
       (blast radius,         (a human said no)                              (undo applied)
        no reversal data,
        nothing to do)
```

- **`refused` happens at plan time, not apply time.** An operator must never
  hold an approvable plan that will be rejected when applied. Blast radius,
  missing reversal data and an unconfigured write credential are all decided
  before anyone is asked to approve.
- **Approval requires a different actor** (`can_approve`) and a role from the
  same set that approves waivers.
- **`apply` re-checks everything.** Approval may be hours old: the write
  credential may have been revoked, and the plan may exceed a blast radius that
  was since tightened. Re-checking is cheap; applying a stale authorisation is
  not.
- **`apply` is per-step isolated.** One resource failing must not abandon the
  rest, and every step's outcome is recorded, so a partial apply is fully
  described rather than inferred.

## 5. Blast radius

A setting, `enforcement_max_resources` (default **10**). A plan touching more
resources is `refused` with the count and the limit stated.

Ten is deliberately small. The purpose is not to size a batch job; it is that
the first enforcement action a deployment takes should be too small to be a
disaster, and raising the limit should be a conscious act by someone who has
watched it work. A plan may also be narrowed to specific `resource_ids` at
planning time, which is the intended path for "just this one account".

## 6. Reversal is a precondition, not a feature

Every step carries `current_state` captured before the change. A provider that
cannot produce it does not get a step in the plan.

`reverse` re-applies `current_state`. It is best-effort by nature — the world
may have moved — and its outcomes are recorded exactly like an apply's. What
matters is that the *information* needed to undo is captured before the change
and stored with the plan, so a human has it even if `reverse` fails.

## 7. What is recorded, and what is deliberately not built

Every applied plan writes:

- an **audit entry** per transition through `ccf.api.audit.record_event`, so
  the tamper-evident chain covers enforcement;
- a **bus event** (`governance.bus.emit`) with verb `enforced`, which already
  feeds the timeline and outbound webhook delivery;
- **per-step outcomes** on the plan row.

**A significant-change notification workflow is NOT built here.** An applied
configuration change on a system under authorization is a candidate SCN, and
the event carries what an SCN process would need — but SCN proper (§2.19) is
its own capability with its own submission semantics, and stubbing it would
produce a record nobody sends. The event is the honest seam.

## 8. The first provider

**M365 stale accounts → disable the account.** Chosen because it is the
canonical remediation, it is bounded (one field on one object), and it is
**reversible** — `accountEnabled: false` back to `true`. `PATCH /v1.0/users/{id}`
with `User.ReadWrite.All`.

Deliberately *not* first: anything touching Conditional Access policy, which
can lock every administrator out of a tenant. A provider that can cause a
lockout is not the one to learn on.

## 9. What this does NOT do

- No automatic enforcement. Nothing in the scheduler applies anything; there is
  no auto-remediate flag in this sub-project. A plan is created, reviewed and
  applied by people.
- No enforcement without an approved plan. There is no "apply this finding"
  shortcut.
- No `ConfigConnector` change.
- No new secret storage (§2).
- No SCN workflow (§7).
- No policy-driven remediation selection: which findings to plan for is a human
  choice, not a rule engine. That can come later, on these rails.

## 10. Testing strategy

Every refusal gets a test asserting **nothing was written** — using a provider
double that records calls, so "did not apply" is observed rather than assumed:

- no write credential → `refused`, provider's `apply` never called
- blast radius exceeded → `refused` at plan time, with count and limit
- a step with no reversal data → excluded from the plan; a plan with no steps
  is `refused` rather than approvable
- approval by the requester → refused (`can_approve`)
- apply without approval → refused
- apply twice → refused the second time
- write credential revoked between approval and apply → refused at apply
- one step failing → the others still applied, all outcomes recorded
- reverse restores `current_state` and records outcomes
- every transition audited; an applied plan emits `enforced`
- tenant isolation on every query
- the M365 provider: the PATCH body is exactly `{"accountEnabled": false}`,
  the reversal body exactly `{"accountEnabled": true}`, and a 403 is an outcome
  rather than an exception

Mutation testing on every guard, with the harness invariants from the
mutation-testing memory — and, per the last three sub-projects: a fixture with
**two** rows wherever a filter is tested, and a direct call wherever a branch
is keyed on something the HTTP client holds constant.
