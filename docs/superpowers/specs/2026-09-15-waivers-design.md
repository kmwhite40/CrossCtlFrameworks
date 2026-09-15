# Waivers — accepting a finding without erasing it (CC&E #8)

**Status:** design, awaiting implementation plan
**Extends:** `governance/control_tests.record_result`, the posture spine (0068)
**Motivated by:** the CC&E directive's capability #8, and a finding from P2b —
two checks can now cover one control and disagree, and a waiver is the
mechanism for accepting one of them.

## 1. A correction, and the distinction it forces

Section 6.2 of `docs/architecture/forge-capability-inventory.md` classified #8
as "NEEDS EXTENSION — generalize `KSIException`". Reading what `KSIException`
actually does shows that is wrong, and the reason matters.

`fedramp20x/readiness.py` counts `KSIException` rows with `status == "open"`
into `Readiness.open_exceptions`, which is a **detractor** surfaced in the
readiness payload and the authorization package. It suppresses nothing. It is a
*disclosure*: "we know about this, here it is, count it against us."

What CC&E #8 asks for is different in effect: stop the operational consequence
of a finding that has been formally accepted — no fresh alert, no repeated
remediation task, no POA&M churn — **while the finding and its evidence stay
exactly as recorded.**

Conflating the two would be a genuine compliance-integrity failure in either
direction: making disclosure silence an alert, or making an operational
silence disappear from the package. So this introduces a distinct `Waiver` and
leaves `KSIException` untouched. §7 records why they are not merged yet and
what merging would cost.

## 2. The invariant

**A waiver changes what happens next. It never changes what was observed.**

Concretely, a waiver in force MUST NOT alter:

- `ControlTestResult.status` — a `fail` stays `fail`
- `ControlTestResourceResult` rows — every resource's verdict and observed text
- `ControlTest.last_status` / `last_tested_at`
- `posture.scan.effective_verdict` — it still reports `fail`
- the `tested` event on the bus

A waiver in force suppresses exactly one thing: the `_alert_on_failure` call —
the notification, the auto remediation `Task`, and the POA&M upsert.

This is the whole design. Everything below is a consequence of it.

## 3. Where it applies

`record_result` is the only writer of results, and it already owns alerting,
POA&M upsert, recovery and events. The waiver check goes **between** the
resource rows being flushed and `_alert_on_failure` being called — by which
point all evidence is already persisted, so no failure of the waiver logic can
cost a recorded observation.

Putting it anywhere else fails:

- in the posture rollup → rewrites the verdict, i.e. the evidence
- at read time only → alerts have already fired and POA&Ms already exist
- in each caller → three triggers (manual run, scheduler, posture scan) would
  drift apart, which is why `record_result` is the only writer in the first
  place

## 4. Scope and the coverage rule

A waiver targets, within one system:

- a **check** (`check_key`) or a **control** (`control_id`) — one or the other
- optionally narrowed to a single **resource** (`resource_id`)

Coverage, deliberately strict:

1. A waiver with no `resource_id` covers the whole result.
2. A waiver with a `resource_id` covers only that resource.
3. `_alert_on_failure` is suppressed **only when every failing resource is
   covered**. One uncovered failing resource and the alert fires normally — a
   partially-accepted check is still an unaccepted finding.
4. A result carrying **no resource findings** (a manual test, or a
   pre-0068 caller) can be covered only by a waiver with no `resource_id`. A
   resource-scoped waiver must never silence a result whose resources were
   never enumerated: there is nothing to prove the waived resource was the
   failing one.

Rule 4 is the subtle one and the one most likely to be got wrong by being
helpful.

## 5. Active, and the expiry that must bite

A waiver is **active** when `status == "approved"` and
(`expires_on IS NULL` OR `expires_on >= today`).

- `requested` suppresses nothing. If asking were enough, anyone could silence a
  check by asking.
- `revoked` suppresses nothing, immediately.
- An **expired waiver resumes alerting with no action taken.** This is the
  load-bearing property, it is a clock-dependent behaviour, and it gets an
  explicit test with an injected date rather than being left to inference.

`expires_on` is nullable, because a permanent architectural acceptance is a real
thing. But an indefinite waiver is a governance smell, so it is *counted and
reported* rather than forbidden — the same posture `KSIException` takes toward
disclosure.

## 6. What the evidence records

The result must say it was waived, or the read side cannot distinguish "failing
and unaddressed" from "failing and formally accepted" — and that distinction is
the entire point for an auditor.

- `control_test_resource_results.waiver_id` — nullable FK, set per resource.
  This is the precise home, because coverage is per resource.
- `control_test_results.waived` — integer count, matching the existing
  `evaluated` / `failing` shape on that row, for reporting without a join.

A waiver therefore leaves a *stronger* record than an unwaived failure, not a
weaker one.

**A waiver does not close an existing POA&M.** If a POA&M is already open when a
waiver is granted, it stays open until someone closes it deliberately; closing
a POA&M is a governance act with its own audit trail, and inferring it from a
waiver would let an acceptance quietly erase an outstanding weakness. The
combination — a failing result, a waiver in force, and an open POA&M — is a
legitimate state, and one an auditor should be able to see. What the waiver does
stop is the POA&M being re-upserted and its weakness text refreshed on every
subsequent failing scan.

## 7. Why `KSIException` is not merged into this

They overlap in fields (rationale, status, expiry, linked risk) and differ in
effect (§1). Merging is attractive and is **not** done here, for three reasons
worth stating rather than leaving implicit:

1. `KSIException` has live readers — `readiness.py`, `package.py`, and two
   route modules — and its rows feed an authorization package. Changing what
   those rows mean is an authorization-affecting change, not a refactor.
2. Its `status` vocabulary (`open|accepted|closed`) means something different
   from a waiver's (`requested|approved|revoked`), and `readiness` counts
   `open` — which under a waiver's vocabulary would be the state that does
   nothing.
3. A merge needs a data migration of real disclosure records.

The honest outcome: one mechanism for operational suppression (this), one for
FedRAMP disclosure (`KSIException`), and a documented follow-up to unify them
by making disclosure a *read* over waivers once this has an approval trail
worth reading. That follow-up is named in the plan, not silently dropped.

## 8. Testing strategy

- Coverage is a **pure** function over (findings, waivers, today) and gets
  table-driven tests: full cover, partial cover, no cover, resource-scoped
  against a resource-less result (rule 4), expired, requested, revoked, and a
  waiver for a different check.
- The invariant in §2 gets its own test asserting that a waived `fail` still
  records `status == "fail"`, still writes every resource row, still leaves
  `last_status == "fail"`, and still reports `fail` from `effective_verdict`.
- Suppression is asserted by **absence**: no notification, no `Task`, no POA&M
  after a waived failing result — and their **presence** after an unwaived one,
  so the test cannot pass by the fixture simply not producing them.
- Expiry gets a clock: the same waiver suppresses before `expires_on` and does
  not after.
- Mutation testing on every guard, with the harness invariants from the
  mutation-testing memory (assert the watchdog, hash the files, restore on a
  trap).
