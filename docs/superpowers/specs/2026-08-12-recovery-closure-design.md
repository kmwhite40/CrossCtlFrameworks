# Recovery Closure — Design

**Date:** 2026-08-12
**Status:** Approved (design), pending implementation plan
**Slice:** hardening; not part of the ATO Bot capability delta, which is closed
**Depends on:** the branch state at `185770c` on `feat/evidence-prep-spine`

## Context

`control_tests.record_result` (`src/ccf/governance/control_tests.py:269`) opens a
remediation `Task` and a `POAM` when a control test returns `fail` or `warn`, via
`_alert_on_failure`. It does nothing at all on `pass`:

```python
if status in ("fail", "warn"):
    await _alert_on_failure(session, test, status, detail or "")
```

conmon's `_upsert_task` / `_upsert_poam` (`src/ccf/governance/conmon.py:200-296`)
have the same shape — they open on at-risk/overdue and never resolve on healthy.
A grep for `close`, `reopen` or `resolved` in `control_tests.py` returns nothing.

No test covers the transition either: `tests/test_grc_integration.py:182-219`
drives a test straight to `pass` and asserts only `last_status`.

**Consequence.** A control that failed once and has since been fixed keeps an
open POA&M until a human closes it by hand. The remediation backlog fills with
entries that look like live findings and are not. That is not merely untidy: a
POA&M list nobody trusts is a POA&M list nobody reads, and this one feeds
authorization packages.

Found by the continuous-verification drift gap analysis. It is **Concord's own
defect, not a missing ATO Bot capability** — that delta is closed, and this
should not be described as part of it.

## Goals

1. A control test recovering from `fail`/`warn` to `pass` resolves the
   remediation `Task` it opened.
2. The POA&M it opened is **surfaced for closure**, not closed.
3. Neither happens to anything a human created or has touched.

## Non-goals

- **No auto-closing of POA&Ms.** See below; this is the load-bearing decision.
- **No change to the ISSM-08/09 closure gate** (`api/routes/poams.py:216`).
- **No new tables, jobs or queues.** `Task`, `POAM` and `PoamMilestone` already
  carry everything needed.
- **No change to conmon's health derivation.** Only its open/resolve symmetry.
- **No retrofit.** Tasks and POA&Ms already open when this ships stay as they
  are; only transitions observed afterwards are acted on.

## The decision: resolve the Task, surface the POA&M

The two objects warrant different treatment, and the data model already says so.

A `Task` (`models.py:1035`, `kind="remediation"`) is an internal work item with a
free status vocabulary and no formal gate. Nothing downstream depends on it and
no authorization artifact cites it. Resolving one automatically when its
triggering condition clears is uncontroversial.

A `POAM` has a closure gate: all milestones complete, or dated `Evidence` on or
after `identified_on`, **plus** a separation-of-duties `Approval` when auth is
enabled. That gate exists because closing a POA&M is an assertion, in an
authorization package, that a weakness is remediated.

**A single passing control test is not that assertion.** It is one observation,
possibly of a narrow assertion, possibly transient. Letting it close a POA&M
would route around the gate — the same objection that made slice 5 refuse to let
a passing re-evaluation retire its own finding.

This is deliberately asymmetric with `scanners.py:397`, which *does* auto-close a
POA&M absent from the latest scan. That asymmetry is principled and should be
documented rather than smoothed over: a vulnerability missing from a scan is
direct evidence the weakness is gone. A control test passing once is weaker —
and unlike a scan, its assertion may cover only part of what the POA&M describes.

So on recovery the POA&M gains a **recorded observation** that its originating
test now passes, with the timestamp and the result id, and becomes visible in
whatever surface lists POA&Ms awaiting review. A human still closes it, through
the gate, with the evidence the gate demands.

## Only auto-created, untouched items

Both halves act only on items this machinery created, identified by the
`dedupe_key` (Task) and `source_ref` (POA&M) they were opened with — the same
keys `_alert_on_failure` and conmon's upserts already use.

An item a human created, or one they have since edited, assigned or partially
remediated, is left alone. The acceptance→POA&M bridge established this rule in
slice 5: re-acceptance finds an existing POA&M and leaves it completely alone
rather than overwriting a human's work. The same reasoning applies here, and the
test for it must be the same shape — **change a field and assert the change
survives**, not merely assert a count, since a count-only assertion passes
against code that overwrites.

## Where the transition is detected

In `record_result`, which already has both the previous status
(`test.last_status`, read before it is reassigned) and the new one. The
transition of interest is `last_status in ("fail", "warn")` and `status == "pass"`.

Note the ordering hazard: `record_result` assigns `test.last_status = status` at
line 290, before the alert branch. The previous value must be captured **before**
that assignment or the transition is undetectable. This is exactly the kind of
detail that reads as correct and is not, so it gets its own test.

conmon's equivalent transition is at-risk/overdue → healthy, detected the same
way against whatever it already persists.

## Error handling

Resolution is best-effort and must never fail the result recording. The test
result is the authoritative write; losing the resolution is recoverable, and
discarding a recorded test result because a derived update would not persist is
worse. It runs in `async with session.begin_nested():` — **`AsyncSession.rollback()`
is not savepoint-scoped** and unwinds the whole transaction; slice 3 shipped a
version that silently discarded the caller's work while reporting success.

Beware the trap this project hit in slice 5: a best-effort `except Exception`
makes "correctly skipped" and "raised and was swallowed" observably identical, so
a test asserting only that nothing happened passes either way. Any such test must
also assert nothing was logged at warning.

## Testing

- **The transition fires:** fail → pass resolves the Task. Assert the Task's
  status changed, not merely that the call returned.
- **The POA&M is surfaced and *not* closed** — assert its status is still open
  and that the observation was recorded. Both, separately.
- **No transition on fail → fail, warn → warn, or pass → pass.** Assert no
  provider-side effect *and* nothing logged at warning, so a clean skip is
  distinguishable from a swallowed exception.
- **The ordering hazard:** a test that fails if `test.last_status` is read after
  it is reassigned.
- **Human-touched items are untouched:** edit a field on the auto-created POA&M
  and Task, recover, and assert the edits survive. Asymmetric fixture.
- **Only matching items:** a Task or POA&M with a different `dedupe_key` /
  `source_ref` is not resolved. Assert against the specific organization and
  control, not a table that may be empty for unrelated reasons.
- **Failure isolation:** force the resolution to raise; the `ControlTestResult`
  still persists and a warning is logged. Confirm the test fails if the work is
  moved outside its savepoint.
- **conmon symmetry:** the same properties for at-risk/overdue → healthy.
- **Mutation discipline:** every guard verified by deleting it and confirming a
  test fails. Roughly two dozen defects in this project were found that way and
  almost none by reading.

## Documentation

`docs/ARCHITECTURE.md` and `CHANGELOG.md` record the recovery path and state
plainly that POA&Ms are **not** auto-closed, with the reason and the deliberate
asymmetry with the scanner path. Also state that pre-existing open items are not
retrofitted, so nobody reads a persistently stale backlog as a bug in this work.
