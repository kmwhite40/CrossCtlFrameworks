# Closure & Remediation Loop — Design

**Date:** 2026-08-11
**Status:** Approved (design), pending implementation plan
**Slice:** 5 of the ATO Bot capability delta
**Depends on:** slices 1–4, all on `feat/evidence-prep-spine`

## Context

Slice 2 built an engine that proposes control findings. Slice 3 recorded which
model produced each verdict and who accepted it. Slice 4 measured whether the
verdicts are any good. This slice makes an accepted finding become tracked work,
and makes completed work come back for re-evaluation.

### The two halves that are missing

**Acceptance is a dead end.** `accept_control_proposal`
(`src/ccf/assessment/engine/service.py:319`) upserts an `AssessmentControlResult`
and stops. Its own docstring says that row is "the only path by which engine
output reaches the existing SAR generator or an auto-created POA&M" — but no
caller anywhere invokes the POA&M creation path after acceptance. Turning an
accepted finding into tracked work requires a human to remember to
`POST /{assessment_id}/poams-from-findings`
(`src/ccf/api/routes/assessments.py:205`). So the engine can produce an
`other_than_satisfied` finding that never becomes tracked work at all.

**Correction to an earlier draft of this document**, which claimed that endpoint
reads the *legacy* `AssessmentResult` table. It does not: `_results`
(`assessments.py:91`) selects `AssessmentControlResult`, the same table the
engine writes. The gap is narrower than that claim implied — the endpoint would
work, nothing calls it — and it is still worth closing, because a loop that
depends on someone remembering to trigger it is a loop that silently stops.
It also means the bridge and that endpoint must not fight: both key on
`source_ref`, so whichever runs first wins and the other is a no-op. That is why
the bridge extends the existing convention rather than inventing one.

**Nothing ever comes back.** Re-testing is purely calendar-driven:
`control_tests.run_due` and `conmon.scan` re-evaluate on a frequency cadence.
Nothing re-runs a control test, re-derives health, or re-evaluates an assessment
objective *because* its remediation completed. And `record_result`
(`src/ccf/governance/control_tests.py:269`) opens a Task and a POA&M on fail or
warn with no symmetric path on a later pass.

The loop is open at both ends. This slice closes it.

## Goals

1. An accepted `other_than_satisfied` finding becomes a POA&M, idempotently,
   without a human having to remember to trigger it.
2. Closing an assessment-sourced POA&M enqueues a re-evaluation of the control
   that produced it.
3. A re-evaluation that now reads `satisfied` surfaces as a **proposal**, so a
   human closes the loop.

## Non-goals

- **No new remediation model.** `POAM.remediation_plan` and `PoamMilestone`
  already carry the plan. A parallel plan-with-steps model would fragment
  closure tracking across two tables and duplicate the closure gate.
- **No email.** No SMTP/SES/SendGrid transport exists anywhere in `src/ccf`;
  delivery today is in-app `Notification` rows plus outbound webhooks. Adding a
  transport is its own slice.
- **No overdue escalation or reminders.** `overdue` is computed at read time
  (`poams.py:_out`) and nothing proactively notifies. Out of scope.
- **No unification of the two legacy POA&M-from-findings paths.** They are noted
  as debt; this slice must not add a third, but rewriting them is not its job.
- **No retrofit.** Findings accepted before this slice get no POA&M created
  retroactively.

## Scope, in order

The three parts are separable and shippable in sequence: the bridge alone closes
the dead end; the re-evaluation trigger alone is inert without it.

## 1. The bridge — acceptance creates a POA&M

Inside `accept_control_proposal`, after the `AssessmentControlResult` upsert,
an accepted `other_than_satisfied` finding creates a POA&M.

**Idempotency is the whole correctness story.** Acceptance can be re-run — the
result row is an upsert by `(assessment_id, control_id)` — so the POA&M creation
must be keyed, not blind. It uses the established convention:

```
source_ref = f"assessment_control_result:{result.id}"
source     = "assessment"
```

An existing POA&M with that `source_ref` is **found and left alone**, never
duplicated and never silently mutated: a POA&M a human has since edited, assigned
or partially remediated must not be overwritten because someone re-accepted the
proposal. Re-acceptance is a no-op on an existing POA&M.

`source_ref` rather than title matching, because `ui.py`'s inline duplicate
dedupes on title alone and would collide across two systems with the same control.

Severity comes from the existing `SEVERITY_SLA_DAYS` mapping (`src/ccf/ingest/scanners.py:34`, re-exported from `ccf.ingest`) that every other
creation site uses, and `due_on` from it, so a finding-sourced POA&M ages on the
same clock as a scan-sourced one.

**Only `other_than_satisfied` creates one.** `satisfied`, `not_applicable` and
`insufficient_evidence` do not. `insufficient_evidence` in particular is the
engine saying it could not tell — turning that into tracked remediation work
would manufacture a finding out of the engine's own uncertainty.

### Failure isolation

A POA&M-creation failure must not fail the acceptance. Acceptance writes the
authoritative `AssessmentControlResult`; losing the derived POA&M is recoverable,
and discarding a human's accepted finding because a derived row would not insert
is not. It runs in a `begin_nested()` savepoint and logs at warning on failure —
the same discipline slice 3's `record_ai_run` uses, and for the same reason.

Note the trap that shaped that rule: `AsyncSession.rollback()` is **not**
savepoint-scoped and unwinds the entire transaction. Slice 3 shipped a version
that silently discarded the caller's work while reporting success. Use
`begin_nested()`.

## 2. Closure enqueues a re-evaluation

When an assessment-sourced POA&M transitions to `closed`, enqueue a re-evaluation
job for the control it came from.

Only POA&Ms whose `source_ref` matches `assessment_control_result:{id}` qualify —
a scan-sourced or profile-gap POA&M has no objective-level proposal to re-derive,
and enqueueing one would run the engine against a control nobody assessed.

`AssessmentJob` is keyed to a proposal (`control_proposal_id`, NOT NULL —
`models_assessment_engine.py:203`), not to a control identifier, so closure
follows the same two-step the first pass does: create a new
`AssessmentControlProposal` in its initial state with `source_poam_id` set, then
enqueue an `AssessmentJob` against it. There is no third queue table and no
control-identifier-keyed job.

That shape also supplies the idempotency key: an open re-evaluation proposal
already carrying this `source_poam_id` means the work is queued, so closing the
POA&M again enqueues nothing.

The job reuses `ccf.queue`'s `claim_jobs` / `reap_stale_jobs`
(`SELECT ... FOR UPDATE SKIP LOCKED`, atomic `attempts += 1`, dead-letter after
`max_attempts`) and the existing `AssessmentJob` table and worker rather than
introducing a third queue. The worker pattern is fixed and must be followed:
commit the claim immediately, commit each job's outcome independently, and
**call `reap_stale_jobs` inside the loop** — a fix wave in slice 1 left it
outside a `--loop` and silently disabled the dead-letter net.

Enqueueing is best-effort and idempotent: closing a POA&M twice, or closing one
whose control already has a pending re-evaluation, must not produce two jobs.

**The closure gate is untouched.** Whatever ISSM-08/09 already requires to reach
`closed` — all milestones completed, or dated evidence on or after
`identified_on`, plus a separation-of-duties `Approval` when auth is enabled
(`poams.py:216`) — still applies unchanged. This slice observes the transition;
it does not widen the path to it.

## 3. A passing re-evaluation proposes closure

The re-evaluation runs the existing objective evaluation and rollup, producing a
new `AssessmentControlProposal` exactly as a first-pass evaluation does. It
writes no `AssessmentControlResult` and closes nothing.

**The engine never retires its own finding.** Auto-closing on a passing re-test
would route around the closure gate and let the model that raised a finding
decide it is resolved. A human accepts, and acceptance is where the authoritative
write already happens.

This is deliberately asymmetric with the scanner path
(`src/ccf/ingest/scanners.py:397`), which *does* auto-close a POA&M absent from
the latest scan. That asymmetry is intentional and should be documented rather
than smoothed over: a vulnerability missing from a scan is direct evidence the
weakness is gone, whereas a model re-reading prose evidence is an opinion about a
control. The two warrant different levels of trust.

The proposal is marked as a re-evaluation so a reviewer sees it is the second
look at a remediated control rather than a fresh assessment — carrying the
closed POA&M's id, so "what was remediated, and did it work" is answerable
without reconstructing the chain by hand.

## Data model

No new tables. One column plus a constraint swap the column forces.

**The constraint swap.** `uq_control_proposal_assessment_control` is unique on
`(assessment_id, control_identifier)` (`models_assessment_engine.py:138`,
migration `0055:69`; confirmed present in the live schema). A re-evaluation is a
second proposal for a control that already has one, so that constraint would
reject it outright. It is replaced by two partial unique indexes:

- `uq_control_proposal_first_pass`, scoped `WHERE source_poam_id IS NULL` —
  preserving the original guarantee for first-pass proposals exactly.
- `uq_control_proposal_source_poam`, on `source_poam_id` — capping one
  re-evaluation per POA&M.

The second index is not merely permissive; it is where this slice's idempotency
actually lives. "Closing a POA&M twice enqueues one re-evaluation" becomes a
database invariant rather than an application-level check that a race could slip
past — which is the shape the standing debt list has wanted for job dedup.

`open_control_proposal`'s own lookup must also filter `source_poam_id IS NULL`,
or it raises `MultipleResultsFound` once a re-evaluation row coexists with a
first-pass one.

The column: `assessment_control_proposals.source_poam_id`
(nullable `BigInteger`, FK to `ccf.poams.id`, `ON DELETE SET NULL`, indexed),
NULL for first-pass proposals. Migration `0058`.

Nullable because every existing proposal has no source POA&M, and because a
re-evaluation must remain usable if the POA&M is later deleted.

Every column-adding migration in this repo re-issues
`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app`,
and `downgrade()` must round-trip.

## API

- `GET /api/assessment-engine/proposals?source_poam_id={id}` — the re-evaluations
  for a remediated control. Derives the organization from
  `Depends(get_principal)`, never from a query or body argument. 404 for another
  tenant's POA&M, not 403, so a response cannot confirm the id exists.

No new endpoint creates or closes a POA&M; the existing `poams.py` routes and
their gate remain the only way.

## Multi-tenancy

The POA&M's `organization_id` comes from the accepted proposal, never from an
argument. The re-evaluation job carries the same organization and is claimed
per-tenant like every other job. Three endpoints in slice 1 leaked across tenants
by trusting a body field, and one laundered through a foreign-key id belonging to
another org — so the re-evaluation must reconcile the POA&M's organization
against the proposal's before enqueueing anything.

## Testing

- **Bridge:** an accepted `other_than_satisfied` creates exactly one POA&M with
  the right `source_ref`, severity and `due_on`; `satisfied`, `not_applicable`
  and `insufficient_evidence` create none.
- **Idempotency, asserted as a repeat:** accepting twice yields one POA&M, and a
  POA&M edited between the two acceptances is **not** overwritten — assert a
  changed field survives, not merely that the count is one.
- **Failure isolation:** force the POA&M write to raise; the
  `AssessmentControlResult` and the acceptance still persist and a warning is
  logged. Confirm the test fails if the write is moved outside its savepoint.
- **Closure trigger:** closing an assessment-sourced POA&M enqueues exactly one
  job; closing it twice enqueues one; closing a scan-sourced POA&M enqueues none.
- **Re-evaluation:** produces a proposal carrying `source_poam_id`, and writes
  **no** `AssessmentControlResult` — asserted against the specific assessment and
  control, since an earlier test in this project asserted zero against a table
  that was empty for unrelated reasons.
- **Tenant isolation, asserted as an attack:** an org-A principal cannot reach
  org B's re-evaluations, and a POA&M belonging to org B cannot enqueue a job
  against org A's proposal.
- **Mutation discipline:** every guard and every recorded field gets its own
  assertion, verified by deleting the guard and confirming a test fails. Roughly
  a dozen defects in this project were found this way and none by reading.
  Fixtures must be **asymmetric** wherever two values could be swapped
  undetected — a symmetric fixture in slice 4 passed against transposed code and
  proved nothing.

## Documentation

`docs/ARCHITECTURE.md`, `README.md` and `CHANGELOG.md` gain the loop, and state
plainly what it does not do: no retrofit of already-accepted findings, no
auto-close, no email, no escalation. The asymmetry with the scanner auto-close
path is documented with its reason.

## Follow-ups this slice does not close

The standing debt list carries forward: `prep_screen_threshold`'s narrow ~0.03
margin; base-control collapse meaning enhancements are never cited;
re-preparation duplicating passages in retrieval; scanned-PDF pages skipped
without a persisted marker; job dedup wanting a partial unique index; migration
`0057`'s `GRANT` lacking the `pg_roles` existence guard that `0054` establishes
as the standard. Added here: the two competing legacy POA&M-from-findings paths
(`assessments.py:205` and the inline duplicate in `ui.py`) remain unreconciled,
and `ui.py`'s dedupes on title alone.
