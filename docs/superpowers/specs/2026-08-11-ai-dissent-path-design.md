# AI Dissent Path — Design

**Date:** 2026-08-11
**Status:** Approved (design), pending implementation plan
**Slice:** 6 of the ATO Bot capability delta
**Depends on:** slices 1–5, all on `feat/evidence-prep-spine`

## Context

Every assessment objective gets exactly one verdict from one model call, with a
self-reported `model_confidence` (`src/ccf/assessment/engine/evaluate.py:98`,
stored at `models_assessment_engine.py:220`). Nothing challenges that verdict.

Self-reported confidence is a weak error signal. A model that is confidently
wrong is the failure slice 4 was built to detect, and it is the expensive one: a
`satisfied` verdict on a control that is not satisfied becomes a **missed
finding** in an authorization package. Slice 4 measures that after the fact, from
assessor rejections. This slice tries to catch it before an assessor ever sees it.

## Goals

1. Run an independent challenger against verdicts where being wrong is expensive.
2. Record disagreement as a first-class signal, visible to the assessor.
3. Make the effect measurable through the calibration harness slice 4 built.

## Non-goals

- **No voting, no averaging, no tie-breaking third call.** See below.
- **No new refusal state.** Disagreement reuses `insufficient_evidence`.
- **No challenge of the retrieval step.** The challenger sees the same citations
  the primary saw; contesting *which* evidence was retrieved is a different
  problem and would confound the measurement.
- **No retrofit.** Objectives evaluated before this slice carry no dissent record.

## 1. The challenger

For a qualifying verdict, a second call receives the same objective and the same
retrieved passages, and is asked to make the strongest case for the opposite
conclusion, citing only from that same passage set.

Same citation set is load-bearing: it isolates the variable. If the challenger
could retrieve differently, a disagreement would be ambiguous between "the
evidence does not support this" and "the challenger found different evidence,"
and only the first is what this slice is trying to detect.

### Which verdicts are challenged: `satisfied` only

Dissent on every objective doubles model calls, and AC-4 alone has 98 objectives.
Slice 4's asymmetry says where to spend: challenging a `satisfied` verdict guards
against a **missed finding**; challenging a `not_satisfied` verdict guards only
against a **false alarm**, which costs wasted remediation effort rather than a
hole in an authorization package.

`insufficient_evidence` verdicts are not challenged — the engine has already
declined to conclude, which is the outcome dissent would produce anyway.

This is a policy, not a law of nature, and it should be named and versioned as
one so a later change is legible rather than silent.

## 2. Disagreement routes to `insufficient_evidence`

**Two verdicts are never averaged, majority-voted, or tie-broken.** Reducing two
independent reads to one number manufactures precision that is not there — the
same reasoning that keeps slice 4 from collapsing `missed_findings` and
`false_alarms` into a single accuracy figure.

When the challenger reaches a different verdict with citations, the objective
becomes `insufficient_evidence`. That state already exists and already does
everything needed:

- it means "the engine could not tell", which is exactly what two independent
  reads disagreeing establishes;
- the rollup already forces the whole control to `insufficient_evidence` on any
  such objective (`rollup.py`), so no rollup change is required;
- `accept_control_proposal` already refuses to accept it, so a contested verdict
  cannot reach a Security Assessment Report;
- slice 4 already excludes it from `CORRECTED_FINDINGS`, so it cannot be recorded
  as an assessor's correction.

No new vocabulary, no new gate. **The bar is any credible disagreement** — a
differing verdict with at least one citation. Requiring the challenger to clear a
confidence threshold would make the escalation depend on self-reported
confidence, which is the signal this slice exists because we do not trust.

The original verdict and the challenger's verdict are both retained. Overwriting
the primary verdict would destroy the evidence that a disagreement happened, and
that record is what the assessor needs in order to adjudicate it.

**How that is stored, made explicit.** `verdict` is the field the rollup reads,
so on disagreement it *is* set to `insufficient_evidence` — that is what makes
the existing rollup work unchanged, with no change to `rollup.py`. The primary's
original conclusion therefore needs somewhere to live: a fourth column,
`primary_verdict` (nullable `String(32)`), written whenever a challenge runs.

It is tempting to skip it, since under the `satisfied`-only policy a contested
objective's primary verdict was `satisfied` by construction and could be
inferred. Do not rely on that. The policy is explicitly expected to change, and
the moment it does, every previously contested row becomes unreadable — the
primary verdict would be unrecoverable from stored data. Record it rather than
infer it.

## 3. Data model

Four nullable columns on `assessment_objective_proposals`, all NULL for
un-challenged objectives, plus one on the control proposal. Migration `0059`.

- `primary_verdict` (`String(32)`) — what the primary call concluded, before
  any disagreement rewrote `verdict`.
- `challenger_verdict` (`String(32)`) — the challenger's conclusion.
- `challenger_rationale` (`Text`) — its argument, shown to the assessor.
- `challenger_ai_action_run_id` (nullable `BigInteger`, FK to
  `ccf.ai_action_runs.id`, `ON DELETE SET NULL`, indexed) — provenance, recorded
  through slice 3's `record_ai_run`, not through the approval-gated `run_action`.
- `assessment_control_proposals.dissent_count` (`Integer`, NOT NULL, default `0`)
  — how many objectives were contested, so a reviewer sees it without a join.

NULL rather than a sentinel, so "not challenged" and "challenged and agreed" stay
distinguishable — a distinction the calibration measurement depends on.

`downgrade()` must round-trip, and the migration re-issues
`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app`.
Note that migrations `0057` and `0058` both omit the `pg_roles` existence guard
that `0054` establishes as this repo's standard; `0059` should carry it and the
omission in the earlier two stays on the debt list.

## 4. Configuration and its effect on calibration

`CCF_ASSESSMENT_DISSENT_ENABLED`, defaulting to **false**. This doubles model
calls on the passing subset, and a deployment must opt into that cost.

**The calibration fingerprint must include it.** `config_fingerprint`
(`src/ccf/assessment/engine/calibration.py:152`) hashes `prep_screen_threshold`,
the rollup policy identity, and the evaluation model name. Dissent changes what
is being measured just as surely as any of those, so enabling it must make prior
snapshots report **not comparable** rather than showing an unexplained shift in
`missed_findings`. Adding the flag to the fingerprint payload is a required part
of this slice, not a follow-up — the challenge policy name should go in too, so a
later change to "which verdicts get challenged" is equally visible.

This is also how the slice gets evaluated: slice 4's harness answers whether
dissent actually reduces missed findings, or only reduces throughput.

## 5. Failure isolation

A challenger failure must never fail the evaluation. The primary verdict is the
deliverable; the challenge is an enhancement. A provider error, a timeout or a
malformed response leaves the objective with its primary verdict, NULL challenger
columns, and a warning log — the same discipline slices 3 and 5 use.

It runs inside the savepoint that already protects each objective. **`AsyncSession.rollback()`
is not savepoint-scoped** and unwinds the whole transaction; slice 3 shipped a
version that silently discarded the caller's work while reporting success. Use
`begin_nested()`.

A NULL `challenger_verdict` therefore means "not challenged **or** the challenge
failed", and those must be distinguishable in the logs even though they are not
in the column — the calibration reading depends on knowing which.

## Testing

- **Only `satisfied` is challenged:** a `not_satisfied` and an
  `insufficient_evidence` objective each leave the challenger columns NULL and
  make no second model call. Assert the call count, not just the columns.
- **Agreement is recorded, not just disagreement:** a challenger that agrees
  leaves the verdict `satisfied` and `dissent_count` at 0, with
  `challenger_verdict` populated — so "challenged and agreed" is distinguishable
  from "not challenged".
- **Disagreement flips the objective to `insufficient_evidence`, retains both
  verdicts, and increments `dissent_count`** — asserted as separate assertions,
  since four field mappings in this project were correct but untested until a
  reviewer mutated them.
- **The rollup consequence:** one contested objective forces the whole control to
  `insufficient_evidence`, and `accept_control_proposal` then refuses it. This is
  the end-to-end property that makes the slice worth building; assert it against
  the specific assessment and control, not a whole table.
- **Never averaged:** a fixture where a naive majority or average would produce
  `satisfied` must still produce `insufficient_evidence`. Make the fixture
  **asymmetric** — a symmetric one in slice 4 passed against transposed code and
  proved nothing.
- **Failure isolation:** force the challenger call to raise; the primary verdict
  persists, columns stay NULL, the stage completes, a warning is logged. Confirm
  the test fails if the call is moved outside its savepoint.
- **Fingerprint:** toggling `CCF_ASSESSMENT_DISSENT_ENABLED` between two
  snapshots makes them report **not comparable**, not drift.
- **Disabled by default:** with the flag unset, no challenger call is made and
  every existing test's behaviour is unchanged.
- **Mutation discipline:** every guard verified by deleting it and confirming a
  test fails. This project has found roughly seventeen defects that way and none
  by reading — including one guard whose deletion left every test in its file
  green because a best-effort handler swallowed the resulting exception.

## Documentation

`docs/ARCHITECTURE.md`, `README.md` and `CHANGELOG.md` describe the challenger,
the `satisfied`-only policy and why, the routing to `insufficient_evidence`, and
the fact that it is **off by default**. They must state plainly that a NULL
challenger verdict does not mean agreement, and that objectives evaluated before
this slice are not retrofitted.

## Follow-ups this slice does not close

The standing debt list carries forward: `prep_screen_threshold`'s narrow ~0.03
margin; base-control collapse meaning enhancements are never cited;
re-preparation duplicating passages; scanned-PDF pages skipped without a marker;
job dedup wanting a partial unique index; migrations `0057` and `0058` missing
the `pg_roles` GRANT guard; and the two unreconciled legacy POA&M-from-findings
paths, one of which dedupes on title alone.
