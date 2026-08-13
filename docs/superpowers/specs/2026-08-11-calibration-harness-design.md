# Calibration Harness — Design

**Date:** 2026-08-11
**Status:** Approved (design), pending implementation plan
**Slice:** 4 of the ATO Bot capability delta
**Depends on:** slices 1–3, all on `feat/evidence-prep-spine`

## Context

Slice 2 built an engine that proposes control findings from AI-evaluated
assessment objectives. Slice 3 recorded which model produced each verdict and who
accepted it. Nothing measures whether the verdicts are any good.

That gap is not academic. `prep_screen_threshold` was derived once, empirically,
against one catalog snapshot, with a measured margin of about 0.03 — so it will
need re-deriving, and today nothing would show whether re-deriving it made
assessment quality better or worse. The rollup policy has never been evaluated
against known-correct outcomes at all.

It is also why this slice comes before the closure and remediation loop.
Remediation built on unmeasured verdicts turns a wrong verdict into a wrong
remediation task with an owner and a due date attached.

### The finding that shapes this slice

**`"rejected"` is declared in `PROPOSAL_STATES` but nothing ever writes it.**
`accept_control_proposal` exists; there is no reject path. So the system records
an assessor saying "this verdict is right" and captures nothing when they decide
it is wrong.

That makes the acceptance gate a half-built labelling mechanism. It already
produces ground truth as a side effect of work assessors do anyway — the cheapest
labelled data available — but only positive labels. A harness measuring
agreements alone cannot see the failure that actually costs something: the engine
confidently producing wrong verdicts that assessors quietly correct without
leaving a trace.

## Goals

1. Let an assessor record that a proposed finding was wrong, with the finding
   they believe correct and why.
2. Measure agreement between proposed and assessor-decided outcomes, reporting
   the two error directions **separately** because their costs differ sharply.
3. Make that measurement comparable across time, so a configuration change shows
   up as an explained shift rather than unexplained drift.

## Non-goals

- **No synthetic evidence generation.** A later slice.
- **No automatic threshold tuning.** The harness measures; a human decides.
- **No CI gate** failing a build on a metric change — that needs a baseline this
  slice exists to produce first.
- **No retrofit.** Proposals decided before the reject path exists carry no
  recorded disagreement, so the first snapshot's denominator starts at zero.

## Scope, in order

The reject path must exist before calibration has anything to measure. Both are
in this slice, but they are separable: if the plan runs long, the reject path
alone is a coherent, shippable deliverable.

## 1. The reject path — completing slice 2's human gate

```python
async def reject_control_proposal(
    session: AsyncSession,
    proposal_id: int,
    *,
    rejected_by: str,
    corrected_finding: str,
    note: str,
) -> AssessmentControlProposal
```

Sets `state="rejected"`, records `corrected_finding` and `note`, and stamps the
linked `AiActionRun`s with `disposition="rejected"`, `reviewer=rejected_by` and
`decided_at` — mirroring what slice 3's acceptance already does with
`"accepted"`, so the audit trail records disagreement as faithfully as agreement.
`mutation_applied` stays `False`, because nothing authoritative was written.

**Rejection must not write to `AssessmentControlResult`.** A rejected proposal
produces no finding; the assessor records theirs through the existing assessment
workflow. Writing one would put the engine's wrong answer into the SAR with a
human's name attached to it.

`note` is **required**. A rejection without a reason tells calibration that the
engine was wrong but not how, and "how" is what makes the metric actionable. That
is deliberate friction, accepted.

`corrected_finding` must be one of the real `finding_status` values —
`satisfied`, `other_than_satisfied`, `not_applicable`. Never
`insufficient_evidence`: that is a proposal-only state, and an assessor
correcting a verdict is asserting what is true, not declining to say.

New columns on `AssessmentControlProposal`: `corrected_finding` (nullable
`String(32)`), `rejected_by` (nullable `String(255)`), `rejected_at` (nullable
timestamp), `rejection_note` (nullable `Text`). Migration `0057`.

A proposal already `accepted` cannot be rejected, and vice versa — the same
terminal-state discipline slice 2's four acceptance refusals enforce.

## 2. Calibration — a computation over rows that already exist

No new pipeline. The labelled data lives in the proposals: `proposed_finding`
versus the assessor's decision (`accepted` = agreed; `rejected` +
`corrected_finding` = disagreed).

```python
@dataclass(slots=True)
class CalibrationMetrics:
    decided: int                    # accepted + rejected
    agreed: int
    agreement_rate: float
    missed_findings: int            # proposed satisfied -> corrected other_than_satisfied
    false_alarms: int               # proposed other_than_satisfied -> corrected satisfied
    other_disagreements: int        # any remaining corrected pair
    by_family: dict[str, FamilyMetrics]
```

**The two error directions are reported separately and never averaged.** They
cost very different things:

- **`missed_findings`** — the engine said `satisfied`, the assessor corrected to
  `other_than_satisfied`. A control passes that should not. In an authorization
  package that is a missed finding, and it is the number to watch.
- **`false_alarms`** — the reverse. Wasted remediation effort: annoying, not
  dangerous.

Collapsing these into a single accuracy figure would hide exactly the number
worth watching. `agreement_rate` is reported alongside them, not instead of them.

`by_family` groups by the control family prefix of `control_identifier` (`AC`,
`SC`, …), folded through `ccf.prep.screen.normalize_control_identifier` first,
because a model reliable on `AC` and unreliable on `SC` is a different problem
from one uniformly mediocre — and the per-family split is what tells them apart.

## 3. Drift — a snapshot with a configuration fingerprint

One table, `calibration_snapshots`: `organization_id`, `computed_at`,
`config_fingerprint` (`String(64)`), and `metrics` (JSONB). Migration `0057`
alongside the proposal columns.

**The fingerprint is the load-bearing part.** A metric is comparable to an
earlier one only if what was being measured did not change underneath. It is a
SHA-256 over `prep_screen_threshold`, the rollup policy identity, and the
evaluation model name.

Comparing two snapshots with different fingerprints reports **not comparable**
rather than drift. Without this, re-deriving the screen threshold — which slice
2's narrow margin means will happen — would surface as an unexplained accuracy
shift instead of an expected consequence.

`ccf calibration-snapshot` computes and stores one, gated on
`assessment_engine_enabled` like the other engine commands.

## API

- `POST /api/assessment-engine/proposals/{id}/reject` — body
  `{corrected_finding, note}`, mirroring the accept endpoint's shape.
- `GET /api/assessment-engine/calibration` — current metrics for the principal's
  organization, computed live.

Both take `Depends(get_principal)` and derive the organization from it, never
from a body field, following `evidence_repo.py` and slice 2's endpoints. 404 for
another tenant's proposal, not 403.

## Error handling

Rejecting an already-decided proposal raises `AcceptanceRefused`'s sibling — a
`ProposalError` subclass — surfacing as 409, matching how repeat acceptance
already behaves.

A calibration computation over zero decided proposals returns
`decided=0, agreement_rate=0.0` rather than dividing by zero, and the endpoint
reports it plainly as "no decisions recorded yet" rather than as 0% accuracy.
Those are very different statements and the difference matters to whoever reads
the number.

## Testing

- **Reject path:** records all four columns; stamps linked runs with
  `disposition="rejected"`; writes **no** `AssessmentControlResult`; requires a
  note; refuses `insufficient_evidence` as a corrected finding; refuses an
  already-accepted proposal; and — asserted as an attack — an org-A principal
  cannot reject org B's proposal.
- **Metrics:** a hand-built set of decided proposals produces exactly the
  expected `missed_findings` / `false_alarms` split, and the two are never
  conflated. Zero decisions yields `decided=0` without dividing by zero.
- **Per-family:** padded and unpadded identifiers (`AC-02`, `AC-2`) fold into one
  family; a CMMC-style identifier does not corrupt the grouping.
- **Fingerprint:** two snapshots taken under the same configuration are
  comparable; changing `prep_screen_threshold` between them makes the comparison
  report **not comparable**, not drift.
- **Mutation discipline:** every recorded field must be asserted individually.
  Four field mappings across this project were correct but untested until a
  reviewer mutated them, so each new column and each metric gets its own
  assertion.

## Follow-ups this slice does not close

The known debt list stands: `prep_screen_threshold`'s narrow margin (this slice
gives the means to evaluate a change to it, but does not change it); base-control
collapse meaning enhancements are never cited; re-preparation duplicating
passages in retrieval; scanned-PDF pages skipped without a persisted marker; and
the best-effort job dedup wanting a partial unique index.
