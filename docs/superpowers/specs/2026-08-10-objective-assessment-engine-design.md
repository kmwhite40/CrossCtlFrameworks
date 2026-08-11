# Objective-Level Assessment Engine — Design

**Date:** 2026-08-10
**Status:** Approved (design), pending implementation plan
**Slice:** 2 of the ATO Bot capability delta
**Depends on:** Slice 1, [the evidence preparation & retrieval spine](2026-08-10-evidence-prep-spine-design.md) — branch `feat/evidence-prep-spine`

## Context

Slice 1 gave Concord the ability to read a document: parse it with structure
preserved, screen it against the 800-53A catalog, expand hits into passages,
classify them, embed them, and retrieve them by control with citations back to a
page and table cell. That substrate exists but nothing consumes it.

This slice is the first consumer. It evaluates individual 800-53A **assessment
objectives** against retrieved evidence and rolls the objective verdicts into a
proposed control finding, which an assessor confirms.

### The insight this slice is built on

**The objectives are already in the database.** `ccf.controls` holds not only
addressable controls but sub-clause rows where `control_name IS NULL` and
`assessment_objective` carries the actual objective text, grouped by
`sequence_control`:

```
SEQ: AC-01  AO: "personnel or roles to whom the access control policy is to be
                 disseminated is/are defined;"
SEQ: AC-01  AO: "an official to manage the access control policy and procedures
                 is defined;"
SEQ: AC-01  AO: "the frequency at which the current access control policy is
                 reviewed and updated is defined;"
```

These are the ~4,224 rows slice 1's screen stage deliberately filters out, because
they are not controls anyone can cite. They are exactly what an objective-level
engine needs. No new ingestion, no new catalog, no hand-authored objective list —
the same shape of win as slice 1 screening against the catalog the ETL already
loads.

### What Concord already has, and must not duplicate

Concord **already performs objective-level assessment — for CMMC**.
`ScoringControl.objective_parts` (JSONB `{label, text}`) seeds
`AssessmentControlResult.objective_findings` (JSONB `{label, text, finding}`),
which `ccf.assessment.sar` renders into the Security Assessment Report, and
`/api/assessments` auto-creates one POA&M per `other_than_satisfied` finding.

That path works today for the 110 CMMC L2 practices. What does not exist is the
equivalent for 800-53A, or any AI evaluation of evidence against an objective.
This slice adds exactly that and reuses everything else.

## Goals

1. Enumerate the assessment objectives for a control from the existing catalog.
2. Assemble bounded evidence per objective using slice 1's retrieval.
3. Evaluate each objective against that evidence, recording citations,
   contradictions and gaps as structured data.
4. Roll objective verdicts into a proposed control finding using **application
   code**, not model output.
5. Require an assessor to accept a proposal before it becomes a finding.

## Non-goals

Deliberately excluded, each a later slice: closure question generation (S3),
remediation drafting (S3), generated-artifact validation (S4), an AI dissent path
(S5), the calibration harness and synthetic evidence (S6), the project-context
assistant (S7). This slice produces proposed objective verdicts with citations,
and an accept action. Nothing else.

## Two decisions that shape everything

**Results land in `AssessmentControlResult`.** Accepted proposals project into the
existing `objective_findings` JSONB and `finding` column, so the SAR generator,
POA&M auto-creation and the assessments UI work unchanged.

**The engine proposes; it never decides.** An objective verdict here becomes an
assessment finding, and a failed control auto-creates a POA&M — real remediation
work. So proposals are inert until an assessor accepts them. This matches ATO
Bot's own stated principle that models analyse but never hold final authority,
and Concord's existing AI-action approval posture.

Those two compose into a draft/final split: proposals live in new tables;
acceptance projects them into the existing results store.

## Architecture

```
ccf.controls (control_name IS NULL rows)      ← objectives, already ingested
        │  objectives_for("AC-2") → [(label, text, sha256), …]
        ▼
  assessment_objective_proposals   ←── retrieve()  (slice 1, bounded evidence)
        │                           ←── model: verdict + citations + gaps
        │  rollup policy — application code, thresholds from a run snapshot
        ▼
  assessment_control_proposals  ──[assessor accepts]──▶ AssessmentControlResult
                                                         (SAR + POA&M, unchanged)
```

New module `src/ccf/assessment/engine/`, new models in
`src/ccf/models_assessment_engine.py`, tables in the `ccf` schema. The existing
`src/ccf/assessment/` package (SAR generation, CMMC seeding) is not modified.

### 1. Objective extraction — no new table

`objectives_for(session, control_identifier) -> list[Objective]` queries
`ccf.controls` for sub-clause rows sharing a `sequence_control`, in catalog order.
Label derives from `ap_acronym` when present (`AC-01a`) and from ordinal position
otherwise, since `ap_acronym` is sparse in the real workbook.

Objectives are **not materialised**. A proposal stores the objective's `label` and
a `text_sha256`, so a catalog re-ingest that changes wording makes stale proposals
*detectable* rather than silently wrong. Materialising would duplicate catalog data
and drift from it; this cannot.

Identifier normalisation reuses slice 1's `normalize_control_identifier` from
`ccf.prep.screen` — the catalog mixes `AC-02`, `CP-9` and `AC.L2-3.1.1` forms, and
this slice must not reintroduce the padding mismatch that slice 1's final review
found.

### 2. Evidence assembly

Per objective, call slice 1's
`retrieve(session, org_id=…, control_identifier=…, query_text=<objective text>,
system_id=…)`. Passing the objective text as `query_text` is the point: it is a far
better retrieval query than a bare control id, and it is what the hybrid retriever
was built to serve.

### 3. Evaluation

One model call per objective via `ccf.ai.gateway.generate_structured`, returning
only structured output: `verdict` ∈ `satisfied | not_satisfied | not_applicable |
insufficient_evidence`, cited `prep_unit` ids, contradictions, gaps, rationale,
confidence. The model sees one objective and its retrieved passages — never the
whole control, never the catalog.

Cited unit ids are validated against the ids actually retrieved, exactly as slice
1's classify stage validates control identifiers against screening candidates. A
model cannot cite a passage that was not put in front of it.

### 4. Rollup — application code

800-53A semantics are strict: a control is satisfied only when every objective is.
Defaults:

| Objective verdicts | Proposed control finding |
|---|---|
| all `satisfied` (ignoring `not_applicable`) | `satisfied` |
| any `not_satisfied` | `other_than_satisfied` |
| any `insufficient_evidence`, none `not_satisfied` | `insufficient_evidence` (proposal state only) |
| all `not_applicable` | `not_applicable` |

`insufficient_evidence` is a **proposal-only** state. `AssessmentControlResult.finding`
is a free-text `String(32)`, so nothing in the schema would stop it being written
there; the constraint is enforced in application code, and the acceptance path
refuses such a proposal. It means "the engine could not tell", which is different
from "the control fails", and conflating them would manufacture POA&Ms out of
missing evidence. (`AssessmentResult.finding` — the older, implementation-linked
table — *is* a Postgres enum of `satisfied | other_than_satisfied |
not_applicable`; this slice does not write to it.)

Thresholds live in settings and are snapshotted onto the run, so a settings change
mid-flight cannot retroactively reinterpret a run in progress — the same guarantee
slice 1's `config_snapshot` provides.

### 5. Acceptance

`accept_control_proposal(session, proposal_id, assessor)` projects the proposal
into `AssessmentControlResult`: `objective_findings` gets one entry per objective
in the existing `{label, text, finding}` shape, and `finding` gets the rolled-up
value. Acceptance is recorded with actor and timestamp on the proposal. A proposal
whose control finding is `insufficient_evidence` cannot be accepted.

## Execution

Per-objective model calls across thousands of objectives is worker work, not
request work.

A sibling `assessment_jobs` table, **not** a `kind` discriminator on `prep_jobs`.
Adding one would require making `prep_jobs.run_id` nullable, mutating the exact
machinery that took three fix rounds to harden. Instead the claim / reap /
dead-letter logic is factored into a shared `src/ccf/queue.py` helper parameterised
by model class, so `prep_jobs` and `assessment_jobs` cannot drift.

The properties that helper must preserve, all verified in slice 1 and all
load-bearing:

- `SELECT ... FOR UPDATE SKIP LOCKED` claiming, exactly-once under concurrency
- the claim committed **before** stage work, so `attempts` is durable across a crash
- per-job commits, so one job's failure cannot roll back another's completed work
- stale reaping on a cadence **inside** the worker loop, not once at startup
- a dead-letter cap with an operator-legible `last_error`
- rollback before recording a failed job, so `last_error` survives an aborted
  transaction

Refactoring `prep_jobs` onto the shared helper is **conditional**, and the gate is
explicit: extract the helper, build `assessment_jobs` on it first, then move
`prep_jobs` across **only if slice 1's existing job tests pass unchanged** — no
edits to those tests, no adjusted assertions. If they do not, stop and leave
`prep_jobs` as it is; a second implementation is a smaller cost than regressing
crash-recovery semantics that took three fix rounds and an adversarial review to
get right. Carrying two implementations is how queues drift, but drift is
recoverable and a silent durability regression is not.

## Multi-tenancy

Every new table carries `organization_id`. Proposals derive their org from the
`Assessment` → `System` → `Organization` chain and never from a client-supplied
field. The API endpoints take `Depends(get_principal)` and resolve the org from
the principal, following `evidence_repo.py` — slice 1's final review found three
endpoints trusting a body field, and that must not recur.

Retrieval is already org-scoped on all four of its query paths including
hydration; this slice passes the proposal's org through and adds no new path.

Like the prep tables, these carry **no RLS policies** — isolation is
application-layer. That exemption is documented in the models module and in
`docs/ARCHITECTURE.md`, not left to be inferred.

## Error handling

A model failure on one objective marks that objective's proposal `failed` with the
error and leaves the rest of the control's objectives intact — a per-objective
savepoint, following the per-line savepoint slice 1's screen stage needed. One bad
objective must not fail a control, and one bad control must not fail a run.

Retrieval returning nothing is not an error: it yields `insufficient_evidence` with
an explicit "no evidence retrieved" gap, which is the honest answer and exactly
what an assessor needs to see.

A stale `text_sha256` marks the proposal `stale` rather than silently evaluating
against changed objective wording.

## Testing

Against real Postgres, following slice 1's conventions.

- **Objective extraction:** a control with known sub-clause rows yields them in
  catalog order with stable labels; a control with no sub-clauses yields none;
  padded and unpadded identifiers both resolve.
- **Evidence assembly:** the objective text reaches `retrieve` as `query_text`.
- **Evaluation:** with a stubbed gateway, a model citing a `prep_unit` id that was
  not retrieved has that citation dropped — the scope-narrowing guarantee.
- **Rollup:** each row of the table above, asserted directly, including that
  `insufficient_evidence` never produces a `finding_status` value.
- **Snapshot:** a proposal evaluated under a snapshotted threshold is unaffected by
  a later settings change.
- **Acceptance:** projects into `objective_findings` in the existing shape and sets
  `finding`; the SAR generator renders the result unchanged; a POA&M is created for
  `other_than_satisfied`; an `insufficient_evidence` proposal cannot be accepted.
- **Tenant isolation:** an org-A principal cannot read, evaluate or accept an org-B
  proposal — asserted through the real authenticated HTTP path, not `session_scope`,
  since that is the only reason slice 1's `search_path` bug was regression-covered.
- **Queue refactor:** slice 1's existing job tests must pass unchanged against the
  shared helper, and the durability properties above must be re-proven for both
  queues.
- **End to end:** a real `Assessment` over a system with prepared evidence produces
  objective proposals with citations that resolve to real `prep_units`, rolls up to
  a control proposal, and on acceptance appears in a generated SAR.

## Follow-ups this slice does not close

Carried forward from slice 1 and still open: classification does not route through
`ai_actions.run_action`, so there is no `ai_action_runs` audit trail for AI-produced
content — this slice's evaluation calls have the same gap and should be wired
together in one pass; `prep_signal` has no production caller; re-preparing a
document duplicates passages in retrieval; scanned-PDF pages are skipped without a
persisted marker.

The audit-trail gap is the one worth closing soonest. This slice generates content
that becomes assessment findings, and "show me every AI-generated verdict and who
accepted it" is a question a FedRAMP assessor will ask.
