# The guided onboarding path — design

**Status:** design 2026-09-21. A customer-facing "where am I, what is next"
view, per system.

**Depends on** `fix/connector-backed-claim` landing first — step 3's honest
wording depends on what that fix decides.

---

## 1. The problem, measured

63 templates. The global nav (`api/templates/base.html:28`) offers roughly 40
destinations across four groups — Compliance, Authorization, Operations,
Insights. That grouping is a product org chart, not a journey: a new customer
has forty doors and nothing says which is first.

Measured, **no onboarding or next-steps surface exists**. Grepping
`onboarding|getting.started|next.steps` across `src/` finds only personnel
onboarding (a different domain — training obligations for people), one nav
description, and a `"Getting started"` badge that is merely the `<50%` bucket
label on a coverage gauge.

## 2. It extends `system_detail`; it is not a new page

`/systems/{id}` (`api/routes/ui.py:600`) already renders implementation-status
counts, POA&Ms, evidence count and four boundary counts — **four of the signals
this path needs, as bare numbers with no state and no next action.** Adding a
seventh dashboard beside `/dashboard`, `/posture`, `/executive` and
`/governance` would be the fifth place that answers a slightly different
version of "how are we doing".

So the path is rendered **on the system detail page**, above what is there now,
and the existing counts become the evidence behind its steps rather than a
parallel display.

### 2.1 One progress story per page

`ccf.fedramp20x.readiness._derive_status` (`readiness.py:79`) already returns an
ordered lifecycle — `not_started → initial_build → evidence_collection →
validation_in_progress → assessor_review → ready_for_submission`. It overlaps
these six steps almost exactly.

**It is deliberately not rendered here.** Two progress indicators on one page
that can disagree is the dashboard-versus-source divergence this programme has
already recorded. `_derive_status` is KSI-derived and returns `not_started`
whenever `ksi_total == 0`, so it is meaningless off the 20x lane; the six steps
work for every system. Where a system is on the 20x lane, this page **links to**
`/fedramp20x`, which owns that number.

---

## 3. The six steps

| # | Step | Where the work happens |
|---|---|---|
| 1 | Answer the intake questionnaire | `/intake` |
| 2 | Connect your evidence sources | `/connectors` |
| 3 | Generate and refine the SSP | `/ssp` |
| 4 | Close the gaps | `/coverage`, `/fedramp20x`, `/poams` |
| 5 | Produce the package | packages / CR26 |
| 6 | Bring in your 3PAO | `/admin/portal` |

Ongoing monitoring is the steady state after 6, not a seventh step.

### 3.1 Why 2 precedes 3, stated correctly

An earlier version of this reasoning was **wrong** and is corrected here
because the wrong version is plausible and will be re-derived otherwise.

`has_capture_connector` (`ssp/platforms.py:183`) is pure — it checks whether
the declared `cloud_platform` is in a hardcoded set, not whether the tenant has
anything configured. **Connecting a connector does not change what SSP
generation emits**; the `cloud_platform` answer does. That is the defect
`fix/connector-backed-claim` addresses.

The ordering still holds, for two real reasons:

1. Capture feeds ODP values (`CaptureSnapshot`), control tests and evidence —
   everything steps 4 and 5 measure.
2. The remedy for a thin SSP is re-running auto-statements, and
   `governance/automation.py:662` assigns `part_narratives` unconditionally for
   every entry — one call discards everything written in between.

---

## 4. Four states, and why not three

- **done** — evidence exists.
- **in progress** — begun, with something measurable left. The remainder is
  **named**, not just counted.
- **not started** — the platform positively knows nothing exists.
- **unknown** — the platform cannot see enough to say.

**`unknown` must not collapse into either neighbour.** Collapsing it into
`not started` renders a guess as a fact; collapsing it into `done` is the OCR's
empty-array lesson — in a compliance surface an empty result reads as the
favourable answer, and it is the one the platform is least entitled to assert.

**A step is `done` only on a row that exists, never on a query returning
empty.** "No POA&Ms found" is not "no gaps"; "no connector errors" is not "a
connector works".

### 4.1 Not-applicable is derived, not marked

A customer with no cloud would see step 2 red forever, and one visibly wrong
step costs the whole page its credibility.

**But this does not need a stored marking, a migration or a UI.** The platform
already knows: `SystemProfile.cloud_platform` gives the declared platform, and
the platform→connector-key mapping says whether any connector exists for it.
Where none does, step 2 renders **not available for this platform** — a
derived, explainable state, not a human assertion to store and audit.

A stored override is deliberately deferred. If a customer needs to mark a step
not-applicable for a reason the platform cannot see, that is a separate change
with its own audit requirement.

---

## 5. Signals, each from the helper that already owns it

**No number on this page may be computed twice.** A second implementation of a
figure the app already knows is how a dashboard and its source begin to
disagree.

| Step | Signal | Source |
|---|---|---|
| 1 | `SystemProfile` for this system; `derived_at` set | `models.py:416`; the API already says "complete the questionnaire first" (`automation.py:170`) |
| 2 | org has a configured, synced connector that discovered objects | the ladder in `governance/control_tests.py:128` — reuse, never restate |
| 3 | SSP project exists; completeness score | `ssp/completeness.py:192` `assess(...)` — see §6 |
| 4 | coverage; KSI states; open/overdue POA&Ms | `governance/automation.py:747` `coverage`; `select(KSIState)`; `analytics/posture.py:58` `systems_scorecard` |
| 5 | packages; CR26 documents and their validity | `AuthorizationPackage` by `system_id`; `api/routes/cr26.py:60` `_summary` |
| 6 | a current engagement for this system | `AssessmentEngagement` filtered by `system_id`, with the currency rule from `portal/service.py:453` |

### 5.1 Two numbers that must NOT appear

- **`AuthorizationPackage.readiness_pct`** is a frozen snapshot copied at
  package-creation time (`packages/service.py:171`), correct only as of
  `created_at`. Rendering it on a live page states a stale number as current.
  If a readiness figure is wanted, it is the live one from
  `fedramp20x/readiness.py:172` `score_system(persist=False)` — and per §2.1
  that belongs on `/fedramp20x`, not here.
- **Anything derived from `has_capture_connector` alone** (§3.1).

### 5.2 Overdue POA&Ms: reuse the rule

`analytics/posture.py:78` defines overdue as
`coalesce(due_on, scheduled_completion, original_due_on) < today` over active
statuses, and `poam_aging` documents the invariant
`on_track + overdue + no_due_date == open_total`. Re-deriving it here would
give two overdue counts in one product.

---

## 6. Prerequisite: SSP completeness is trapped in a route handler

`assess(...)` is pure, but the code that feeds it real rows — entries, ODP
definitions, evidence linkage, the boundary dict — exists **only** inside
`api/routes/ssp.py:334`, about 80 lines. Reaching it from another page means
copying it or calling the app over HTTP.

**Extract it to a service function first**, in its own commit, with the route
then calling it and its behaviour unchanged. That extraction is a prerequisite,
not part of this page; a copy would put a second SSP score in the product, and
the two would diverge the first time either changed.

The boundary dict built at `ssp.py:389-412` — including the
`interconnections_with_agreements` rule at `:403` — moves with it.

---

## 7. What this must not become

- **A gate.** Nothing here blocks any existing page. It orders and recommends.
- **A progress bar that only goes up.** Revoking a connector or letting an
  engagement lapse moves a step backwards. A monotonic bar would be a false
  claim the day something expires.
- **A second definition of any number** (§5).

---

## 8. Testing requirements

1. **Each step's four states are reachable**, driven by real seeded rows — not
   by stubbing the state function. A test that mocks the signal proves only
   that the mock works.
2. **`unknown` never renders as `done`**, asserted per step.
3. **A step goes backwards.** Seed a current engagement (step 6 `done`), revoke
   it, assert the step is no longer `done`. Same for a connector. This is the
   test that stops the page becoming a ratchet.
4. **Not-available-for-platform** on an Azure system at step 2, and that it is
   distinct from both `not started` and `done`.
5. **No number is computed twice** — the page's POA&M counts equal
   `systems_scorecard`'s for the same system, asserted by equality.
6. **Tenant isolation**: the page 404s for a system outside the principal's org,
   via `systems.py:47` `require_system_in_scope` — the correct helper, which
   also excludes soft-deleted systems. `ui.py:600` open-codes this check
   inline; do not copy that.
7. **The extraction in §6 changed nothing** — the SSP completeness route
   returns identical output before and after, asserted against a seeded project.

Mutation-verify each state rule: break it, confirm a test fails.

---

## 9. Out of scope

- **A stored not-applicable override** (§4.1).
- **Changing the nav.** If the path works, the nav question can be revisited
  with evidence; restructuring 40 links on a hunch is a separate decision.
- **Rendering `_derive_status` or any second readiness figure** (§2.1, §5.1).
- **Any change to what the six steps' destination pages do.**
