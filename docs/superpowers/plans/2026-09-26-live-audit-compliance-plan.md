# Live Audit Compliance Plan

## Goal

Make Concord behave like a seasoned GRC application: scan the real provider
environment through APIs, evaluate every applicable control in the selected
framework and provider shared-responsibility model, open useful POA&Ms for
gaps, and carry the evidence and implementation impact into the SSP.

## Current Slice — landed 2026-09-26

- **Done.** `POST /api/systems/{id}/scan-all` scans a system with every
  registered provider, so an operator does not need to know a connector key.
  Provider-specific scan remains for troubleshooting.
- **Done.** Every scan reports `checks_expected`, `checks_run`,
  `skipped_checks` (each with a reason) and `unexpected_outcomes`. The three
  reasons a check produced no result — no credential, no outcome from the
  provider, a generated test a human deactivated — are each named.
- **Done.** `ControlTest.expected` is written on create and refreshed on every
  scan, so a failure is explainable from the definition rather than only from
  result rows.
- **Done.** A failed API-backed control test seeds `POAM.remediation_plan` with
  the expected state, the observed condition, recommended actions, validation
  evidence, and SSP impact.

### What review changed

The first implementation of this slice had four defects worth recording,
because three of them are shapes this codebase has produced before.

1. **A re-scan destroyed analyst edits.** Whether to overwrite
   `remediation_plan` was decided by testing whether the stored text still
   began `"Remediation objective:"`. That reads as a marker and behaves as a
   trap: the likeliest analyst edit — append a milestone, correct the action —
   keeps that first line. It is also the mistake migration 0089 had just fixed
   one table over, provenance carried in prose that nothing maintains.
   Migration 0090 adds `POAM.remediation_plan_source`
   (`generated` | `ai` | `analyst`); only `generated` is refreshable, existing
   rows backfill to `analyst`, and the AI-mutation and analyst-edit paths set
   their own label. Provenance is set by the write, never offered as a field a
   request body can claim.
2. **`scan-all` discarded every provider when one failed.** No per-provider
   isolation meant the request raised, the commit never ran, and a tenant with
   a healthy Microsoft 365 connector and a broken AWS one recorded nothing —
   while the error named only the broken half. Each provider is now isolated,
   its failure rolled back and reported in `providers_unavailable`.
3. **`skipped_checks` held a list per provider and an int at the top level.**
   One key, two types, depending on where a consumer looked. The aggregate is
   now `skipped_checks_total`, beside `providers_scanned`,
   `providers_without_checks` and `providers_unavailable`.
4. **`checks_expected == checks_run + len(skipped_checks)` was untested.** That
   invariant is what makes the three numbers addable rather than three separate
   claims; an outcome for a check this build has no definition for is reported
   in `unexpected_outcomes` precisely so it cannot break the sum while looking
   like extra diligence.

Verified by mutation: 13 deletions, 13 named failures.

## Build Plan

1. Provider Readiness
   - **Done.** Add a connector readiness endpoint that verifies credentials, permissions,
     sovereign cloud/region, tenant/account identity, and required API grants
     before a scan starts. Implemented as
     `POST /api/systems/{id}/provider-readiness`, and both single-provider
     scan and `scan-all` now run readiness before attempting live API checks.
   - **Done.** Store readiness results so "not scanning" is visible as a
     compliance gap, not a silent product failure. Implemented on
     `ConnectorConfig.readiness_status`, `readiness_checked_at`, and
     `readiness_detail`; connector credential listing returns those fields.
   - **Done.** `scan-all` gates each provider on readiness. Unready providers
     return blocked checks in `skipped_checks` with the readiness reason and
     are included in `providers_unavailable`.

2. Shared-Responsibility Control Templates
   - **Done.** Introduce provider responsibility templates per platform and framework:
     customer-owned, provider-owned, shared, inherited, and not applicable.
     Implemented in `ccf.ssp.responsibility` as versioned
     `ResponsibilityEntry` templates. Existing SSP constants now delegate to
     this layer, preserving current origination behavior.
   - **Done.** Bind posture checks to those responsibility entries so scan
     scope can be computed from the system boundary and provider model.
     Provider readiness now annotates each expected check with `responsibility`
     and `scan_applicability`.
   - **Done.** Version templates so an SSP can cite which provider model
     informed the control origination. Each entry carries `version`,
     `framework`, `platform`, `scope`, and source metadata.

3. Applicable-Control Evaluation
   - **Done.** Resolve a system's framework baseline, provider template, installed packs,
     and connector capabilities into a live audit plan.
     Implemented as `GET /api/systems/{id}/audit-plan`, returning the applied
     framework, provider readiness, API-runnable checks, and
     `manual_review_required` items.
   - **Done.** Execute all applicable checks and explicitly mark
     unsupported checks as manual-review-required when no API can assess them.
     `scan-all` now records generated control-test results with
     `manual_review_required` when a provider is unavailable or a responsibility
     template says the item should be evidenced outside an API scan, and passes
     only `scan_applicability == "scan"` checks into provider execution.
   - **Done.** Add resource-level drilldown as the default control evaluation view:
     expected state, observed state, failing resources, applicable controls,
     evidence, waiver state, and POA&M linkage. Implemented as
     `GET /api/systems/{id}/control-evaluations`.

4. Remediation and POA&M Flow
   - **Done.** Expand deterministic remediation playbooks per check/provider
     instead of generic guidance only. Implemented initial M365 and AWS
     playbooks in `ccf.posture.remediation`; generated POA&M guidance uses a
     check-specific playbook when one exists and falls back to generic guidance
     otherwise.
   - **Done.** Let the user create or update a POA&M directly from a failed control
     row, prefilled with weakness, milestones, evidence needed, validation
     method, and SSP impact. Implemented as `POST /api/control-tests/{id}/poam`
     for failed, warned, and manual-review-required evaluations.
   - **Done.** Preserve analyst edits while refreshing machine-generated observations
     on each re-scan or explicit POA&M refresh. The control-test POA&M path now
     uses the same provenance-aware helper as scans.

5. SSP Synchronization
   - **Done.** Add SSP control impact records sourced from scan results and POA&Ms:
     passing checks become evidence references; failures become implementation
     caveats and POA&M references. Implemented as
     `GET /api/ssp/projects/{id}/scan-sync`, scoped to the SSP project's linked
     system and including passing evidence, open findings, active POA&M links,
     and manual-review-required controls.
   - **Done.** Update SSP generation so each control can include automated evidence,
     unresolved gaps, shared-responsibility origination, and active POA&M
     references without overstating failed controls as implemented. Implemented
     through `ccf.governance.automation.generate_statements()` and
     `ccf.ssp.statements`: passing tests are cited as automated verification,
     failed/warned tests render as open findings with active POA&M references,
     manual-review-required checks render as manual-evidence caveats, and
     failed controls are downgraded from implemented claims.
   - **Done.** Gate final SSP readiness on unresolved
     manual-review-required checks, missing provider templates, and open
     high-risk POA&Ms. `project_completeness()` now feeds machine-evidence
     gates into SSP readiness, blocking on latest failed/warned controls,
     latest manual-review-required controls, open high/critical POA&Ms, and
     SSP controls whose platform/domain has no shared-responsibility template
     coverage.

6. End-User Flow
   - **Done.** Replace provider-key-first scanning with a simple workflow:
     select system, verify connectors, run live audit, review failed controls,
     accept guidance or create POA&M, then update SSP. Implemented the
     read-only workflow contract as
     `GET /api/systems/{id}/live-audit-workflow`, returning the next action,
     step statuses, readiness/audit-plan summary, control-evaluation counts,
     POA&M action state, and linked SSP readiness. The system detail page now
     renders that workflow with UI actions for provider readiness and live
     audit scans that return the user to the system page.
   - **Done.** Keep advanced provider-specific scans for troubleshooting.

## Acceptance Criteria

Every criterion below is **executed** by a named test, not asserted by this
document. Each was checked by mutation: the guard was broken deliberately and
the named test had to fail. A criterion recorded as met with no test that can
fail is the same claim-versus-rendering defect this plan exists to remove.

- **Executed** — A test environment with known misconfigurations produces
  matching failed resource rows and control failures.
  `tests/test_acceptance_known_misconfigurations.py`. One deliberately broken
  M365 tenant driven through the real pipeline (payload → scan → resource rows →
  control verdict → POA&M → framework posture → SSP statement). The fixture
  answers all fourteen m365 platform checks, so a new check with no known-bad
  payload fails the suite rather than scanning nothing.
  *Limitation, stated rather than implied:* the environment is recorded
  payloads. It proves Concord turns a given Graph response into the right
  conclusion, not that Graph returns that response for a tenant in that state.
  Closing that half needs a tenant somebody deliberately misconfigures, and it
  is the one piece of this plan that hardware cannot substitute for.

- **Executed** — A scan response names every applicable check that did not run
  and why. `tests/test_acceptance_unrun_checks_are_named.py`. Asserts the
  property rather than the paths: the arithmetic
  (`checks_expected == checks_run + len(skipped_checks)`) closes, every skipped
  entry names its check, and every reason is a sentence rather than a status
  word. A structural guard covers the branch nobody has written yet — a new
  `skipped_checks` entry with no `reason` fails the build.
  Found and fixed while executing this: the success return omitted `reason`
  while the unconfigured-connector return carried it, so `out["reason"]` worked
  on the unhappy path and raised on the happy one.

- **Executed** — Every failed scan-owned control can produce a POA&M with
  actionable guidance. `tests/test_acceptance_known_misconfigurations.py::
  test_every_failing_check_opens_a_poam_with_guidance`. One POA&M per failing
  check, each `open`, each carrying generated guidance with a remediation
  objective, the observed condition and the SSP impact, and the observed
  condition carries the real resource count rather than a placeholder.

- **Executed** — SSP output distinguishes passing automated evidence,
  documented-only controls, failed controls with POA&Ms, inherited controls, and
  manual review gaps. `tests/test_acceptance_ssp_distinguishes_control_kinds.py`.
  One SSP project holding one control of each kind, asserted as a matrix: every
  entry carries its own marker and none of the other four. Absence is asserted
  as hard as presence, because a composer that appended every clause to every
  control would satisfy the criterion on a read and be worthless — and because
  "Verified by automated testing" on a control nothing tested is a false
  statement in an authorization package that validates.

### Not covered by these criteria

Worth naming so nobody reads the four above as a completion certificate:

- **eMASS** has never been exercised against a live instance. The client is
  written and unit-tested; nothing has confirmed the real API accepts it.
- **Workers and the scheduler** ship disabled. `ccf-prep-worker` and
  `ccf-assessment-worker` are built but not running, and
  `CCF_SCHEDULER_ENABLED` is unset on the dev container, so nothing recurs on
  its own. See the runbook's automation-gate section.
- **Check coverage** is partial by construction, and the runbook's coverage
  table is the number to read — not these criteria, which say the plumbing is
  right, not that it reaches every control.
