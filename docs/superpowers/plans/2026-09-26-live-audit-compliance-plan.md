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
   - Add a connector readiness endpoint that verifies credentials, permissions,
     sovereign cloud/region, tenant/account identity, and required API grants
     before a scan starts.
   - Store readiness results as evidence artifacts so "not scanning" is visible
     as a compliance gap, not a silent product failure.

2. Shared-Responsibility Control Templates
   - Introduce provider responsibility templates per platform and framework:
     customer-owned, provider-owned, shared, inherited, and not applicable.
   - Bind posture checks to those responsibility entries so scan scope is
     computed from the system boundary and provider model.
   - Version templates so an SSP can cite which provider model informed the
     control origination.

3. Applicable-Control Evaluation
   - Resolve a system's framework baseline, provider template, installed packs,
     and connector capabilities into a live audit plan.
   - Execute all applicable checks and explicitly mark unsupported checks as
     manual-review-required when no API can assess them.
   - Add resource-level drilldown as the default control evaluation view:
     expected state, observed state, failing resources, applicable controls,
     evidence, waiver state, and POA&M linkage.

4. Remediation and POA&M Flow
   - Expand deterministic remediation playbooks per check/provider instead of
     generic guidance only.
   - Let the user create or update a POA&M directly from a failed control row,
     prefilled with weakness, affected resources, milestones, evidence needed,
     and validation method.
   - Preserve analyst edits while refreshing machine-generated observations on
     each re-scan.

5. SSP Synchronization
   - Add SSP control impact records sourced from scan results and POA&Ms:
     passing checks become evidence references; failures become implementation
     caveats and POA&M references.
   - Update SSP generation so each control can include automated evidence,
     unresolved gaps, shared-responsibility origination, and active POA&M
     references without overstating failed controls as implemented.
   - Gate final SSP readiness on unresolved manual-review-required checks,
     missing provider templates, and open high-risk POA&Ms.

6. End-User Flow
   - Replace provider-key-first scanning with a simple workflow:
     select system, verify connectors, run live audit, review failed controls,
     accept guidance or create POA&M, then update SSP.
   - Keep advanced provider-specific scans for troubleshooting.

## Acceptance Criteria

- A test environment with known misconfigurations produces matching failed
  resource rows and control failures.
- A scan response names every applicable check that did not run and why.
- Every failed scan-owned control can produce a POA&M with actionable guidance.
- SSP output distinguishes passing automated evidence, documented-only controls,
  failed controls with POA&Ms, inherited controls, and manual review gaps.
