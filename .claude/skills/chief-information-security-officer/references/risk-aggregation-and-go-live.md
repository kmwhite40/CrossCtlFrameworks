# Risk Aggregation & Go-Live Gate — reference

Companion to the `chief-information-security-officer` skill.

## Dashboard-vs-source integrity checks

The overview rollup lives in `src/ccf/analytics/overview.py`; reports in
`src/ccf/reporting/`. For each headline metric, trace and reconcile:

| Metric | Source of truth | Reconcile against |
|---|---|---|
| Open POA&Ms / overdue | `poams`, `poam_milestones` | Dashboard count vs. `SELECT` count; overdue = scheduled date past |
| Open risks / accepted | `risks` | Rollup vs. rows; accepted risks have owner + expiration |
| Control coverage | `control_implementations` status | Dashboard % vs. computed; exclude N/A consistently |
| ATO posture | `systems.ato_status` | Per-system status vs. summary tile |
| SSP readiness | `ssp/completeness.py` score | Tile vs. actual completeness run |
| Findings by severity | `audit_findings` | Chart vs. rows; no dropped/duplicated severities |

Rule: **dashboard, report, and export must return the same number for the same
question.** A divergence is a finding — cite both values.

## Risk aggregation rules

- Roll up by **highest-water-mark within a system**, then across systems by
  count-at-severity — never average severities into a single mushy score.
- Residual risk (post-control) is what leadership accepts, not raw finding count
  (see `poam-risk-management`).
- Overdue + High/Critical items must be individually visible, not buried in a
  total. If leadership can't see the worst items, that's a decision-support gap.
- Trend needs a baseline: a number with no prior period is not a trend.

## AI / document governance checks

- Every AI-drafted artifact carries provenance (provider, model, prompt-template
  version, generation date, source records) and a validation/approval status —
  `ai_actions/` is citation-first and `ai_require_human_approval` defaults true.
  Confirm the *UI* surfaces this, not just the database.
- AI-generated ≠ approved. An executive report must label draft/AI content. An
  unlabeled AI claim presented as fact is a **material** finding.
- Confirm org-scoped isolation of AI credentials and that no secret appears in
  reports, logs, or exports (validate with `information-assurance-engineer`).

## Production go-live gate

Issue one of: **Go · Conditional Go · No-Go.** A finding maps to a gate outcome:

| Gate blocker | Outcome |
|---|---|
| Any Critical IA finding open (cross-tenant, secret leak, auth bypass) | **No-Go** until fixed |
| Dashboard/report/export disagree on a material number | **No-Go** or condition |
| AI content indistinguishable from approved in a user-facing surface | Condition (blocker if it reaches external parties) |
| Systemic broken handoff (findings never reach POA&Ms) | Condition |
| Missing production gate (no branch protection / no release approval) | Condition |
| Stale/duplicated metric, cosmetic UX | Acceptable, track |

A **Conditional Go** must enumerate every condition, its owner, and its acceptance
criterion. Residual risk carried into production is accepted by the Authorizing
Official, recorded as a `risks` row with an expiration (see `grc-authorization`).

## Program maturity note

Score the program, not just the app: are there owners for each lifecycle stage,
repeatable approvals, evidence freshness discipline, and audit-trail completeness?
Immature-but-improving is a condition; absent-and-unowned is a blocker.
