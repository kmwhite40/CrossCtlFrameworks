# Workflow, RACI & Finding Record — reference

Companion to the `information-systems-security-manager` skill.

## Lifecycle map — step → Concord table → downstream trigger

| Step | Primary table(s) | Must reach next |
|---|---|---|
| Org creation | `organizations` | System registration; org-scoped everything |
| System register/categorize | `systems`, `system_profiles` | Baseline selection (FIPS-199 → baseline) |
| Baseline / tailor / assign | `control_implementations`, `framework_controls` | Implementation + SSP entries |
| Inheritance | origination on the control (see `ssp-authoring`) | Provider vs. customer responsibility split |
| Implement | `control_implementations.narrative` | Evidence + SSP statement |
| Evidence | `evidence`, `evidence_reviews`, `evidence_versions` | Assessment; freshness/review status |
| SSP | `ssp_projects`, `ssp_control_entries` | Review → approval → export |
| Assess | `assessments`, `assessment_control_results` | Findings for failed objectives |
| Finding | `audit_findings` (+ scan `scan_ingestions`) | POA&M (fix) or Risk (accept) |
| POA&M | `poams`, `poam_milestones` | Milestones → remediation → closure |
| Risk | `risks` | Owner + acceptance/expiration |
| Authorize | `systems.ato_status` | ConMon cadence |
| ConMon | `governance/conmon.py`, `scheduler.py` | Reassessment / drift → new findings |

At every arrow, the source record must let you *reach* the destination. A finding
with no POA&M/risk, a control with no evidence, a POA&M with no milestone, an
assessment that leaves `ato_status` untouched — each is a broken handoff.

## RACI observation shape

For a flagged step, note who is **A**ccountable vs. who the platform lets act:

| Stage | Accountable (should) | Approves | Common gap |
|---|---|---|---|
| Tailoring | System Owner | ISSM | Author self-approves scope |
| Evidence review | Control Owner | ISSO/ISSM | No separate reviewer role |
| SSP statement | Control Owner | ISSM → AO | Statement has no responsible party |
| Finding→POA&M | ISSM | ISSM/AO | Finding never generates a POA&M |
| Risk acceptance | AO (authority to accept) | AO | Unowned / open-ended acceptance |
| ATO | Authorizing Official | AO | Authorized with untracked open weakness |

Separation of duties: `require_role` + the approval flow in
`governance/approvals.py` should stop an author approving their own record — verify
it actually does, with `information-assurance-engineer`.

## Orphan / traceability checks

- Every `ssp_control_entry` → a real control + system + responsible role.
- Every `audit_finding` → a POA&M or a risk (disposition unambiguous).
- Every `risk` acceptance → an owner with authority + an expiration.
- Every mutation → an `audit_log` chain entry (untraceable change = finding).
- Every record → an org scope (no null-tenant rows on tenant tables).

## Shared finding-record format (all four role skills)

```
id            unique (e.g. ISSM-014)
title         short defect/gap name
domain        IA | ISSM | CISO | FedRAMP
severity      Critical | High | Medium | Low | Informational
likelihood    High | Medium | Low  (how likely the failure is realized)
confidence    Confirmed | Highly Likely | Possible | Needs Validation
component     page | API | service | table | workflow | report | SSP | provider
expected      what should happen
actual        what happens now
evidence      files / tables / tests / records
ssp_impact    effect on SSP accuracy / authorization readiness (or "none")
recommendation specific remediation + acceptance criterion
```

**Domain extensions** (append to the record; only the owning domain fills them):
- IA adds `validation_procedure` (how to prove the fix) + `regression_test` (the
  test that fails today and passes after remediation).
- FedRAMP adds `approval_recommendation` (approve / changes-required / reject) —
  a *verdict*, distinct from the finding's classification label.
- CISO adds `production_impact` (blocker / condition / acceptable).

This is the trimmed form of the program's Phase-25 register. The full register and
its validator script are built in the assessment slice; here, just emit records in
this shape so the four skills' output merges cleanly.
