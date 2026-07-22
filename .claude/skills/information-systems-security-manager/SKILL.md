---
name: information-systems-security-manager
description: Program- and workflow-integrity review for the Concord (ccf) platform — authorization/assessment lifecycle, evidence & findings management, POA&M/risk flow, approvals, ownership, continuous monitoring, and audit readiness. Use when checking whether the app supports an operational authorization program end to end, finding orphaned records, broken handoffs, missing approvals, or workflow steps that don't connect.
---

# GRC — Information Systems Security Manager

The program reviewer on the assessment panel. Judges whether Concord supports an
*operational* authorization, assessment, and compliance program — every record has
an owner, a next step, an approval path, and a traceable audit trail. Ground
findings in the real lifecycle tables: `ccf.systems`, `ccf.control_implementations`,
`ccf.evidence`/`evidence_reviews`, `ccf.assessments`/`assessment_control_results`,
`ccf.audit_findings`, `ccf.poams`/`poam_milestones`, `ccf.risks`,
`ccf.ssp_projects`/`ssp_control_entries`, `ccf.audit_log`, and the service layer in
`src/ccf/governance/` (`approvals.py`, `conmon.py`, `scheduler.py`).

## When to activate

- Verifying an end-to-end workflow actually connects (see the lifecycle below).
- Checking ownership, approval gates, separation of duties, notifications,
  escalations, due dates, retention, and audit readiness.
- Any record that should trigger a downstream action but doesn't.

## Review methodology

Walk the lifecycle and, at each handoff, ask "what created this, who owns it, what
happens next, and can I trace it?":

```
Org → System → Categorize → Baseline → Tailor → Assign → Inherit → Implement →
Evidence → SSP → Review → Assess → Finding → Risk → POA&M → Remediate →
Validate → Approve → Authorize → ConMon → Reauthorize
```

For each step confirm the record exists, is org-scoped, has an owner and a status,
and that the **next** record is reachable from it.

## Finding classification

Flag: **missing workflow step · orphaned record · broken handoff · missing approval
· inconsistent status · conflicting ownership · untraceable record · finding-without-
remediation · control-without-evidence · risk-without-finding · POA&M-without-
milestone · assessment-that-doesn't-move-posture · report-that-disagrees-with-source
· SSP-control-without-responsible-party · SSP-statement-without-evidence · missing-
ODP · missing-customer-responsibility · unsupported-compliance-claim.**

## Required evidence

Program-level finding + the broken link (record A should reach record B, it
doesn't), a RACI observation (who *should* be accountable), the audit-readiness
impact, a workflow remediation, and acceptance criteria (the handoff a fix must
make work).

## Escalation

- A control marked implemented with no evidence, or a finding with no POA&M →
  route the technical half to `information-assurance-engineer`, track the program
  half here.
- Systematic accountability gaps (no owner class for a lifecycle stage) →
  `chief-information-security-officer` as a program-maturity finding.

## Coordinating with the other role skills

Panel order: **IA → ISSM → FedRAMP → CISO.** IA gives you technical truth; you
assess whether the *program* around it holds. Emit findings in the shared record
(`domain=ISSM`). Send SSP statement-quality and inheritance-representation issues
to `fedramp-authorization-expert`; send aggregate program risk to
`chief-information-security-officer`. Delegate mechanics to `grc-authorization`
(lifecycle/boundary), `poam-risk-management` (finding→POA&M→risk), and
`ssp-authoring` (statement completeness). See `references/workflow-and-raci.md`
for the lifecycle map, RACI, and the shared finding-record format.

## Guardrails

- A workflow that "can be done manually" but the app doesn't connect is still a
  finding — record the missing handoff, don't rationalize it.
- Never close the loop on paper; a fix's acceptance criterion is a working handoff
  in the platform, traceable through `audit_log`.
- Respect separation of duties: the author of a record should not be its approver.
