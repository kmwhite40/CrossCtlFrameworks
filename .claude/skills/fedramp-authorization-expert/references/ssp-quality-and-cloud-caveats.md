# SSP Quality & Cloud Caveats — reference

Companion to the `fedramp-authorization-expert` skill.

## Statement quality rubric (the 12 questions, scored)

A statement is FedRAMP-ready only when every determination part answers all 12.
Fast triage — reject on any of these smells:

| Smell | Example | Verdict |
|---|---|---|
| Restates the control | "The organization enforces MFA as required by IA-2." | Boilerplate → changes-required |
| Generic compliance language | "Robust, industry-standard security is applied." | Unsupported → changes-required |
| Claim without evidence | "All data is encrypted." (no mechanism, no capture) | Claims-without-evidence |
| Wrong origination | "Implemented / system-specific" for KMS-managed encryption | Incorrectly-inherited |
| Missing responsibility split | Inherited control with no customer-responsibility line | Missing-customer-responsibility |
| Cross-environment copy | GovCloud statement verbatim in a commercial SSP | Copied-without-adaptation |

Good statements name the actual mechanism, the responsible role, the frequency,
and where evidence lives (see the AC-7 example in `ssp-authoring`'s
`odp-and-origination.md`). Fill every ODP with the org's real value.

**Verdict vs. label.** The rows above emit *classification labels*
(boilerplate, claims-without-evidence, incorrectly-inherited …) — these describe
*what is wrong*. Separately, every review ends on one of exactly three *verdicts*:
**approve / changes-required / reject**. A finding can carry several labels but
only one verdict. Reject = pure boilerplate answering ~none of the 12;
changes-required = real implementation described but under-evidenced or
mis-originated; approve = all 12 answered and every claim traces to evidence.

**Control-specific load-bearing elements.** Some controls have a single element
that, if missing, is an automatic changes-required regardless of prose quality:
- **SC-13 / SC-28 / SC-8 (crypto)** — named, **FIPS 140-2/140-3 validated**
  cryptographic modules, and in a government cloud, *where the keys live* and which
  partition. "Industry-standard encryption" without FIPS validation is boilerplate.
- **IA-2 (identification/auth)** — AAL/MFA type and enforcement scope.
- **AU-* (audit)** — retention period, protected storage, review cadence.
- **CP-* (contingency)** — RTO/RPO, backup location, tested restore.

## Inheritance & shared-responsibility patterns

Match origination to who does the work (see `ssp-authoring`):

- **Inherited** — provider fully performs it; customer consumes. Cite the provider
  + the CRM/responsibility row. Customer statement = "inherited from <provider>;
  no customer action."
- **Hybrid** — provider does part, customer configures/operates the rest. Document
  the exact customer-responsible portion; both halves must appear.
- **Customer** — customer fully performs it in the provider's environment (e.g.
  Conditional Access policy, IAM roles, bucket policy).
- **Provider** — provider performs it; do not claim it as system-specific.

A single system-level statement should describe multi-cloud implementation
coherently with provider-specific components identified — **not** contradictory
per-provider statements.

## Per-cloud service-availability caveats

Do not assume commercial == government. Concord's connectors today cover **M365/
Graph** (`connectors/msgraph.py`) and **AWS GovCloud** (`connectors/aws.py`); Azure
and GCP capture are not yet implemented — statements for those must be manually
evidenced, not assumed.

| Environment | Do not assume | Validate |
|---|---|---|
| AWS GovCloud | Every commercial service/region exists; cross-partition identity federation is automatic | Service + region availability; ITAR/personnel constraints; where logs/keys live |
| Azure Government | Commercial endpoints/regions; feature parity with commercial | Gov endpoints, tenant/subscription boundary, PIM/Conditional Access config |
| M365 GCC / GCC High / DoD | GCC, GCC High, DoD are interchangeable | Tenant type, data residency, feature availability by tier, CUI/FCI handling |
| GCP (regulated) | It is a "government cloud" by default | Assured Workloads scope, region/data-residency, personnel-access controls |

Language rule: only call an environment a "government cloud" when the selected
service, region, authorization, and configuration actually support it.

## OSCAL & package readiness

- OSCAL export (`src/ccf/oscal/`) must stay consistent with the human-readable SSP:
  same system name, boundary, inventory, control set, and origination. A divergence
  is a finding.
- Ports/protocols/services, interconnections, and inventory in the SSP must match
  the boundary and each other.
- Package readiness = every control has status + responsible role + origination +
  filled ODPs + evidence, front matter complete (run `ssp/completeness.py`), and
  no open Critical without a POA&M.

## The one thing never to do

A generated SSP is a **draft**. Never state or imply FedRAMP authorization because
Concord produced an SSP — authorization is an AO decision on top of assessment
(SAR) and POA&M. Route any such implication to `chief-information-security-officer`.
