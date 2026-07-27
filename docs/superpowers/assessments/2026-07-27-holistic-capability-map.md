# Concord (ccf) — Holistic Capability Map & Roadmap

- **Date:** 2026-07-27
- **Purpose:** View Concord as a whole *federal authorization operating system* — the end-to-end lifecycle a system owner walks from "we have a system" to "we have an ATO and keep it." Shows where the platform is strong, partial, or missing, and names the **keystone** capabilities that would make it complete.
- **Companion backlogs:** [improvement-opportunities-backlog](2026-07-27-improvement-opportunities-backlog.md) (11 items), plus the second-wave findings synthesized here.

## The shape of the gap

Concord is **strong through the middle of the lifecycle** — control catalog/mapping (now with OSCAL reconciliation), POA&M/risk with real SLAs and provenance, the finding→risk→POA&M→ATO spine, evidence WORM, audit hash-chain, multi-tenant RLS. It is **thin at the two ends**:

- **Front end (define the system):** there is no model of the *actual system* — no authorization boundary, component inventory, data flows, interconnections, or per-information-type categorization. Everything hangs off controls, but the SSP can't say *what* the controls protect.
- **Back end (the platform's own production/identity posture):** single-factor local auth, no MFA/PIV/SSO enforcement, stubbed KMS, unproven FIPS, no SIEM export, no 508 conformance — the tool can't yet meet the control set it assesses others against.

Filling those two ends — plus turning the assessment side into a deliverable package — is what turns "a very good control/POA&M tracker" into "a complete authorization platform."

## Capability map (authorization lifecycle)

| Pillar | Coverage | What's missing to be whole |
|---|---|---|
| **1. System definition & boundary** | 🔴 Missing | Component inventory, ports/protocols/services, data flows, interconnections/ISAs, HW/SW/firmware inventory, per-information-type FIPS-199/800-60 categorization. Boundary is a free-text field today. **Keystone #1.** |
| **2. Control catalog & mapping** | 🟢 Strong | OSCAL 800-53r5 reconciliation just landed. Remaining: extend endpoint validation to ISO/CIS/CSF/CMMC catalogs; v2 canonical-join enforcement; a trustworthy cross-framework "what do I satisfy" navigator UI. |
| **3. SSP authoring** | 🟡 Partial | Statements are templated, not system-specific; inheritance partial; no inventory/boundary to reference; no Customer Responsibility Matrix (CRM) export. |
| **4. Baseline & FedRAMP pipeline** | 🟡 Partial | Generator is really CMMC/800-171 relabeled. A **real 800-53r5 FedRAMP pipeline** (baseline selection, ODP handling, statement composition → SSP/OSCAL) is now feasible on the reconciliation catalog. **Keystone #2.** |
| **5. Assessment (SAP/SAR)** | 🟡 Partial | 800-53A objectives now in the catalog, but no SAP/SAR generation, no evidence→determination-statement mapping, no assessment test automation. **Keystone #3.** |
| **6. Evidence & continuous monitoring** | 🟡 Partial→Strong | WORM/retention solid; connectors only M365 + AWS GovCloud (Azure Gov/GCP missing); ConMon off-by-default with no drift/delta detection. |
| **7. POA&M & risk** | 🟢 Strong | SLA table (30/90/180), scan→POA&M dedup, risk spine, aggregation. Minor: unify ConMon-sourced POA&M SLAs with the severity table. |
| **8. Authorization (ATO) & governance** | 🟡 Partial | ATO write path exists; missing significant-change-request workflow, boundary/authorization-approval gates, continuous-authorization cadence. |
| **9. Identity & access (the tool itself)** | 🔴 Weak | No MFA/PIV-CAC, no account lockout (AC-7), no password policy (IA-5), coarse role-strings (no ABAC/SoD/per-object grants), OIDC lacks nonce/PKCE/id_token validation. **Keystone #4.** |
| **10. AI assistance** | 🟡 Partial | Org gateway built and safe, but the typed `ai_actions` path returns stub text (never reaches the gateway); no human review-queue UI. |
| **11. Reporting & package** | 🟡 Partial | OSCAL SSP/POA&M/component-def export; missing OSCAL **assessment-results (SAR)**, a single **authorization-package bundle**, CRM, and a VPAT. |
| **12. Platform operability & own compliance** | 🔴 Weak | Stubbed KMS + no key rotation (SC-12), unproven FIPS 140-3 (SC-13), no SIEM/syslog audit export (AU-6), no audit-log retention/records schedule (AU-11), no 508/WCAG conformance, no backup/DR posture, no SAST in CI. |

## Keystones — the four additions that most move Concord toward holistic completeness

### Keystone #1 — System boundary & inventory model *(the missing front-end)*
Model an authorization boundary with an enumerated inventory: components, ports/protocols/services, data flows, interconnections/ISAs, and per-information-type categorization. This is the single largest completeness gap: it's the backbone the SSP's `system-implementation`, the OSCAL SSP, the CRM, and assessment scoping all reference. Without it the platform describes controls but not the system. **Effort L · Impact High.**

### Keystone #2 — Real 800-53r5 FedRAMP SSP pipeline
Consume the just-merged reconciliation catalog + baselines + crosswalk to add genuine baseline selection, ODP handling, and 800-53r5 statement composition → SSP/OSCAL. Closes the "we say FedRAMP but produce CMMC" gap. **Effort L · Impact High.**

### Keystone #3 — Assessment → SAR → authorization-package bundle
Generate SAP/SAR from the 800-53A objectives (now in the catalog), map evidence to determination statements, and emit a single downloadable **OSCAL authorization package** (SSP + SAR + POA&M). Turns the lifecycle into a deliverable. **Effort M–L · Impact High.**

### Keystone #4 — Make the platform itself authorizable
The tool must meet the controls it assesses: MFA/PIV-CAC + account lockout + password policy (IA-2/AC-7/IA-5), invert secure-by-default (the standing blocker), real KMS + key rotation and FIPS-validated crypto (SC-12/13), SIEM audit export + retention (AU-6/11), and 508 conformance. Several are Small individually; together they're what makes Concord deployable for real federal, CUI, or FedRAMP use. **Effort M (clustered) · Impact High.**

## Fastest high-leverage moves (small effort, high impact)
1. **Invert secure-by-default + CORS fail-closed** (`config.py`) — one-file change; removes the last fail-open path. *(backlog #1)*
2. **Account lockout on login** (`api/routes/auth.py`) — AC-7; the tool is currently brute-forceable.
3. **Wire `ai_actions` → org gateway** (`ai_actions/provider.py`) — unlocks the entire already-built AI feature.
4. **Unify ConMon POA&M SLAs** with the severity table (`governance/conmon.py`) — small consistency fix.
5. **Add SAST (bandit/semgrep) to CI** — RA-5/SA-11; first-party code is currently unscanned.

## Sequencing recommendation
Keystone #4's *quick* items (secure-by-default, lockout) and the AI wiring first — days, high value. Then Keystone #1 (boundary/inventory) as the foundation, which unblocks the fuller value of #2 (FedRAMP SSP) and #3 (SAR/package). That order builds the front-end keystone before the deliverables that depend on it, while shipping the cheap production-hardening wins immediately.
