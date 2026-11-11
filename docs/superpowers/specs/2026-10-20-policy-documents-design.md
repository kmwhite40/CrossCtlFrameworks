# Policy, plan and procedure documents: design

Date: 2026-10-20. This is part 2 of the m365-docs-hub port and builds on part 1 (the ATO workspace).

## Intent

The user asked us to "incorporate documentation features" from m365-docs-hub, without duplicating anything Concord already has. An inventory compared each source documentation feature against Concord.

**Already in Concord, and better there.** SSP generation, reports, document ingestion (the `prep/` pipeline), package and OSCAL exports, FedRAMP 20x and CR26 documents.

**What Concord lacks:**
- A policy, plan and procedure library. Concord stores `Policy` and `PolicyVersion` rows but has no templates, no generator, no page, no approval, and no record of which version is in force.
- Two SSP inventories: ports/protocols/services and cryptographic modules.

The source's document text is reusable. SBS Federal wrote it, so licensing is fine. But it asserts M365 products and "Implemented" status as fact for every tenant, and it bakes in values that only an organization can choose.

## What was built

| Piece | How it integrates |
|---|---|
| `ccf/policies/library.py`: 32 templates (23 policies, 7 plans, 2 procedures) | Adapted from the source's SBS-authored text. Product claims are removed, and requirements are stated rather than presented as already done. Every organization-chosen value is a `{{parameter}}` with no default (95 keys, reused across templates). |
| Rendering | `ccf.ssp.odp.render`, the same mechanism the SSP builder uses. An unset value prints as `[ORGANIZATION-DEFINED: key]`. |
| Versions | Each render is a new immutable `PolicyVersion` that records `body_sha256` and `unresolved_parameters`. |
| Activation | `Policy.active_version_id` is set only by activation, which refuses a version with unset values. With auth on, it spends an approval of **that version** (`policy_version` approval entity; admin authority; separation of duties). Approving the policy as a whole would not do: a version written after the review could then be activated on it. |
| Attestation | Records the signed-in person only, and only for the version in force. |
| Existing API fixes | Every route now resolves the policy in the caller's organization (before this, `add_version` and `attest` did not). A policy can no longer be created already active. |
| Packages | `capture_facts` adds the policies in force as `policy` facts (name, version, body hash), so a policy change after authorization shows in package diff and replay. |
| Pages | `/policies` (register and library) and `/policies/{id}` (values, versions, review, activation, acknowledgement, DOCX/Markdown). |
| SSP inventories | `ports_protocols_services` and `crypto_modules` on the system boundary (API and boundary page). A module can be `validated` only with a CMVP certificate number, which the API and a database constraint both enforce. Concord does not verify certificates; it links to NIST's record instead. |

## Calls made here

- Templates have no defaults. A default would be one value chosen on behalf of every customer.
- **Not ported from the source:**
  - the traceability matrix ("Implemented" ×111)
  - "Implementation Details"
  - the synthetic POA&M rows
  - the self-attestation SPRS heuristics
  - Report Builder's fallback scores
  - contract SOW/PWS documents
  - the M365 script library and as-built documents
  - Document Intelligence: Concord's `prep/` pipeline already supersedes it
- **Policy approval is admin-only.** A policy belongs to the organization, not to a system, so no system role applies.
- **A retired policy governs nothing.** It drops out of package facts.

## Deferred

- An 800-171 Rev. 3 SSP framework.
- An executive DOCX with a data-reconciliation appendix.
- A RACI document generated from `ato/roles`.
- OSCAL export of the two new inventories.
