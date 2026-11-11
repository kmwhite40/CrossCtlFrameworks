# AWS impact level and evidence artifacts: design

Date: 2026-10-20. This is part 5 of the m365-docs-hub port.

## Intent

m365-docs-hub's last AWS layer is a set of static datasets:

- an IL5 service list and validator
- Zero Trust and CCI matrices
- an SCA checklist
- a Terraform generator
- a required-evidence-artifact table

All seven arrived in one commit, and each was checked against its primary source before anything was ported. Most failed:

| Dataset | Finding |
|---|---|
| IL5 "prohibited" services | 6 of 11 are authorized at IL5 on AWS's DoD CC SRG services-in-scope page (updated 2026-10-14). 5 it called authorized are not. It names about 50 of the 146 authorized services. |
| Test matrix and SCA checklist | 49 of 76 and 36 of 53 CCIs are mapped to the wrong control (DISA U_CCI_List, 2025-01-23). |
| Zero Trust catalog | Invented IDs, and a four-tier model that is not DoD's. |
| Terraform generator | Would not apply. Its SCPs are never attached. |
| IL5 validator | Passes when data is missing. |

The user chose "only what can be made true". That means three things:

- rebuild the IL5 service scope from AWS's own page;
- add the two IL5 checks the SRG supports (GovCloud partition, customer-managed keys);
- port the evidence-artifact table with its errors corrected.

Zero Trust, the CCI matrices and Terraform are not ported.

## What was built

| Piece | Integration |
|---|---|
| `System.dod_impact_level` | A nullable column (migration 0106), constrained to IL2/IL4/IL5/IL6. It is set by an admin at `PUT /api/systems/{id}/dod-impact-level` or on the ATO workspace card, and the change is audited. Unset means "not declared", never a default level. |
| `connectors/aws_service_scope.py` + `data/aws_dod_srg_scope.json` | AWS's table, stored with its URL, its stated "Last updated" date, the date it was read, and the page's SHA-256. `ccf aws-scope-refresh --from-file PAGE [--write]` re-parses a saved copy and prints which IL5 entries changed. A ✓ is `authorized`. A blank cell on a listed service is `not_in_scope`. Text such as "3PAO Assessment" is `other`. A service with no row (ELB, Auto Scaling) is unlisted. |
| `aws.partition.govcloud_for_impact_level` | SA-9(5). Uses STS `GetCallerIdentity`. A commercial ARN for an IL4/IL5 system is a `fail`. IL2 is `not_applicable` (either partition is fine), and so is a system with no level declared (not a DoD system, or not yet stated). IL6 (the Secret Region) is `manual_review_required`. |
| `aws.services.dod_srg_scope` | SA-9. Uses Config `GetDiscoveredResourceCounts`. A listed service with a blank cell at the system's level is the only `fail`. Unlisted services and "other" text go to review, citing the table's date. |
| `aws.kms.customer_managed_keys_at_rest` | SC-12 and SC-28(1), mapped to CMMC SC.L2-3.13.10. At IL5 or IL6, EBS, RDS and S3 that are unencrypted or encrypted under AWS-owned or AWS-managed keys are a `fail`. A key whose manager cannot be read goes to review. IL2 and IL4 are `not_applicable`. |
| `posture/parameters.with_system_parameters` | Passes the system's impact level to the three checks. The system's value overrides any pack parameter. |
| `packs/bundled/aws-devsecops-evidence` | The evidence-artifact table, as an installable pack (below). |

All three checks follow the same rules as the part 4 checks: an empty fleet is `not_applicable`, unreadable data is `manual_review_required`, and missing data is never a pass. Coverage is now 53 checks touching 51 of 288 practices. Runbook section 7 and its pinning tests are updated.

## The evidence-artifact pack

Each artifact in the source table is evidence for a control. It is not a control itself. So the pack's controls are the **39 NIST SP 800-53 Rev. 5 controls** the artifacts evidence, and each artifact is an **evidence requirement** on each control it supports: 45 artifacts, 71 requirements. A pack of artifact IDs would have no canonical control ids. `packs.service.coverage` would match them only by identity, and every system would show 0% coverage, a number over nothing.

Corrections to the source:

- **Remapped:**
  - KMS key policies: SC-13 → SC-12
  - DAST: RA-5 → SA-11(8)
  - SBOMs: SA-15 → SR-4, CM-8
  - build provenance: SA-10 → SR-4
  - federation: IA-5 → IA-2, IA-8
  - container scans: SI-2 → RA-5
  - SAST and threat models: SA-11(1) and SA-11(2)
  - secrets scans: IA-5(7)
  - signatures: SI-7(15), CM-14
- **Added:**
  - identity: role trust policies
  - IaC: CloudFormation drift
  - API: authentication and rate limiting
  - data: encryption in transit, S3 Block Public Access
  - endpoint: EDR findings
  - network: security groups, NACLs, Transit Gateway routes, WAF rule sets. The source's `network` domain was declared but empty.
- **Merged:**
  - "Config non-compliance" into Config compliance reports
  - the two signing artifacts into one
- **Retention:**
  - Event logs: OMB M-21-31, 12 months active and 18 months cold.
  - Everything else: deferred to the organization's records schedule. The source's 365 and 90 days had no source.
- **Dropped:** the `s3://evidence/...` locator templates. They describe the source's bucket layout, not Concord's.

`tests/test_aws_evidence_pack.py` checks every control against the OSCAL catalog Concord ships (it must be present, not withdrawn, and have the right title). It also requires every control to have an artifact, and every requirement to state its retention basis. The corrections are pinned. A mutation run on the pack data killed 12 of 12 mutations.

## Calls made

- **Evidence to collect, not collected evidence.** The pack lists what to gather. It does not mark any artifact as present. The source's `computeArtifactCoverage` took a presence set that nothing populated.
- **Unlisted services are not violations.** Elastic Load Balancing has no row on AWS's page but is in daily use in GovCloud. That is a question for the authorizing official.
- **The table is a snapshot.** Every review verdict cites its "Last updated" date. Refreshing it is a deliberate CLI step, never a background fetch.
- **Not verified against a live AWS account.** No credential exists in this environment, the same constraint as part 4.

## Follow-up: the collector report (branch `feat/aws-collector-truth`)

The user deferred two items from the collector report ("tackle it later"). Both are done, stacked on this branch.

**Missing data never reads as good.** `tests/test_aws_missing_data_never_reads_as_good.py` runs every check in `CHECKS` three ways:

- A reader whose session answers nothing must still have called AWS, and must not lead to a pass. A reader that makes no call can only return a constant.
- An empty answer must never pass.
- A row with every field missing must produce `fail` or `manual_review_required`. It must not produce `pass`, `not_applicable` or no finding at all.

The third case found four evaluators that read missing data as a good answer. All four are fixed, and each fix was confirmed by mutation (4 of 4):

| Evaluator | Before | Now |
|---|---|---|
| Security group admin ingress | A group with no `IpPermissions` passed | Review. AWS always returns the key, even as `[]`. |
| Access-key rotation | A key with no `Status` was `not_applicable` ("cannot authenticate") | Review. Only `Inactive` and `Expired`, the statuses AWS documents, are excused. |
| KMS key rotation | A key with no `KeyState` was `not_applicable` | Review |
| DoD SRG scope | Rows with no resource type were dropped silently | One account-level review naming how many rows were unread |

**IAM user MFA** (`aws.iam.user_mfa_enabled`, IA-2(1)/IA-2(2), CMMC IA.L2-3.5.3). The check reads the IAM credential report:

- Verdicts per user:
  - a console password with active MFA is a `pass`;
  - a console password without MFA is a `fail`;
  - no console password is `not_applicable`, because access keys are the rotation check's concern;
  - any other cell value is `manual_review_required`.
- The root row is left to `aws.iam.root_mfa_enabled`.
- The reader waits a bounded time for a report still being generated. After that it raises, and the check is reported as unrunnable, never as an empty report. A denial is not retried.
- Each finding records the report's `GeneratedTime`, because a report can be up to four hours old.
- Mutation run: 9 of 9 killed.

The check count rises to 54 (`aws_govcloud` 25). Moderate coverage, re-measured, stays at 51 of 288, because IA-2(2) folds into IA-2, which was already covered.
