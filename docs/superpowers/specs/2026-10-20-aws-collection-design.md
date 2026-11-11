# AWS collection: design

Date: 2026-10-20. This is part 4 of the m365-docs-hub port.

## Intent

Bring over m365-docs-hub's AWS collection, integrated into Concord rather than copied.

Only one piece of that code ever called AWS: the `aws-gap-assessment` edge function, with its four collectors. Its secrets were never set, so it never ran. Read call by call, the collectors pass on vacuity, fabricate values, conflate errors, and guess resources from their names:

- **Pass on vacuity.** No VPCs counts as 100% flow logs. No load balancers counts as "TLS enforced".
- **Fabricated values.** Key rotation is hard-coded off. Retention is hard-coded to 90 days.
- **Error conflation.** AccessDenied is read as "not compliant", and a 403 is read as "public".
- **Name heuristics.** The "recovery account" is found by a regex on account names, and so is the "evidence bucket".

What is worth keeping:

- the per-tenant connection design from its ADR 0002 (AssumeRole with an External ID, merged there as "phase 0");
- a list of services worth checking;
- an Organizations walk that treats AccessDenied correctly.

## What was built

| Piece | Integration |
|---|---|
| `connectors/aws_identity.py` | Validates partition-exact role ARNs (`us-gov-(west\|east)-1` maps to `aws-us-gov`; China and ISO regions are refused). Requires role names to start with `ConcordConnector*`. Generates External IDs as `concord-` + 32 hex characters. Builds the trust and least-privilege policies. Maps AWS failures to fixed, tenant-safe reasons. |
| `role_arn` credential method | Added alongside the access-key and profile methods (`credential_spec`). `external_id` is a *generated* field: `set_credential` (the one path both write routes share) drops any client value and injects the org's stored one. Each bundle holds one method, and switching methods in the form replaces the old one. |
| `AwsGovCloudConnector._assumed_session` | Calls `sts:AssumeRole` from the partition's broker profile (`CCF_AWS_BROKER_PROFILE_GOVCLOUD`/`_COMMERCIAL`), passing the `ExternalId`. There is no cross-partition fallback and no ambient chain. The assumed session is cached with a 5-minute skew, and the broker session is never returned. `verify()` requires the caller to be the configured role in the configured account. Errors are classified, because an AssumeRole error names the broker ARN. |
| External ID lifecycle | The connector page generates it and shows the trust policy and permissions policy. Rotation is admin-only, needs explicit confirmation, re-binds the stored bundle, marks the connector not ready, and is audited. |
| Eight posture checks | Config recorder recording all types; GuardDuty detector ENABLED; external-access Access Analyzer ACTIVE; customer-managed KMS key rotation; ELBv2 listener TLS (HTTP passes only if it and every rule redirect to HTTPS; TCP and UDP go to review); WAF on internet-facing ALBs; Object Lock with default retention on the buckets CloudTrail actually writes to; RDS `StorageEncrypted`. In every check, empty fleet means `not_applicable`, stopped or suspended means `fail`, and unreadable means `manual_review_required`. |
| `required_permissions` parity | `tests/test_aws_permissions_are_declared.py` runs every reader against a recording session. It found `ssm:DescribeInstanceInformation` undeclared on the existing patch check. |
| Organizations inventory | `organization_inventory()` keeps the source's rules: a member account's denial is reported as indeterminate, accounts keep only their email domain, and the walk is capped with a `truncated` flag. `aws_inventory.sync_organization_inventory` maps the organization to a `SystemComponent` and each account to an `InventoryItem` through `boundary.service`. The sync is additive and idempotent; human edits survive; a partition mismatch is flagged. The system binding is an operator's choice (`config["system_id"]`). `objects_discovered` is the real count of accounts read. The development-only mock sync is unchanged: it is labelled mock, and `test_live_capture_proof` relies on it to prove a mock cannot manufacture automated evidence. |

## Calls made

- The External ID is per organization, because Concord allows one AWS connector per organization.
- A Security Hub "enabled" probe and an Inspector probe are not ported: Concord's attestation read and its all-resource-types Inspector check are stricter.
- **Deferred:**
  - **Multi-region iteration.** It would change the identity of existing findings.
  - **AWS Backup** (needs a CP scan-scope override), **Macie** (GovCloud availability unverified) and **SCP** checks.
  - **Live Inspector2 sync.** Concord already ingests Inspector JSON through `ingest/scanners.py`.
  - **Scheduling the inventory sync.** It is triggered from the connector page.
- **Nothing has been verified against a live AWS account.** No credential exists in this environment. Every reader and evaluator is tested on recorded response shapes, the same constraint stated in `posture/providers/aws.py`.

## Revised for m365-docs-hub ADR 0005 (same day, 11:00–11:12)

That morning the source accepted IAM-user access keys alongside the role chain. It also moved every AWS screen onto the organization's connection, and disabled the simulated Security Audit and ATO Package screens. Concord already accepted access keys. These are the source's controls on them, applied in Concord:

- **Proven before stored.** `set_credential(..., prove=True)` runs on both write routes (the JSON API and the settings form). It calls STS `GetCallerIdentity` first, so a credential AWS rejects is never encrypted or written. The recorded `account_id` is the one STS reports, and a declared one must match it. The error text is classified, never AWS's own. When the host cannot ask AWS (capture is disabled or boto3 is absent), the credential is stored unproven, as before. The JSON route now answers an unusable credential with 422; until now it returned a 500.
- **Session tokens.** An `ASIA…` key must carry one. A token sent with an `AKIA…` key is refused.
- **Display tag.** `key_last4` now comes from the access key ID. It used to show the last four characters of the secret key.
- **Permission check.** The connector page's "Check permissions" runs each reader once, read-only. A check is `missing` only on a clear denial, naming the refused action from botocore's `operation_name`. A rejected or expired key reports `unknown`. A denial on individual resources (key policies, a bucket in another account) counts even when the read succeeded, because that is the source's "denial recorder" rule.
- **Organizations endpoint.** Organizations is called in `us-east-1` (commercial) or `us-gov-west-1` (GovCloud), whatever region the credential names.

Not adopted:

- AES-GCM bound to the connection ID as associated data. Concord's envelope cipher (`ai.cipher`) is its own scheme.
- The Key Vault key custody. That is an Azure deployment detail of the source.
