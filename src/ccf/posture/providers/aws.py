"""AWS GovCloud posture checks -- the account configuration nobody can see.

``AwsGovCloudConnector`` could already *capture* AWS configuration into ODP
values; nothing evaluated it. These four checks close that: they assess the
account-level identity and audit settings a FedRAMP package asserts and an
assessor asks for evidence of.

Four checks spanning distinct resource shapes, the way ``m365.py`` does, rather
than four variants of one:

* :data:`ROOT_MFA_ENABLED` -- a **singleton read from a summary map**. One
  account, one boolean, and an absent summary is ``manual_review_required``
  rather than a pass.
* :data:`PASSWORD_POLICY` -- a **singleton whose absence is itself the
  finding**. An account with no IAM password policy is not "nothing to
  assess"; it is an account where AWS's permissive default applies, so empty
  input is a ``fail`` here and not a ``not_applicable``.
* :data:`CLOUDTRAIL_MULTI_REGION` -- a **singleton derived by any-of over a
  fleet**. Many trails may exist; the control is a property of the account
  ("at least one multi-region trail is actually logging"), so flagging a
  legitimate single-region supplementary trail would be a false positive an
  operator cannot act on.
* :data:`ACCESS_KEY_ROTATION` -- a **fleet with exclusions**. One finding per
  access key, with inactive keys excluded and unreadable dates escalated
  rather than assumed healthy.

Every evaluator here is pure: it takes the rows an AWS API call returned and
returns findings. No boto3, no network, no clock, no database -- ``now`` is
passed in -- so each is unit-testable against a recorded AWS response shape,
which matters because no AWS account is reachable from the build environment.
This is the same property ``m365.py`` holds, and for the same reason.

ENDPOINTS, for a provider that has no URLs
------------------------------------------
``ENDPOINTS`` maps a check key to *where its rows come from*. For Graph and
PuppetDB that happens to be a URL path, because those providers are HTTP APIs.
AWS is not: boto3 speaks in ``client(service).operation()`` pairs, and there is
no request path a caller composes. So the value here is a **boto3
``<service>.<operation>`` source token** -- ``"iam.get_account_summary"`` --
and deliberately not a URL. Inventing a URL-shaped string to make the type line
up would be a fiction: nothing would ever fetch it, and the first reader to
trust it would be misled.

The token is not data handed to boto3. ``AwsGovCloudConnector`` uses it as a
key into a fixed dispatch table of reader methods, so a token this build does
not recognise raises rather than turning into an arbitrary AWS API call made
with the organization's own credentials.

What this means for pack-declared checks -- stated, not implied
--------------------------------------------------------------
**A tenant can parameterize an AWS check (Form A). A tenant cannot declare a
new AWS check (Form B).** That is a real capability gap, and it is written
here because an unstated gap is worse than a stated one:

* *Form A works.* :data:`ACCESS_KEY_ROTATION` is listed in
  ``posture.parameters.PARAMETERIZABLE``, so a pack may supply its own
  ``threshold_days``. The endpoint is the platform's own token, looked up from
  this module -- the tenant never names a data source.
* *Form B does not.* ``posture.resolve.validate_endpoint`` admits only a
  relative Graph path (``/v1.0/`` or ``/beta/``), which is a security control
  for Graph's bearer token, not a formatting rule -- so no AWS source token can
  pass it. A declarative AWS check therefore has no way to say what it reads.
  Making one possible would mean letting a tenant-authored pack name an
  arbitrary boto3 operation to run under that organization's AWS credentials.
  That is a permissions-and-blast-radius decision, not a plumbing gap, and it
  is not taken here.

A Form B rule that names ``provider: aws_govcloud`` with a Graph-shaped
endpoint will still install (pack validation only checks the endpoint's shape).
It does not silently vanish: the connector has no reader for that token, so the
check reports one ``manual_review_required`` finding saying exactly that. A
check that stops producing results is indistinguishable from one that passes,
so it reports instead.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from ..types import PostureCheck, ResourceFinding

#: Maximum age of an *active* IAM access key. Wants to be an
#: organization-defined parameter -- the ODP machinery already exists for
#: exactly this, and unlike the other thresholds here a pack can already
#: supply its own through Form A (see ``posture.parameters``). The constant
#: remains the default, with a recorded intent, rather than a bare literal.
#: 90 days is the CIS AWS Foundations Benchmark's rotation period and the
#: value FedRAMP assessors most often expect to see defended.
ACCESS_KEY_MAX_AGE_DAYS = 90

#: Minimum console password length. IA-5(1) states this as an
#: organization-defined value; 14 is what a FedRAMP Moderate package is
#: normally held to. Not currently parameterizable -- see the note on
#: :data:`PASSWORD_POLICY_EXPECTED`.
MIN_PASSWORD_LENGTH = 14

#: How many previous passwords IAM must refuse to reuse (IA-5(1)). 24 is the
#: value AWS's own console guidance and the CIS benchmark converge on.
MIN_PASSWORD_REUSE_PREVENTION = 24

#: An access key that is not ``Active`` cannot authenticate, so it is excluded
#: from the rotation verdict rather than counted as a pass.
_ACTIVE_KEY_STATUS = "Active"


ROOT_MFA_ENABLED = PostureCheck(
    key="aws.iam.root_mfa_enabled",
    title="The account root user has MFA enabled",
    provider="aws_govcloud",
    resource_type="aws_account",
    expected="the account root user has a multi-factor authentication device enabled",
    control_ids=("IA-2", "IA-2(1)"),
    required_permissions=("iam:GetAccountSummary",),
)

#: The one place the password-policy expectation is worded, rendered once from
#: the same constants the evaluator defaults to, so an SSP can never claim one
#: minimum while the check enforces another.
#:
#: Deliberately NOT registered in ``parameters.EXPECTED_TEMPLATES``. That
#: machinery renders a template with only the parameters a pack supplied, which
#: is safe for a one-parameter template and a ``KeyError`` mid-resolution for a
#: two-parameter one where the pack set only a single value. Keeping this check
#: unparameterized keeps the single-source-of-wording property without relying
#: on a partial-render path that has never been exercised.
PASSWORD_POLICY_EXPECTED = (
    "the IAM account password policy requires at least {min_length} characters "
    "and prohibits reuse of the last {reuse_generations} passwords"
)

PASSWORD_POLICY = PostureCheck(
    key="aws.iam.password_policy",
    title="The IAM password policy meets the required minimums",
    provider="aws_govcloud",
    resource_type="aws_account",
    expected=PASSWORD_POLICY_EXPECTED.format(
        min_length=MIN_PASSWORD_LENGTH,
        reuse_generations=MIN_PASSWORD_REUSE_PREVENTION,
    ),
    control_ids=("IA-5", "IA-5(1)"),
    required_permissions=("iam:GetAccountPasswordPolicy",),
)

#: The one place the key-rotation expectation is worded. A pack that
#: parameterizes the threshold re-renders this template (Form A), so the prose
#: in an SSP can never claim 90 days while the check enforces 45. Same
#: discipline as ``m365.STALE_ACCOUNTS_EXPECTED``.
ACCESS_KEY_ROTATION_EXPECTED = (
    "no active IAM access key is older than {threshold_days} days"
)

ACCESS_KEY_ROTATION = PostureCheck(
    key="aws.iam.access_key_rotation",
    title="No active access key is older than the rotation threshold",
    provider="aws_govcloud",
    resource_type="iam_access_key",
    expected=ACCESS_KEY_ROTATION_EXPECTED.format(threshold_days=ACCESS_KEY_MAX_AGE_DAYS),
    control_ids=("IA-5(1)",),
    required_permissions=("iam:ListUsers", "iam:ListAccessKeys"),
)

CLOUDTRAIL_MULTI_REGION = PostureCheck(
    key="aws.cloudtrail.multi_region_logging",
    title="A multi-region CloudTrail trail is logging",
    provider="aws_govcloud",
    resource_type="aws_account",
    expected="at least one multi-region CloudTrail trail exists and is actively logging",
    control_ids=("AU-2", "AU-12"),
    required_permissions=("cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus"),
)

CLOUDTRAIL_LOG_FILE_VALIDATION = PostureCheck(
    key="aws.cloudtrail.log_file_validation",
    title="Every CloudTrail trail validates its log files",
    provider="aws_govcloud",
    resource_type="cloudtrail_trail",
    expected="each CloudTrail trail has log file validation enabled",
    # AU-9 is protection of audit information; AU-9(3) is the cryptographic
    # protection of it, which is precisely what log file validation is -- a
    # digest chain that makes a deleted or edited log file detectable.
    control_ids=("AU-9", "AU-9(3)"),
    # No new AWS surface: this reads the trails `describe_trails` already
    # returned for CLOUDTRAIL_MULTI_REGION, so it adds a control family
    # without adding a permission an operator has to grant.
    required_permissions=("cloudtrail:DescribeTrails",),
)

S3_PUBLIC_ACCESS_BLOCKED = PostureCheck(
    key="aws.s3.public_access_blocked",
    title="Every bucket blocks public access at the bucket level",
    provider="aws_govcloud",
    resource_type="s3_bucket",
    expected="each S3 bucket has all four public-access-block settings enabled",
    control_ids=("AC-3", "AC-4", "SC-7"),
    required_permissions=("s3:ListAllMyBuckets", "s3:GetBucketPublicAccessBlock"),
)

S3_DEFAULT_ENCRYPTION = PostureCheck(
    key="aws.s3.default_encryption",
    title="Every bucket encrypts objects at rest by default",
    provider="aws_govcloud",
    resource_type="s3_bucket",
    expected="each S3 bucket has a default server-side encryption rule",
    control_ids=("SC-28", "SC-28(1)"),
    required_permissions=("s3:ListAllMyBuckets", "s3:GetEncryptionConfiguration"),
)

#: Administrative ports an unrestricted rule must never expose. Deliberately a
#: short list rather than "any port": 443 open to the world is ordinary
#: architecture for a load balancer, and a check that failed it would be the
#: check an operator learns to ignore. The requirement is permit-by-exception,
#: and a corporate CIDR reaching SSH *is* the exception.
_ADMIN_PORTS: tuple[int, ...] = (22, 3389)

#: The two ways a rule says "from anywhere". `::/0` is the same exposure as
#: `0.0.0.0/0` and the one more often left behind.
_ANY_IPV4 = "0.0.0.0/0"
_ANY_IPV6 = "::/0"

#: RDS lifecycle states where the instance has not settled on its final
#: configuration. Failing one would make every deployment briefly
#: non-compliant, which teaches an operator to ignore the check.
_RDS_UNSETTLED_STATES: frozenset[str] = frozenset(
    {"creating", "modifying", "backing-up", "deleting", "rebooting", "starting"}
)

#: Inspector resource-type states that mean scanning is actually happening.
#: `SUSPENDED` is its paused state, so it is not one of them.
_INSPECTOR_ACTIVE = frozenset({"ENABLED"})

INSPECTOR_ENABLED = PostureCheck(
    key="aws.inspector.enabled",
    title="Amazon Inspector scans every resource type",
    provider="aws_govcloud",
    resource_type="aws_account",
    expected="Inspector is enabled for EC2, ECR and Lambda in this account",
    control_ids=("RA-5", "RA-5(2)"),
    required_permissions=("inspector2:BatchGetAccountStatus",),
)

PATCH_COMPLIANCE = PostureCheck(
    key="aws.ssm.patch_compliance",
    title="Every managed instance is patched",
    provider="aws_govcloud",
    resource_type="aws_instance",
    expected="no Systems Manager-managed instance has missing or failed patches",
    control_ids=("SI-2", "SI-2(2)", "CM-6"),
    required_permissions=("ssm:DescribeInstancePatchStates",),
)

RDS_NOT_PUBLICLY_ACCESSIBLE = PostureCheck(
    key="aws.rds.not_publicly_accessible",
    title="No database instance is reachable from the internet",
    provider="aws_govcloud",
    resource_type="aws_db_instance",
    expected="no RDS instance has PubliclyAccessible enabled",
    control_ids=("SC-7", "SC-7(3)", "AC-4"),
    required_permissions=("rds:DescribeDBInstances",),
)

SECURITY_GROUP_ADMIN_INGRESS = PostureCheck(
    key="aws.ec2.security_groups_no_public_admin_ingress",
    title="No security group exposes SSH or RDP to the internet",
    provider="aws_govcloud",
    resource_type="aws_security_group",
    expected=(
        "no security group permits ingress from 0.0.0.0/0 or ::/0 to port 22 or 3389"
    ),
    control_ids=("SC-7", "AC-4", "CM-7"),
    required_permissions=("ec2:DescribeSecurityGroups",),
)

VPC_FLOW_LOGS = PostureCheck(
    key="aws.vpc.flow_logs_enabled",
    title="Every VPC records network flow logs",
    provider="aws_govcloud",
    resource_type="aws_vpc",
    expected="each VPC has at least one flow log in the ACTIVE state",
    control_ids=("AU-2", "AU-12", "SI-4"),
    required_permissions=("ec2:DescribeVpcs", "ec2:DescribeFlowLogs"),
)

EBS_ENCRYPTION_BY_DEFAULT = PostureCheck(
    key="aws.ec2.ebs_encryption_by_default",
    title="New EBS volumes are encrypted by default",
    provider="aws_govcloud",
    resource_type="aws_account",
    expected="EBS encryption by default is enabled in this account and region",
    control_ids=("SC-28", "SC-28(1)"),
    required_permissions=("ec2:GetEbsEncryptionByDefault",),
)

CHECKS: tuple[PostureCheck, ...] = (
    ROOT_MFA_ENABLED,
    PASSWORD_POLICY,
    ACCESS_KEY_ROTATION,
    CLOUDTRAIL_MULTI_REGION,
    CLOUDTRAIL_LOG_FILE_VALIDATION,
    S3_PUBLIC_ACCESS_BLOCKED,
    S3_DEFAULT_ENCRYPTION,
    EBS_ENCRYPTION_BY_DEFAULT,
    SECURITY_GROUP_ADMIN_INGRESS,
    VPC_FLOW_LOGS,
    RDS_NOT_PUBLICLY_ACCESSIBLE,
    INSPECTOR_ENABLED,
    PATCH_COMPLIANCE,
)

#: The four settings that together make a bucket non-public. All four are
#: required: ``BlockPublicAcls`` stops new public ACLs while ``IgnorePublicAcls``
#: neutralizes ones already set, and the same split applies to policies. A
#: bucket with two of the four enabled is still reachable by one of the two
#: routes, so this is an all-of and not a majority.
_PUBLIC_ACCESS_BLOCK_SETTINGS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)

#: Check key -> the boto3 ``<service>.<operation>`` its rows come from.
#:
#: A dot, not a colon, separates the two halves: ``iam.get_account_summary`` is
#: a boto3 operation, and ``iam:GetAccountSummary`` (which appears in
#: ``required_permissions``) is the IAM action that authorizes it. They are
#: different vocabularies and one is not substitutable for the other, so they
#: are not spelled alike.
#:
#: ``cloudtrail.describe_trails`` names the *primary* call. Its reader also
#: issues ``get_trail_status`` per trail to merge ``IsLogging``, because a
#: multi-region trail that was stopped satisfies ``describe_trails`` and
#: satisfies nothing an AU-12 assessor is asking about. The token names where
#: the fleet comes from, not every call made to complete a row.
ENDPOINTS: dict[str, str] = {
    ROOT_MFA_ENABLED.key: "iam.get_account_summary",
    PASSWORD_POLICY.key: "iam.get_account_password_policy",
    ACCESS_KEY_ROTATION.key: "iam.list_access_keys",
    CLOUDTRAIL_MULTI_REGION.key: "cloudtrail.describe_trails",
    # Deliberately the same token as CLOUDTRAIL_MULTI_REGION: both judge the
    # trails that one call returns, and giving this check a token of its own
    # would make the connector fetch the same fleet twice. Two m365 checks
    # share `/deviceManagement/deviceCompliancePolicies` for the same reason.
    CLOUDTRAIL_LOG_FILE_VALIDATION.key: "cloudtrail.describe_trails",
    S3_PUBLIC_ACCESS_BLOCKED.key: "s3.get_public_access_block",
    S3_DEFAULT_ENCRYPTION.key: "s3.get_bucket_encryption",
    EBS_ENCRYPTION_BY_DEFAULT.key: "ec2.get_ebs_encryption_by_default",
    SECURITY_GROUP_ADMIN_INGRESS.key: "ec2.describe_security_groups",
    # One token for two calls. `describe_flow_logs` answers which VPCs are
    # covered, but the denominator is every VPC, so the reader joins
    # `describe_vpcs` to it and hands the evaluator whole VPCs. A VPC with no
    # flow log has no row in the flow-log response at all -- keying the check on
    # that response alone would make an unmonitored VPC invisible rather than
    # failing.
    VPC_FLOW_LOGS.key: "ec2.describe_flow_logs",
    RDS_NOT_PUBLICLY_ACCESSIBLE.key: "rds.describe_db_instances",
    INSPECTOR_ENABLED.key: "inspector2.batch_get_account_status",
    PATCH_COMPLIANCE.key: "ssm.describe_instance_patch_states",
}

#: Evaluators that need to be told which account they are judging, because
#: their resource is the account itself rather than a row AWS returned.
ACCOUNT_SCOPED: frozenset[str] = frozenset(
    {
        ROOT_MFA_ENABLED.key,
        PASSWORD_POLICY.key,
        CLOUDTRAIL_MULTI_REGION.key,
        EBS_ENCRYPTION_BY_DEFAULT.key,
        SECURITY_GROUP_ADMIN_INGRESS.key,
        VPC_FLOW_LOGS.key,
        RDS_NOT_PUBLICLY_ACCESSIBLE.key,
        INSPECTOR_ENABLED.key,
        PATCH_COMPLIANCE.key,
    }
)


def _parse_aws_datetime(value: Any) -> datetime | None:
    """A timezone-aware datetime, or ``None`` when the value is unusable.

    boto3 deserializes AWS timestamps into ``datetime`` objects already, so
    that is the shape a live scan passes in. A string is also accepted: a
    recorded or round-tripped payload (a snapshot, a JSON fixture) carries the
    ISO-8601 form, and rejecting it would make this evaluator untestable
    against exactly the recorded shapes it exists to be testable against.

    A naive datetime returns ``None`` rather than being used. Subtracting one
    from the timezone-aware ``now`` raises ``TypeError``, which would take out
    the whole fleet's verdict over a single bad row -- the defect
    ``puppetdb._parse_timestamp`` already documents. Unusable is unusable,
    whichever way it got that way.
    """
    parsed: datetime | None = None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed is None or parsed.tzinfo is None:
        return None
    return parsed


def _summary_map(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The ``SummaryMap`` from a ``get_account_summary`` response, if present."""
    for row in rows:
        summary = row.get("SummaryMap")
        if isinstance(summary, dict):
            return summary
    return None


def evaluate_root_mfa(
    rows: list[dict[str, Any]], *, account_id: str
) -> list[ResourceFinding]:
    """Exactly one finding: the account is the resource.

    ``get_account_summary`` reports ``AccountMFAEnabled`` as ``1`` or ``0``.
    An absent summary is ``manual_review_required``, never a pass: a root user
    whose MFA state was never observed is not a root user with MFA.
    """
    summary = _summary_map(rows)
    if summary is None:
        return [
            ResourceFinding(
                resource_id=account_id,
                resource_type="aws_account",
                verdict="manual_review_required",
                observed="IAM account summary unavailable; root MFA state not observed",
                detail={"rows": len(rows)},
            )
        ]
    raw = summary.get("AccountMFAEnabled")
    enabled = raw == 1 or raw is True
    return [
        ResourceFinding(
            resource_id=account_id,
            resource_type="aws_account",
            verdict="pass" if enabled else "fail",
            observed=(
                "root user has an MFA device enabled"
                if enabled
                else "root user has no MFA device enabled (AccountMFAEnabled=0)"
            ),
            detail={
                "AccountMFAEnabled": raw,
                "AccountAccessKeysPresent": summary.get("AccountAccessKeysPresent"),
            },
        )
    ]


def evaluate_password_policy(
    rows: list[dict[str, Any]],
    *,
    account_id: str,
    min_length: int = MIN_PASSWORD_LENGTH,
    reuse_generations: int = MIN_PASSWORD_REUSE_PREVENTION,
) -> list[ResourceFinding]:
    """Exactly one finding: the account is the resource.

    **Empty input is a ``fail``, not "nothing in scope".** IAM raises
    ``NoSuchEntity`` when an account has no password policy at all, and the
    connector's reader turns exactly that one error into ``[]``. An account
    with no policy is an account running AWS's permissive default, which is
    the very thing IA-5(1) exists to forbid -- reporting ``not_applicable``
    there would hide the weakest possible configuration behind the most
    benign-looking verdict. Every other IAM error propagates and is reported
    as unrunnable instead, so "no policy" and "could not look" stay distinct.

    The observed string names each shortfall *and the value seen*, because a
    finding that says only "fail" is not one an operator can act on.
    """
    policy: dict[str, Any] | None = None
    for row in rows:
        candidate = row.get("PasswordPolicy")
        if isinstance(candidate, dict):
            policy = candidate
            break
    if policy is None:
        return [
            ResourceFinding(
                resource_id=account_id,
                resource_type="aws_account",
                verdict="fail",
                observed=(
                    "no IAM account password policy is configured; the AWS "
                    "default applies (no minimum length, no reuse prevention)"
                ),
                detail={"policy": None},
            )
        ]
    length = policy.get("MinimumPasswordLength")
    reuse = policy.get("PasswordReusePrevention")
    problems: list[str] = []
    if not isinstance(length, int) or isinstance(length, bool) or length < min_length:
        problems.append(
            f"minimum length {length if length is not None else 'not set'} "
            f"(requires {min_length})"
        )
    if not isinstance(reuse, int) or isinstance(reuse, bool) or reuse < reuse_generations:
        problems.append(
            f"password reuse prevention {reuse if reuse is not None else 'not set'} "
            f"(requires {reuse_generations})"
        )
    return [
        ResourceFinding(
            resource_id=account_id,
            resource_type="aws_account",
            verdict="fail" if problems else "pass",
            observed=(
                "; ".join(problems)
                if problems
                else (
                    f"minimum length {length}, password reuse prevention {reuse}"
                )
            ),
            detail={
                "MinimumPasswordLength": length,
                "PasswordReusePrevention": reuse,
                "ExpirePasswords": policy.get("ExpirePasswords"),
                "MaxPasswordAge": policy.get("MaxPasswordAge"),
            },
        )
    ]


def _key_ref(row: dict[str, Any]) -> str:
    """The access key id, never empty.

    An unidentified key is still an unrotated key, so it is reported rather
    than dropped -- the judgement ``puppetdb._node_ref`` makes for a node with
    no certname.
    """
    key_id = row.get("AccessKeyId")
    if isinstance(key_id, str) and key_id:
        return key_id
    return "unknown"


def evaluate_access_key_rotation(
    rows: list[dict[str, Any]],
    *,
    now: datetime,
    threshold_days: int = ACCESS_KEY_MAX_AGE_DAYS,
) -> list[ResourceFinding]:
    """One finding per access key: has an active credential gone unrotated?

    ``now`` is a parameter so the evaluator stays pure and the threshold is
    testable without freezing the clock. ``threshold_days`` defaults to the
    module constant, so every existing caller is unaffected; a pack supplies
    its own through Form A, which is what the constant's note above wants.

    Two exclusions, both ``not_applicable`` rather than ``pass``. An
    ``Inactive`` key cannot authenticate, so it is not a live rotation risk.
    And a key whose ``CreateDate`` is missing or unusable is
    ``manual_review_required``: an unreadable age is not evidence of a fresh
    key, and calling it ``pass`` would assert something never observed.

    AWS has no "last rotated" field for an access key -- rotation means
    creating a replacement and deleting the old key -- so ``CreateDate`` *is*
    the age of the credential in use. The observed string says "created", not
    "rotated", so the finding cannot be read as claiming more than AWS reports.
    """
    findings: list[ResourceFinding] = []
    for row in rows:
        ref = _key_ref(row)
        user = row.get("UserName")
        status = row.get("Status")
        if status != _ACTIVE_KEY_STATUS:
            findings.append(
                ResourceFinding(
                    resource_id=ref,
                    resource_type="iam_access_key",
                    verdict="not_applicable",
                    observed=f"access key status {status!r}; cannot authenticate",
                    detail={"UserName": user, "Status": status},
                )
            )
            continue
        created = _parse_aws_datetime(row.get("CreateDate"))
        if created is None:
            findings.append(
                ResourceFinding(
                    resource_id=ref,
                    resource_type="iam_access_key",
                    verdict="manual_review_required",
                    observed=(
                        f"active access key for user {user!r} has no readable "
                        "creation date; age not observed"
                    ),
                    detail={"UserName": user, "CreateDate": str(row.get("CreateDate"))},
                )
            )
            continue
        elapsed = now - created
        # Compare the full-precision delta against the threshold, not
        # ``elapsed.days``: ``.days`` truncates, so a key 90.9 days old would
        # report 90 and pass a 90-day threshold -- an effective threshold of
        # 91, not 90. The same trap ``m365.evaluate_stale_accounts`` documents.
        findings.append(
            ResourceFinding(
                resource_id=ref,
                resource_type="iam_access_key",
                verdict="fail" if elapsed > timedelta(days=threshold_days) else "pass",
                observed=(
                    f"active access key for user {user!r} created "
                    f"{elapsed.days} day(s) ago"
                ),
                detail={"UserName": user, "age_days": elapsed.days},
            )
        )
    return findings


def _trail_summary(trail: dict[str, Any]) -> dict[str, Any]:
    """The three facts about a trail a reader of a failing finding needs."""
    return {
        "name": trail.get("Name") or trail.get("TrailARN"),
        "multi_region": trail.get("IsMultiRegionTrail"),
        "logging": trail.get("IsLogging"),
    }


def evaluate_cloudtrail_multi_region(
    rows: list[dict[str, Any]], *, account_id: str
) -> list[ResourceFinding]:
    """Exactly one finding: the account is the resource, not each trail.

    AU-2/AU-12 asks whether *the account* records its API activity. An account
    may legitimately run several trails, and a single-region trail beside a
    healthy multi-region one is not a defect -- emitting a per-trail ``fail``
    for it would be a false positive nobody can remediate. So the verdict is an
    any-of across the fleet, and the fleet is put in ``detail`` so a reader can
    see what was examined.

    ``IsLogging`` is merged in by the connector from ``get_trail_status``; a
    trail whose status could not be read has no ``IsLogging`` key. When the
    only multi-region trail is in that state the verdict is
    ``manual_review_required``, not ``fail``: an unread status is not proof the
    trail is stopped, and not proof it is running either.
    """
    logging_multi_region = [
        t
        for t in rows
        if t.get("IsMultiRegionTrail") is True and t.get("IsLogging") is True
    ]
    if logging_multi_region:
        winner = logging_multi_region[0]
        return [
            ResourceFinding(
                resource_id=account_id,
                resource_type="aws_account",
                verdict="pass",
                observed=(
                    "multi-region trail "
                    f"{winner.get('Name') or winner.get('TrailARN')!r} is logging"
                ),
                detail={
                    "trail": winner.get("TrailARN") or winner.get("Name"),
                    "IncludeGlobalServiceEvents": winner.get("IncludeGlobalServiceEvents"),
                    "trails_examined": len(rows),
                },
            )
        ]
    unknown = [
        t for t in rows if t.get("IsMultiRegionTrail") is True and "IsLogging" not in t
    ]
    if unknown:
        return [
            ResourceFinding(
                resource_id=account_id,
                resource_type="aws_account",
                verdict="manual_review_required",
                observed=(
                    f"{len(unknown)} multi-region trail(s) exist but their logging "
                    "status could not be read"
                ),
                detail={"trails": [_trail_summary(t) for t in rows]},
            )
        ]
    return [
        ResourceFinding(
            resource_id=account_id,
            resource_type="aws_account",
            verdict="fail",
            observed=(
                "no CloudTrail trail is configured in this account"
                if not rows
                else (
                    f"no multi-region trail is logging; {len(rows)} trail(s) examined"
                )
            ),
            detail={"trails": [_trail_summary(t) for t in rows]},
        )
    ]


def evaluate_cloudtrail_log_file_validation(
    rows: list[dict[str, Any]],
) -> list[ResourceFinding]:
    """One finding per trail. The trail is the resource here, not the account.

    Deliberately not an any-of, unlike :func:`evaluate_cloudtrail_multi_region`.
    That check asks whether *the account* records its activity, which one
    healthy trail answers. AU-9 asks whether the audit record is protected from
    modification, and an unvalidated trail is unprotected however many validated
    trails sit beside it -- its log files can be altered and nothing will show
    it. So each trail is judged on its own.

    A trail that omits ``LogFileValidationEnabled`` entirely is a ``fail``, not
    ``manual_review_required``: ``describe_trails`` returns the field for every
    trail, and AWS's default for it is ``false``. An absent field here means the
    feature was never turned on, which is the finding -- unlike ``IsLogging``,
    which comes from a second call that can genuinely fail.
    """
    findings: list[ResourceFinding] = []
    for trail in rows:
        ref = str(trail.get("Name") or trail.get("TrailARN") or "unknown trail")
        enabled = trail.get("LogFileValidationEnabled") is True
        findings.append(
            ResourceFinding(
                resource_id=str(trail.get("TrailARN") or ref),
                resource_type="cloudtrail_trail",
                verdict="pass" if enabled else "fail",
                observed=(
                    f"{ref}: log file validation enabled"
                    if enabled
                    else f"{ref}: log file validation is not enabled"
                ),
                detail={
                    "LogFileValidationEnabled": trail.get("LogFileValidationEnabled"),
                    "IsMultiRegionTrail": trail.get("IsMultiRegionTrail"),
                },
            )
        )
    return findings


def evaluate_s3_public_access_blocked(
    rows: list[dict[str, Any]],
) -> list[ResourceFinding]:
    """One finding per bucket, naming which of the four settings is missing.

    "Bucket is public" is not actionable; "``IgnorePublicAcls`` is off" is. The
    missing settings go in ``observed`` rather than only in ``detail``, because
    the observed string is what reaches a POA&M's weakness line.

    A bucket whose ``PublicAccessBlockConfiguration`` could not be read is
    ``manual_review_required``. The connector distinguishes "no block
    configuration exists" (which AWS reports as an error, and which means the
    permissive default applies -- a ``fail``) from "the call did not answer",
    and only the second arrives here without a configuration.
    """
    findings: list[ResourceFinding] = []
    for row in rows:
        name = str(row.get("Name") or "unknown bucket")
        if row.get("Unreadable"):
            findings.append(
                ResourceFinding(
                    resource_id=name,
                    resource_type="s3_bucket",
                    verdict="manual_review_required",
                    observed=(
                        f"{name}: public-access-block configuration could not be read"
                        f" ({row.get('Unreadable')})"
                    ),
                    detail={"error": row.get("Unreadable")},
                )
            )
            continue
        config = row.get("PublicAccessBlockConfiguration") or {}
        missing = [s for s in _PUBLIC_ACCESS_BLOCK_SETTINGS if config.get(s) is not True]
        findings.append(
            ResourceFinding(
                resource_id=name,
                resource_type="s3_bucket",
                verdict="fail" if missing else "pass",
                observed=(
                    f"{name}: public access blocked on all four settings"
                    if not missing
                    else f"{name}: not enabled — {', '.join(missing)}"
                ),
                detail={s: config.get(s) for s in _PUBLIC_ACCESS_BLOCK_SETTINGS},
            )
        )
    return findings


def evaluate_s3_default_encryption(
    rows: list[dict[str, Any]],
) -> list[ResourceFinding]:
    """One finding per bucket: is there a default encryption rule at all?

    The algorithm is reported but not judged. ``AES256`` (SSE-S3) and ``aws:kms``
    both satisfy SC-28; SC-28(1) is where a package may require a
    customer-managed key, and which key is acceptable is an
    organization-defined decision this check has no basis to make. Failing a
    bucket for using SSE-S3 would be this module inventing a requirement, so it
    records the algorithm for an assessor and fails only on absence.
    """
    findings: list[ResourceFinding] = []
    for row in rows:
        name = str(row.get("Name") or "unknown bucket")
        if row.get("Unreadable"):
            findings.append(
                ResourceFinding(
                    resource_id=name,
                    resource_type="s3_bucket",
                    verdict="manual_review_required",
                    observed=(
                        f"{name}: encryption configuration could not be read"
                        f" ({row.get('Unreadable')})"
                    ),
                    detail={"error": row.get("Unreadable")},
                )
            )
            continue
        rules = (row.get("ServerSideEncryptionConfiguration") or {}).get("Rules") or []
        algorithms = [
            str(
                (r.get("ApplyServerSideEncryptionByDefault") or {}).get("SSEAlgorithm")
                or ""
            )
            for r in rules
            if isinstance(r, dict)
        ]
        applied = [a for a in algorithms if a]
        findings.append(
            ResourceFinding(
                resource_id=name,
                resource_type="s3_bucket",
                verdict="pass" if applied else "fail",
                observed=(
                    f"{name}: default encryption with {', '.join(applied)}"
                    if applied
                    else f"{name}: no default server-side encryption rule"
                ),
                detail={"algorithms": applied, "rules_examined": len(rules)},
            )
        )
    return findings


def evaluate_ebs_encryption_by_default(
    rows: list[dict[str, Any]], *, account_id: str
) -> list[ResourceFinding]:
    """One finding: the account-and-region setting is the resource.

    ``EbsEncryptionByDefault`` is per region, and the connector reads it for the
    region it is configured against. That is stated in ``detail`` so a reader
    does not take a single ``pass`` as a statement about every region the
    account uses -- it is not one, and a check that quietly implied otherwise
    would be the kind of overclaim that only shows up in an assessment.

    An empty response is ``manual_review_required`` rather than a ``fail``:
    ``get_ebs_encryption_by_default`` returning nothing means the call did not
    answer, and AWS's default being "off" is not a licence to report an
    unverified account as non-compliant when the honest answer is "unknown".
    """
    summary = rows[0] if rows else None
    if not summary or "EbsEncryptionByDefault" not in summary:
        return [
            ResourceFinding(
                resource_id=account_id,
                resource_type="aws_account",
                verdict="manual_review_required",
                observed="the account did not report an EBS default-encryption setting",
                detail={"rows_examined": len(rows)},
            )
        ]
    enabled = summary.get("EbsEncryptionByDefault") is True
    region = summary.get("Region")
    scope = f" in {region}" if region else ""
    return [
        ResourceFinding(
            resource_id=account_id,
            resource_type="aws_account",
            verdict="pass" if enabled else "fail",
            observed=(
                f"EBS encryption by default is enabled{scope}"
                if enabled
                else f"EBS encryption by default is disabled{scope}"
            ),
            detail={
                "EbsEncryptionByDefault": summary.get("EbsEncryptionByDefault"),
                # Named so a pass is not read as an account-wide claim.
                "region_assessed": region,
            },
        )
    ]


#: Check key -> its evaluator. ``scan`` dispatches through this rather than a
#: chain of conditionals, so adding a check is a registry entry.


def _unrestricted_admin_exposure(permission: dict[str, Any]) -> list[str]:
    """Which admin ports this one ingress rule exposes to the whole internet.

    ``IpProtocol: "-1"`` means every protocol and carries no ``FromPort`` at all,
    so a port-equality test misses it entirely -- as does a rule written as
    ``1-65535``, which is the likelier real-world shape. Both are handled by
    treating the rule as a range and asking whether an admin port falls inside
    it.
    """
    open_to_world = [
        cidr
        for cidr in (
            *(r.get("CidrIp") for r in permission.get("IpRanges") or []),
            *(r.get("CidrIpv6") for r in permission.get("Ipv6Ranges") or []),
        )
        if cidr in (_ANY_IPV4, _ANY_IPV6)
    ]
    if not open_to_world:
        return []
    protocol = str(permission.get("IpProtocol", ""))
    if protocol == "-1":
        return [f"all protocols from {cidr}" for cidr in open_to_world]
    from_port = permission.get("FromPort")
    if from_port is None:
        return []
    to_port = permission.get("ToPort")
    low, high = int(from_port), int(to_port if to_port is not None else from_port)
    exposed = [p for p in _ADMIN_PORTS if low <= p <= high]
    return [f"port {p} from {cidr}" for p in exposed for cidr in open_to_world]


def evaluate_security_group_admin_ingress(
    rows: list[dict[str, Any]], *, account_id: str
) -> list[ResourceFinding]:
    """One finding per security group, so a failure names what to go and fix.

    An empty answer is ``manual_review_required`` rather than ``pass``: every AWS
    account has at least a default security group, so "no groups" means the call
    did not answer, and an unverified account is not a compliant one.
    """
    if not rows:
        return [
            ResourceFinding(
                resource_id=account_id,
                resource_type="aws_account",
                verdict="manual_review_required",
                observed="the account reported no security groups, so none were assessed",
                detail={"rows_examined": 0},
            )
        ]
    findings: list[ResourceFinding] = []
    for group in rows:
        group_id = str(group.get("GroupId") or group.get("GroupName") or "unknown")
        exposures = [
            exposure
            for permission in group.get("IpPermissions") or []
            for exposure in _unrestricted_admin_exposure(permission)
        ]
        findings.append(
            ResourceFinding(
                resource_id=group_id,
                resource_type="aws_security_group",
                verdict="fail" if exposures else "pass",
                observed=(
                    f"{group.get('GroupName') or group_id} permits " + "; ".join(exposures)
                    if exposures
                    else "no unrestricted ingress to an administrative port"
                ),
                detail={
                    "group_name": group.get("GroupName"),
                    "exposures": exposures,
                    "admin_ports": list(_ADMIN_PORTS),
                },
            )
        )
    return findings


def evaluate_vpc_flow_logs(
    rows: list[dict[str, Any]], *, account_id: str
) -> list[ResourceFinding]:
    """One finding per VPC. A flow log only counts while it is ``ACTIVE``.

    Reading the row's presence rather than its status is the easy mistake and the
    expensive one: a log stuck in ``FAILED`` delivers nothing, so the boundary is
    unmonitored while the check reports it covered.
    """
    if not rows:
        return [
            ResourceFinding(
                resource_id=account_id,
                resource_type="aws_account",
                verdict="manual_review_required",
                observed="the account reported no VPCs, so none were assessed",
                detail={"rows_examined": 0},
            )
        ]
    findings: list[ResourceFinding] = []
    for vpc in rows:
        vpc_id = str(vpc.get("VpcId") or "unknown")
        logs = vpc.get("FlowLogs") or []
        active = [log for log in logs if str(log.get("FlowLogStatus", "")).upper() == "ACTIVE"]
        inactive = [
            f"{log.get('FlowLogId')} is {log.get('FlowLogStatus')}"
            for log in logs
            if log not in active
        ]
        if active:
            observed = f"{len(active)} active flow log(s)"
        elif inactive:
            observed = "no active flow log; " + "; ".join(inactive)
        else:
            observed = "no flow log is configured for this VPC"
        findings.append(
            ResourceFinding(
                resource_id=vpc_id,
                resource_type="aws_vpc",
                verdict="pass" if active else "fail",
                observed=observed,
                detail={"active": len(active), "configured": len(logs)},
            )
        )
    return findings


def evaluate_rds_not_publicly_accessible(
    rows: list[dict[str, Any]], *, account_id: str
) -> list[ResourceFinding]:
    """One finding per database, so a failure names what to go and fix.

    ``PubliclyAccessible`` is read rather than inferred. Classifying subnets as
    public or private from their route tables is the alternative, and it gets a
    NAT gateway wrong -- this field is what actually decides whether the
    instance's endpoint resolves to a public address.

    An instance that does not report the field is ``manual_review_required``:
    absent is not false, and reading it as private would report an unverified
    database as compliant. An account with no instances is ``not_applicable``
    rather than ``pass`` -- it genuinely may run no RDS, and passing would assert
    a separation nothing observed.
    """
    if not rows:
        return [
            ResourceFinding(
                resource_id=account_id,
                resource_type="aws_account",
                verdict="not_applicable",
                observed="the account runs no RDS instances",
                detail={"rows_examined": 0},
            )
        ]
    findings: list[ResourceFinding] = []
    for db in rows:
        name = str(db.get("DBInstanceIdentifier") or "unknown")
        status = str(db.get("DBInstanceStatus") or "").strip().lower()
        detail = {
            "engine": db.get("Engine"),
            "status": db.get("DBInstanceStatus"),
        }
        if status in _RDS_UNSETTLED_STATES:
            findings.append(
                ResourceFinding(
                    resource_id=name,
                    resource_type="aws_db_instance",
                    verdict="not_applicable",
                    observed=f"not assessed while the instance is {status}",
                    detail=detail,
                )
            )
            continue
        if "PubliclyAccessible" not in db:
            findings.append(
                ResourceFinding(
                    resource_id=name,
                    resource_type="aws_db_instance",
                    verdict="manual_review_required",
                    observed="the instance did not report whether it is publicly accessible",
                    detail=detail,
                )
            )
            continue
        public = db.get("PubliclyAccessible") is True
        findings.append(
            ResourceFinding(
                resource_id=name,
                resource_type="aws_db_instance",
                verdict="fail" if public else "pass",
                observed=(
                    "the instance is publicly accessible, so it is not separated from "
                    "the public network"
                    if public
                    else "the instance is not publicly accessible"
                ),
                detail=detail,
            )
        )
    return findings


def evaluate_inspector_enabled(
    rows: list[dict[str, Any]], *, account_id: str
) -> list[ResourceFinding]:
    """Is Inspector scanning every resource type, not merely switched on?

    "Any resource type enabled" is the trap. An account scanning container images
    while every EC2 instance goes unscanned has not met 3.11.2, so the verdict is
    all-of and the finding names which half is dark.

    What this does *not* claim: that findings are being remediated. That is
    3.11.3, and it stays uncovered -- scanning and fixing are different
    requirements, and a check that implied both would overstate.
    """
    status = rows[0] if rows else None
    if not status or not status.get("resourceState"):
        return [
            ResourceFinding(
                resource_id=account_id,
                resource_type="aws_account",
                verdict="manual_review_required",
                observed="the account did not report an Inspector status",
                detail={"rows_examined": len(rows)},
            )
        ]
    state = status.get("resourceState") or {}
    disabled = sorted(
        name
        for name, value in state.items()
        if str((value or {}).get("status", "")).upper() not in _INSPECTOR_ACTIVE
    )
    return [
        ResourceFinding(
            resource_id=account_id,
            resource_type="aws_account",
            verdict="fail" if disabled else "pass",
            observed=(
                "Inspector is not scanning " + ", ".join(disabled)
                if disabled
                else "Inspector is enabled for every reported resource type"
            ),
            detail={
                "disabled": disabled,
                "states": {k: (v or {}).get("status") for k, v in state.items()},
            },
        )
    ]


def evaluate_patch_compliance(
    rows: list[dict[str, Any]], *, account_id: str
) -> list[ResourceFinding]:
    """One finding per instance: are there uncorrected flaws on it?

    Missing and failed are counted together. Reading only ``MissingCount`` is the
    easy miss -- a patch that was attempted and failed is reported as failed, not
    missing, so the instance reads clean while the flaw is still present.

    An instance with neither count is ``manual_review_required``: never scanned by
    Patch Manager is not the same as patched. An account with no managed instances
    is ``not_applicable`` rather than ``pass``, because it may genuinely run none
    and passing would assert patching that nothing observed.
    """
    if not rows:
        return [
            ResourceFinding(
                resource_id=account_id,
                resource_type="aws_account",
                verdict="not_applicable",
                observed="no Systems Manager-managed instances were reported",
                detail={"rows_examined": 0},
            )
        ]
    findings: list[ResourceFinding] = []
    for row in rows:
        name = str(row.get("InstanceId") or "unknown")
        if "MissingCount" not in row and "FailedCount" not in row:
            findings.append(
                ResourceFinding(
                    resource_id=name,
                    resource_type="aws_instance",
                    verdict="manual_review_required",
                    observed="the instance reported no patch compliance data",
                    detail={"status": row.get("PatchComplianceStatus")},
                )
            )
            continue
        missing = int(row.get("MissingCount") or 0)
        failed = int(row.get("FailedCount") or 0)
        uncorrected = missing + failed
        parts = []
        if missing:
            parts.append(f"{missing} missing")
        if failed:
            parts.append(f"{failed} failed")
        findings.append(
            ResourceFinding(
                resource_id=name,
                resource_type="aws_instance",
                verdict="fail" if uncorrected else "pass",
                observed=(
                    "patches: " + " and ".join(parts)
                    if uncorrected
                    else "no missing or failed patches"
                ),
                detail={
                    "missing": missing,
                    "failed": failed,
                    "status": row.get("PatchComplianceStatus"),
                },
            )
        )
    return findings


EVALUATORS: dict[str, Callable[..., list[ResourceFinding]]] = {
    ROOT_MFA_ENABLED.key: evaluate_root_mfa,
    PASSWORD_POLICY.key: evaluate_password_policy,
    ACCESS_KEY_ROTATION.key: evaluate_access_key_rotation,
    CLOUDTRAIL_MULTI_REGION.key: evaluate_cloudtrail_multi_region,
    CLOUDTRAIL_LOG_FILE_VALIDATION.key: evaluate_cloudtrail_log_file_validation,
    S3_PUBLIC_ACCESS_BLOCKED.key: evaluate_s3_public_access_blocked,
    S3_DEFAULT_ENCRYPTION.key: evaluate_s3_default_encryption,
    EBS_ENCRYPTION_BY_DEFAULT.key: evaluate_ebs_encryption_by_default,
    SECURITY_GROUP_ADMIN_INGRESS.key: evaluate_security_group_admin_ingress,
    VPC_FLOW_LOGS.key: evaluate_vpc_flow_logs,
    RDS_NOT_PUBLICLY_ACCESSIBLE.key: evaluate_rds_not_publicly_accessible,
    INSPECTOR_ENABLED.key: evaluate_inspector_enabled,
    PATCH_COMPLIANCE.key: evaluate_patch_compliance,
}
