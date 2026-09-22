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

CHECKS: tuple[PostureCheck, ...] = (
    ROOT_MFA_ENABLED,
    PASSWORD_POLICY,
    ACCESS_KEY_ROTATION,
    CLOUDTRAIL_MULTI_REGION,
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
}

#: Evaluators that need to be told which account they are judging, because
#: their resource is the account itself rather than a row AWS returned.
ACCOUNT_SCOPED: frozenset[str] = frozenset(
    {ROOT_MFA_ENABLED.key, PASSWORD_POLICY.key, CLOUDTRAIL_MULTI_REGION.key}
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


#: Check key -> its evaluator. ``scan`` dispatches through this rather than a
#: chain of conditionals, so adding a check is a registry entry.
EVALUATORS: dict[str, Callable[..., list[ResourceFinding]]] = {
    ROOT_MFA_ENABLED.key: evaluate_root_mfa,
    PASSWORD_POLICY.key: evaluate_password_policy,
    ACCESS_KEY_ROTATION.key: evaluate_access_key_rotation,
    CLOUDTRAIL_MULTI_REGION.key: evaluate_cloudtrail_multi_region,
}
