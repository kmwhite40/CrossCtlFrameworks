"""AWS GovCloud posture checks: the evaluators, and scan()'s orchestration.

Every evaluator is exercised against a **recorded AWS response shape** -- a
literal dict in this file, shaped the way boto3 returns it, including
``CreateDate`` as a real ``datetime`` because that is what boto3 deserializes
it to. No AWS account is reachable from the build environment, which is the
whole reason the evaluators are pure.

The scan tests monkeypatch the ``_read_*`` reader methods rather than
``_fetch``, so the source-token dispatch in ``_readers`` is exercised for real
-- a test that stubbed ``_fetch`` would pass even if no check's endpoint
resolved to a reader at all.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

import pytest

from ccf.config import get_settings
from ccf.connectors.aws import AwsGovCloudConnector, UnknownAwsSourceError
from ccf.posture.checks import (
    CHECK_REGISTRY,
    ENDPOINT_REGISTRY,
    checks_for,
    endpoint_for,
    platform_check_keys,
)
from ccf.posture.parameters import PARAMETERIZABLE, parameterize
from ccf.posture.providers import aws as aws_checks
from ccf.posture.providers.aws import (
    ACCESS_KEY_MAX_AGE_DAYS,
    ACCESS_KEY_ROTATION,
    CLOUDTRAIL_MULTI_REGION,
    MIN_PASSWORD_LENGTH,
    MIN_PASSWORD_REUSE_PREVENTION,
    PASSWORD_POLICY,
    ROOT_MFA_ENABLED,
)
from ccf.posture.resolve import ResolvedCheck, resolve_checks_from_registry

ACCOUNT = "123456789012"
NOW = datetime(2025, 9, 1, 12, 0, tzinfo=UTC)


# ── recorded AWS response shapes ─────────────────────────────────────────────

#: iam.get_account_summary()
SUMMARY_MFA_ON: dict[str, Any] = {
    "SummaryMap": {
        "AccountMFAEnabled": 1,
        "AccountAccessKeysPresent": 0,
        "Users": 12,
        "UsersQuota": 5000,
        "MFADevices": 9,
        "MFADevicesInUse": 9,
    },
    "ResponseMetadata": {"HTTPStatusCode": 200, "RequestId": "c0ffee-1"},
}

SUMMARY_MFA_OFF: dict[str, Any] = {
    "SummaryMap": {
        "AccountMFAEnabled": 0,
        "AccountAccessKeysPresent": 1,
        "Users": 12,
        "MFADevicesInUse": 4,
    },
    "ResponseMetadata": {"HTTPStatusCode": 200, "RequestId": "c0ffee-2"},
}

#: iam.get_account_password_policy()
POLICY_COMPLIANT: dict[str, Any] = {
    "PasswordPolicy": {
        "MinimumPasswordLength": 14,
        "RequireSymbols": True,
        "RequireNumbers": True,
        "RequireUppercaseCharacters": True,
        "RequireLowercaseCharacters": True,
        "AllowUsersToChangePassword": True,
        "ExpirePasswords": True,
        "MaxPasswordAge": 60,
        "PasswordReusePrevention": 24,
        "HardExpiry": False,
    },
    "ResponseMetadata": {"HTTPStatusCode": 200, "RequestId": "c0ffee-3"},
}

POLICY_WEAK: dict[str, Any] = {
    "PasswordPolicy": {
        "MinimumPasswordLength": 8,
        "RequireSymbols": False,
        "RequireNumbers": True,
        "AllowUsersToChangePassword": True,
        "ExpirePasswords": False,
    },
    "ResponseMetadata": {"HTTPStatusCode": 200, "RequestId": "c0ffee-4"},
}

#: iam.list_access_keys() -> AccessKeyMetadata entries, flattened across users.
FRESH_KEY: dict[str, Any] = {
    "UserName": "svc-etl",
    "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
    "Status": "Active",
    "CreateDate": datetime(2025, 8, 20, 9, 0, tzinfo=UTC),
}

STALE_KEY: dict[str, Any] = {
    "UserName": "svc-legacy",
    "AccessKeyId": "AKIAI44QH8DHBEXAMPLE",
    "Status": "Active",
    "CreateDate": datetime(2024, 11, 1, 9, 0, tzinfo=UTC),
}

INACTIVE_STALE_KEY: dict[str, Any] = {
    "UserName": "svc-retired",
    "AccessKeyId": "AKIAJ7GHJ2KLMEXAMPLE",
    "Status": "Inactive",
    "CreateDate": datetime(2019, 1, 1, 9, 0, tzinfo=UTC),
}

#: cloudtrail.describe_trails() -> trailList, with IsLogging merged in by the
#: connector from get_trail_status().
TRAIL_MULTI_REGION_LOGGING: dict[str, Any] = {
    "Name": "org-audit",
    "S3BucketName": "acme-gov-cloudtrail",
    "IncludeGlobalServiceEvents": True,
    "IsMultiRegionTrail": True,
    "HomeRegion": "us-gov-west-1",
    "TrailARN": "arn:aws-us-gov:cloudtrail:us-gov-west-1:123456789012:trail/org-audit",
    "LogFileValidationEnabled": True,
    "IsOrganizationTrail": False,
    "IsLogging": True,
}

TRAIL_SINGLE_REGION: dict[str, Any] = {
    "Name": "app-only",
    "S3BucketName": "acme-gov-app-trail",
    "IncludeGlobalServiceEvents": False,
    "IsMultiRegionTrail": False,
    "HomeRegion": "us-gov-east-1",
    "TrailARN": "arn:aws-us-gov:cloudtrail:us-gov-east-1:123456789012:trail/app-only",
    "IsOrganizationTrail": False,
    "IsLogging": True,
}

TRAIL_MULTI_REGION_STOPPED: dict[str, Any] = {**TRAIL_MULTI_REGION_LOGGING, "IsLogging": False}

#: get_trail_status() failed, so the connector left IsLogging off the row.
TRAIL_MULTI_REGION_UNKNOWN: dict[str, Any] = {
    k: v for k, v in TRAIL_MULTI_REGION_LOGGING.items() if k != "IsLogging"
}


# ── root MFA: a singleton read from a summary map ────────────────────────────


def test_root_mfa_passes_when_enabled() -> None:
    findings = aws_checks.evaluate_root_mfa([SUMMARY_MFA_ON], account_id=ACCOUNT)
    assert len(findings) == 1
    assert findings[0].verdict == "pass"
    assert findings[0].resource_id == ACCOUNT
    assert findings[0].resource_type == "aws_account"


def test_root_mfa_fails_and_names_the_account_and_the_value() -> None:
    findings = aws_checks.evaluate_root_mfa([SUMMARY_MFA_OFF], account_id=ACCOUNT)
    assert len(findings) == 1
    f = findings[0]
    assert f.verdict == "fail"
    # A finding an operator cannot act on is not worth emitting: it must say
    # WHICH account and WHAT was observed, not merely "fail".
    assert f.resource_id == ACCOUNT
    assert "AccountMFAEnabled=0" in f.observed
    assert f.detail["AccountMFAEnabled"] == 0


def test_root_mfa_with_no_summary_is_manual_review_not_pass() -> None:
    """An unobserved root user is not an MFA-protected root user."""
    findings = aws_checks.evaluate_root_mfa([], account_id=ACCOUNT)
    assert len(findings) == 1
    assert findings[0].verdict == "manual_review_required"
    assert findings[0].verdict != "pass"


def test_root_mfa_ignores_a_row_without_a_summary_map() -> None:
    findings = aws_checks.evaluate_root_mfa(
        [{"ResponseMetadata": {"HTTPStatusCode": 200}}], account_id=ACCOUNT
    )
    assert findings[0].verdict == "manual_review_required"


# ── password policy: a singleton whose absence is the finding ────────────────


def test_password_policy_passes_at_the_required_minimums() -> None:
    findings = aws_checks.evaluate_password_policy([POLICY_COMPLIANT], account_id=ACCOUNT)
    assert len(findings) == 1
    assert findings[0].verdict == "pass"
    assert findings[0].resource_id == ACCOUNT


def test_password_policy_fails_and_names_each_shortfall_with_its_value() -> None:
    findings = aws_checks.evaluate_password_policy([POLICY_WEAK], account_id=ACCOUNT)
    f = findings[0]
    assert f.verdict == "fail"
    assert f.resource_id == ACCOUNT
    # Observed value AND the requirement, so the finding is actionable.
    assert "minimum length 8" in f.observed
    assert f"requires {MIN_PASSWORD_LENGTH}" in f.observed
    assert "password reuse prevention not set" in f.observed
    assert f"requires {MIN_PASSWORD_REUSE_PREVENTION}" in f.observed
    assert f.detail["MinimumPasswordLength"] == 8


def test_no_password_policy_at_all_is_a_fail_not_not_applicable() -> None:
    """The weakest possible configuration must not get the most benign verdict.

    IAM raises NoSuchEntity when no policy exists and the reader turns exactly
    that into []. An account with no policy runs AWS's permissive default.
    """
    findings = aws_checks.evaluate_password_policy([], account_id=ACCOUNT)
    assert len(findings) == 1
    assert findings[0].verdict == "fail"
    assert findings[0].verdict != "not_applicable"
    assert "no IAM account password policy is configured" in findings[0].observed


def test_password_policy_boundary_is_at_the_constant() -> None:
    """One short of the minimum fails; exactly the minimum passes."""
    at = {"PasswordPolicy": {"MinimumPasswordLength": MIN_PASSWORD_LENGTH,
                             "PasswordReusePrevention": MIN_PASSWORD_REUSE_PREVENTION}}
    under = {"PasswordPolicy": {"MinimumPasswordLength": MIN_PASSWORD_LENGTH - 1,
                                "PasswordReusePrevention": MIN_PASSWORD_REUSE_PREVENTION}}
    assert aws_checks.evaluate_password_policy([at], account_id=ACCOUNT)[0].verdict == "pass"
    assert aws_checks.evaluate_password_policy([under], account_id=ACCOUNT)[0].verdict == "fail"


def test_password_policy_rejects_a_boolean_masquerading_as_a_length() -> None:
    """``True`` is an ``int`` in Python; a policy of "True characters" is not a
    policy of 14 characters."""
    row = {"PasswordPolicy": {"MinimumPasswordLength": True, "PasswordReusePrevention": True}}
    assert aws_checks.evaluate_password_policy([row], account_id=ACCOUNT)[0].verdict == "fail"


# ── access keys: a fleet with exclusions ─────────────────────────────────────


def test_access_key_rotation_passes_a_fresh_key() -> None:
    findings = aws_checks.evaluate_access_key_rotation([FRESH_KEY], now=NOW)
    assert len(findings) == 1
    assert findings[0].verdict == "pass"
    assert findings[0].resource_id == FRESH_KEY["AccessKeyId"]


def test_access_key_rotation_fails_and_names_the_key_user_and_age() -> None:
    findings = aws_checks.evaluate_access_key_rotation([STALE_KEY], now=NOW)
    f = findings[0]
    assert f.verdict == "fail"
    assert f.resource_id == STALE_KEY["AccessKeyId"]  # which key to rotate
    assert "svc-legacy" in f.observed  # whose key it is
    expected_age = (NOW - STALE_KEY["CreateDate"]).days
    assert f"{expected_age} day(s) ago" in f.observed  # the observed value
    assert f.detail["age_days"] == expected_age


def test_access_key_rotation_on_an_empty_fleet_returns_nothing() -> None:
    assert aws_checks.evaluate_access_key_rotation([], now=NOW) == []


def test_an_inactive_key_is_excluded_rather_than_passed() -> None:
    """An inactive key cannot authenticate, so it is not a rotation risk --
    and counting it as a pass would inflate a clean-looking fleet."""
    findings = aws_checks.evaluate_access_key_rotation([INACTIVE_STALE_KEY], now=NOW)
    assert findings[0].verdict == "not_applicable"
    assert findings[0].verdict != "pass"
    assert "Inactive" in findings[0].observed


def test_an_unreadable_create_date_is_manual_review_not_pass() -> None:
    naive = {**FRESH_KEY, "CreateDate": datetime(2025, 8, 20, 9, 0)}
    missing = {k: v for k, v in FRESH_KEY.items() if k != "CreateDate"}
    garbage = {**FRESH_KEY, "CreateDate": "not-a-date"}
    for row in (naive, missing, garbage):
        findings = aws_checks.evaluate_access_key_rotation([row], now=NOW)
        assert findings[0].verdict == "manual_review_required", row.get("CreateDate")
        assert findings[0].verdict != "pass"


def test_an_iso_string_create_date_is_accepted() -> None:
    """A recorded or round-tripped payload carries the ISO-8601 form."""
    row = {**FRESH_KEY, "CreateDate": "2025-08-20T09:00:00Z"}
    assert aws_checks.evaluate_access_key_rotation([row], now=NOW)[0].verdict == "pass"


def test_a_key_without_an_id_is_still_reported() -> None:
    row = {k: v for k, v in STALE_KEY.items() if k != "AccessKeyId"}
    findings = aws_checks.evaluate_access_key_rotation([row], now=NOW)
    assert len(findings) == 1
    assert findings[0].resource_id == "unknown"


def test_access_key_threshold_does_not_truncate_to_whole_days() -> None:
    """``elapsed.days`` truncates, which would make a 90-day threshold behave
    like 91. The comparison must use the full-precision delta."""
    exactly = {**FRESH_KEY, "CreateDate": NOW - timedelta(days=ACCESS_KEY_MAX_AGE_DAYS)}
    just_over = {
        **FRESH_KEY,
        "CreateDate": NOW - timedelta(days=ACCESS_KEY_MAX_AGE_DAYS, seconds=1),
    }
    assert aws_checks.evaluate_access_key_rotation([exactly], now=NOW)[0].verdict == "pass"
    assert aws_checks.evaluate_access_key_rotation([just_over], now=NOW)[0].verdict == "fail"


def test_a_mixed_fleet_reports_every_key_once() -> None:
    findings = aws_checks.evaluate_access_key_rotation(
        [FRESH_KEY, STALE_KEY, INACTIVE_STALE_KEY], now=NOW
    )
    assert [f.verdict for f in findings] == ["pass", "fail", "not_applicable"]


# ── CloudTrail: a singleton derived by any-of over a fleet ───────────────────


def test_cloudtrail_passes_when_a_multi_region_trail_is_logging() -> None:
    findings = aws_checks.evaluate_cloudtrail_multi_region(
        [TRAIL_SINGLE_REGION, TRAIL_MULTI_REGION_LOGGING], account_id=ACCOUNT
    )
    assert len(findings) == 1  # the account is the resource, not each trail
    assert findings[0].verdict == "pass"
    assert findings[0].resource_id == ACCOUNT
    assert "org-audit" in findings[0].observed


def test_cloudtrail_fails_when_the_only_multi_region_trail_is_stopped() -> None:
    findings = aws_checks.evaluate_cloudtrail_multi_region(
        [TRAIL_MULTI_REGION_STOPPED], account_id=ACCOUNT
    )
    f = findings[0]
    assert f.verdict == "fail"
    assert f.resource_id == ACCOUNT
    assert "1 trail(s) examined" in f.observed
    # The fleet is in detail so a reader can see WHY, per trail.
    assert f.detail["trails"] == [
        {"name": "org-audit", "multi_region": True, "logging": False}
    ]


def test_cloudtrail_fails_when_only_single_region_trails_exist() -> None:
    findings = aws_checks.evaluate_cloudtrail_multi_region(
        [TRAIL_SINGLE_REGION], account_id=ACCOUNT
    )
    assert findings[0].verdict == "fail"
    assert findings[0].detail["trails"][0]["multi_region"] is False


def test_cloudtrail_with_no_trails_at_all_fails() -> None:
    findings = aws_checks.evaluate_cloudtrail_multi_region([], account_id=ACCOUNT)
    assert len(findings) == 1
    assert findings[0].verdict == "fail"
    assert "no CloudTrail trail is configured" in findings[0].observed


def test_cloudtrail_with_an_unreadable_status_is_manual_review() -> None:
    """An unread status is not proof the trail is stopped, nor that it runs."""
    findings = aws_checks.evaluate_cloudtrail_multi_region(
        [TRAIL_MULTI_REGION_UNKNOWN], account_id=ACCOUNT
    )
    assert findings[0].verdict == "manual_review_required"
    assert findings[0].verdict not in ("pass", "fail")


def test_a_logging_multi_region_trail_outranks_an_unreadable_one() -> None:
    findings = aws_checks.evaluate_cloudtrail_multi_region(
        [TRAIL_MULTI_REGION_UNKNOWN, TRAIL_MULTI_REGION_LOGGING], account_id=ACCOUNT
    )
    assert findings[0].verdict == "pass"


# ── the expectation's wording cannot disagree with what is enforced ──────────


def test_the_rotation_expectation_is_rendered_from_the_enforced_constant() -> None:
    assert str(ACCESS_KEY_MAX_AGE_DAYS) in ACCESS_KEY_ROTATION.expected
    assert ACCESS_KEY_ROTATION.expected == aws_checks.ACCESS_KEY_ROTATION_EXPECTED.format(
        threshold_days=ACCESS_KEY_MAX_AGE_DAYS
    )
    # The default the evaluator actually enforces is that same constant: a key
    # one second past it fails without the threshold being passed in.
    just_over = {
        **FRESH_KEY,
        "CreateDate": NOW - timedelta(days=ACCESS_KEY_MAX_AGE_DAYS, seconds=1),
    }
    assert aws_checks.evaluate_access_key_rotation([just_over], now=NOW)[0].verdict == "fail"


def test_a_parameterized_rotation_check_cannot_claim_one_threshold_and_enforce_another() -> None:
    """The SSP-facing prose and the enforced value come from one parameter."""
    parameterized = parameterize(ACCESS_KEY_ROTATION, {"threshold_days": 45})
    assert "45 days" in parameterized.expected
    assert str(ACCESS_KEY_MAX_AGE_DAYS) not in parameterized.expected
    # 60 days old: compliant under the platform default, failing under 45.
    key = {**FRESH_KEY, "CreateDate": NOW - timedelta(days=60)}
    assert aws_checks.evaluate_access_key_rotation([key], now=NOW)[0].verdict == "pass"
    assert (
        aws_checks.evaluate_access_key_rotation([key], now=NOW, threshold_days=45)[0].verdict
        == "fail"
    )


def test_the_password_policy_expectation_is_rendered_from_its_constants() -> None:
    assert PASSWORD_POLICY.expected == aws_checks.PASSWORD_POLICY_EXPECTED.format(
        min_length=MIN_PASSWORD_LENGTH,
        reuse_generations=MIN_PASSWORD_REUSE_PREVENTION,
    )
    assert str(MIN_PASSWORD_LENGTH) in PASSWORD_POLICY.expected
    assert str(MIN_PASSWORD_REUSE_PREVENTION) in PASSWORD_POLICY.expected


# ── registration: the platform must be able to find these checks ─────────────


def test_the_registry_knows_the_aws_checks() -> None:
    """Registration silently missing is the failure mode this guards."""
    keys = {c.key for c in checks_for("aws_govcloud")}
    assert keys == {c.key for c in aws_checks.CHECKS}
    assert CHECK_REGISTRY["aws_govcloud"] == aws_checks.CHECKS
    for check in aws_checks.CHECKS:
        assert check.provider == "aws_govcloud", check.key
        assert check.control_ids, check.key
        assert check.required_permissions, check.key
        assert endpoint_for("aws_govcloud", check.key), check.key
        assert check.key in platform_check_keys()
    assert set(ENDPOINT_REGISTRY["aws_govcloud"]) == {c.key for c in aws_checks.CHECKS}


def test_every_aws_check_resolves_from_the_registry_with_an_endpoint() -> None:
    resolved = resolve_checks_from_registry("aws_govcloud")
    assert [r.check.key for r in resolved] == [c.key for c in aws_checks.CHECKS]
    assert {r.source for r in resolved} == {"platform"}
    for r in resolved:
        assert r.endpoint == aws_checks.ENDPOINTS[r.check.key]
        assert r.evaluator_key == r.check.key


def test_every_aws_check_has_an_evaluator_and_a_reader() -> None:
    """A check registered into a source nothing reads cannot run."""
    readers = AwsGovCloudConnector(credential={})._readers()
    for check in aws_checks.CHECKS:
        assert check.key in aws_checks.EVALUATORS, check.key
        assert aws_checks.ENDPOINTS[check.key] in readers, check.key


def test_every_aws_check_appears_in_the_parameterizable_vocabulary() -> None:
    """A check absent from PARAMETERIZABLE cannot be named by a pack at all."""
    for check in aws_checks.CHECKS:
        assert check.key in PARAMETERIZABLE, check.key


def test_aws_endpoints_are_source_tokens_not_urls() -> None:
    """The design decision, asserted: AWS has no URLs, so the registry holds
    boto3 ``<service>.<operation>`` tokens. A URL-shaped placeholder here
    would be a fiction nothing could ever fetch."""
    for endpoint in aws_checks.ENDPOINTS.values():
        assert not endpoint.startswith(("/", "http://", "https://")), endpoint
        service, _, operation = endpoint.partition(".")
        assert service and operation, endpoint
        # A source token and an IAM action are different vocabularies.
        assert ":" not in endpoint, endpoint


# ── scan(): configuration, isolation, and the empty-tuple contract ───────────

CRED = {
    "access_key_id": "AKIA-TEST",
    "secret_access_key": "shh",
    "account_id": ACCOUNT,
}


@pytest.fixture
def aws_enabled(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """The deployment flag on and boto3 "present" -- neither is under test here."""
    monkeypatch.setattr(AwsGovCloudConnector, "_boto3_available", lambda self: True)
    monkeypatch.setenv("CCF_AWS_CAPTURE_ENABLED", "true")
    get_settings.cache_clear()
    try:
        yield
    finally:
        monkeypatch.delenv("CCF_AWS_CAPTURE_ENABLED", raising=False)
        get_settings.cache_clear()


def _key_aged(days: int, **overrides: Any) -> dict[str, Any]:
    """An access key of a given age *against the real clock*.

    ``scan()`` calls ``datetime.now(UTC)`` itself -- that is the point of the
    evaluator taking ``now`` as a parameter and the connector being the only
    thing that reads a clock. So a scan-level fixture must be aged relative to
    the real now, not to this module's frozen ``NOW``: pinning it to a fixed
    date would make these tests' verdicts drift with the calendar and pass or
    fail for reasons unrelated to the code.
    """
    return {
        **FRESH_KEY,
        "CreateDate": datetime.now(UTC) - timedelta(days=days),
        **overrides,
    }


def _wire_readers(monkeypatch: pytest.MonkeyPatch, **overrides: Any) -> None:
    """Point each reader at a recorded payload, overridable per reader."""
    defaults: dict[str, Any] = {
        "_read_account_summary": lambda self: [SUMMARY_MFA_ON],
        "_read_password_policy": lambda self: [POLICY_COMPLIANT],
        "_read_access_keys": lambda self: [
            _key_aged(10),
            _key_aged(ACCESS_KEY_MAX_AGE_DAYS + 30, UserName="svc-legacy",
                      AccessKeyId=STALE_KEY["AccessKeyId"]),
        ],
        "_read_cloudtrail_trails": lambda self: [TRAIL_MULTI_REGION_LOGGING],
    }
    for name, fn in {**defaults, **overrides}.items():
        monkeypatch.setattr(AwsGovCloudConnector, name, fn)


async def test_scan_returns_empty_when_unconfigured() -> None:
    """No feature flag, no credential: nothing to scan, and never an exception."""
    assert await AwsGovCloudConnector(credential=None).scan() == []
    assert await AwsGovCloudConnector(credential=CRED).scan() == []


async def test_scan_returns_empty_when_the_org_has_no_credential(
    aws_enabled: None,
) -> None:
    """The flag is on deployment-wide, but this org bound nothing (IA-05: no
    ambient-credential fallback, so there is nothing to scan under)."""
    assert AwsGovCloudConnector(credential=None).is_configured() is False
    assert await AwsGovCloudConnector(credential=None).scan() == []
    assert await AwsGovCloudConnector(credential={}).scan() == []
    assert await AwsGovCloudConnector(credential={"region": "us-gov-west-1"}).scan() == []


async def test_scan_returns_one_outcome_per_registered_check(
    aws_enabled: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    _wire_readers(monkeypatch)
    outcomes = await AwsGovCloudConnector(credential=CRED).scan()
    assert {o.check_key for o in outcomes} == {c.key for c in aws_checks.CHECKS}
    by_key = {o.check_key: o for o in outcomes}
    assert by_key[ROOT_MFA_ENABLED.key].verdict == "pass"
    assert by_key[PASSWORD_POLICY.key].verdict == "pass"
    assert by_key[CLOUDTRAIL_MULTI_REGION.key].verdict == "pass"
    # One stale key in the fleet fails the check; the fresh one still counted.
    rotation = by_key[ACCESS_KEY_ROTATION.key]
    assert rotation.verdict == "fail"
    assert rotation.evaluated == 2
    assert rotation.failing == 1
    assert rotation.expected == ACCESS_KEY_ROTATION.expected


async def test_one_checks_fetch_failing_does_not_lose_the_others(
    aws_enabled: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """THE property most likely to be quietly lost. One service permission gap
    must not discard every outcome already collected."""

    def boom(self: Any) -> list[dict[str, Any]]:
        raise RuntimeError("iam exploded")

    _wire_readers(monkeypatch, _read_access_keys=boom)
    outcomes = await AwsGovCloudConnector(credential=CRED).scan()

    assert {o.check_key for o in outcomes} == {c.key for c in aws_checks.CHECKS}
    by_key = {o.check_key: o for o in outcomes}
    assert by_key[ACCESS_KEY_ROTATION.key].verdict == "manual_review_required"
    assert by_key[ACCESS_KEY_ROTATION.key].verdict != "not_applicable"
    assert "RuntimeError" in by_key[ACCESS_KEY_ROTATION.key].findings[0].observed
    # The other three still came back, and still with their real verdicts.
    assert by_key[ROOT_MFA_ENABLED.key].verdict == "pass"
    assert by_key[PASSWORD_POLICY.key].verdict == "pass"
    assert by_key[CLOUDTRAIL_MULTI_REGION.key].verdict == "pass"


async def test_an_evaluator_failure_also_stays_isolated(
    aws_enabled: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fetch succeeded but the rows were not what the evaluator expected."""
    _wire_readers(monkeypatch, _read_access_keys=lambda self: ["not-a-dict"])
    outcomes = await AwsGovCloudConnector(credential=CRED).scan()
    by_key = {o.check_key: o for o in outcomes}
    assert len(outcomes) == len(aws_checks.CHECKS)
    assert by_key[ACCESS_KEY_ROTATION.key].verdict == "manual_review_required"
    assert by_key[ROOT_MFA_ENABLED.key].verdict == "pass"


async def test_an_access_denied_names_the_permissions_it_needs(
    aws_enabled: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    class ClientError(Exception):
        response: ClassVar[dict[str, Any]] = {
            "Error": {"Code": "AccessDenied", "Message": "nope"}
        }

    def denied(self: Any) -> list[dict[str, Any]]:
        raise ClientError

    _wire_readers(monkeypatch, _read_cloudtrail_trails=denied)
    outcomes = await AwsGovCloudConnector(credential=CRED).scan()
    trail = next(o for o in outcomes if o.check_key == CLOUDTRAIL_MULTI_REGION.key)
    assert trail.verdict == "manual_review_required"
    assert "AccessDenied" in trail.findings[0].observed
    assert "cloudtrail:DescribeTrails" in trail.findings[0].observed
    assert trail.findings[0].resource_id == ACCOUNT


async def test_a_throttling_error_does_not_blame_permissions(
    aws_enabled: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An operator must never be told to grant an action that was never the
    problem."""

    class ClientError(Exception):
        response: ClassVar[dict[str, Any]] = {"Error": {"Code": "Throttling"}}

    def throttled(self: Any) -> list[dict[str, Any]]:
        raise ClientError

    _wire_readers(monkeypatch, _read_account_summary=throttled)
    outcomes = await AwsGovCloudConnector(credential=CRED).scan()
    root = next(o for o in outcomes if o.check_key == ROOT_MFA_ENABLED.key)
    assert "Throttling" in root.findings[0].observed
    assert "iam:GetAccountSummary" not in root.findings[0].observed


async def test_an_unreadable_account_id_does_not_stop_the_scan(
    aws_enabled: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    _wire_readers(monkeypatch)

    async def no_identity(self: Any) -> str:
        raise RuntimeError("sts unreachable")

    monkeypatch.setattr(AwsGovCloudConnector, "_account_id", no_identity)
    outcomes = await AwsGovCloudConnector(credential=CRED).scan()
    assert len(outcomes) == len(aws_checks.CHECKS)
    root = next(o for o in outcomes if o.check_key == ROOT_MFA_ENABLED.key)
    assert root.findings[0].resource_id == "unknown"


# ── checks=() scans nothing, and must NOT fall back to the registry ──────────


async def test_an_empty_tuple_scans_nothing_and_never_reaches_the_registry(
    aws_enabled: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Asserted directly, because this is easy to get backwards: an empty tuple
    means "this tenant has nothing to scan", not "use the defaults"."""
    _wire_readers(monkeypatch)

    def must_not_be_called(provider: str) -> tuple[ResolvedCheck, ...]:
        raise AssertionError(f"registry consulted for {provider!r} despite checks=()")

    monkeypatch.setattr(
        "ccf.connectors.aws.resolve_checks_from_registry", must_not_be_called
    )
    assert await AwsGovCloudConnector(credential=CRED).scan(checks=()) == []


async def test_checks_none_does_consult_the_registry(
    aws_enabled: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other half of the contract -- without this, the test above would
    also pass against a scan() that never consulted the registry at all."""
    _wire_readers(monkeypatch)
    calls: list[str] = []
    real = resolve_checks_from_registry

    def spy(provider: str) -> tuple[ResolvedCheck, ...]:
        calls.append(provider)
        return real(provider)

    monkeypatch.setattr("ccf.connectors.aws.resolve_checks_from_registry", spy)
    outcomes = await AwsGovCloudConnector(credential=CRED).scan()
    assert calls == ["aws_govcloud"]
    assert len(outcomes) == len(aws_checks.CHECKS)


async def test_an_explicit_subset_scans_only_that_subset(
    aws_enabled: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    _wire_readers(monkeypatch)
    only = tuple(
        r for r in resolve_checks_from_registry("aws_govcloud")
        if r.check.key == ROOT_MFA_ENABLED.key
    )
    outcomes = await AwsGovCloudConnector(credential=CRED).scan(checks=only)
    assert [o.check_key for o in outcomes] == [ROOT_MFA_ENABLED.key]


# ── a pack's parameters reach the evaluator; an unknown source cannot run ────


async def test_a_packs_threshold_reaches_the_evaluator(
    aws_enabled: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Form A end to end: the pack's threshold decides the verdict, and the
    check's prose says the same number."""
    _wire_readers(monkeypatch, _read_access_keys=lambda self: [_key_aged(60)])
    platform = next(
        r for r in resolve_checks_from_registry("aws_govcloud")
        if r.check.key == ACCESS_KEY_ROTATION.key
    )
    declared = ResolvedCheck(
        check=parameterize(ACCESS_KEY_ROTATION, {"threshold_days": 45}),
        endpoint=platform.endpoint,
        source="pack:tight-rotation",
        evaluator_key=ACCESS_KEY_ROTATION.key,
        parameters={"threshold_days": 45},
    )
    outcomes = await AwsGovCloudConnector(credential=CRED).scan(checks=(platform, declared))
    by_source = {o.expected: o.verdict for o in outcomes}
    assert by_source[ACCESS_KEY_ROTATION.expected] == "pass"  # 90-day default
    assert by_source[declared.check.expected] == "fail"  # the pack's 45 days
    assert "45 days" in declared.check.expected


async def test_a_tenant_declared_source_cannot_run_and_says_so(
    aws_enabled: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The stated capability gap, made visible at runtime.

    A Form B rule naming ``provider: aws_govcloud`` carries a Graph-shaped
    endpoint (the only shape pack validation admits). It must not silently
    vanish, and it must certainly not be turned into a boto3 call.
    """
    _wire_readers(monkeypatch)
    declared = ResolvedCheck(
        check=ROOT_MFA_ENABLED,
        endpoint="/v1.0/users",
        source="pack:wishful",
        evaluator_key=ROOT_MFA_ENABLED.key,
    )
    outcomes = await AwsGovCloudConnector(credential=CRED).scan(checks=(declared,))
    assert len(outcomes) == 1
    assert outcomes[0].verdict == "manual_review_required"
    observed = outcomes[0].findings[0].observed
    assert "/v1.0/users" in observed
    assert "tenant-declared AWS checks are not supported" in observed


async def test_an_unknown_source_token_raises_rather_than_reaching_boto3() -> None:
    """Raised by _fetch's dispatch -- the layer that would otherwise have to
    decide what to do with an unrecognised token -- and not by boto3 refusing
    an operation it was handed, which would mean the token reached AWS."""
    conn = AwsGovCloudConnector(credential=CRED)
    assert "ec2.describe_instances" not in conn._readers()
    with pytest.raises(UnknownAwsSourceError, match=re.escape("ec2.describe_instances")):
        await conn._fetch("ec2.describe_instances")
