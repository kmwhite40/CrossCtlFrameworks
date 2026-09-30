"""AWS: audit-log integrity and storage encryption produce verdicts.

The AWS connector carried four checks, all of them identity or audit
*configuration*: root MFA, the password policy, key rotation, and whether a
multi-region trail is logging. Nothing assessed whether the audit record could
be tampered with, and nothing assessed storage encryption at all -- so an AWS
tenant's SC-28 and AU-9 read as unaddressed no matter what the account actually
did.

These four close that, and are chosen to span distinct verdict shapes rather
than four variants of one, the way the existing AWS checks do:

* :data:`CLOUDTRAIL_LOG_FILE_VALIDATION` -- a **fleet judged per member**, on
  rows the connector already fetches for another check.
* :data:`S3_PUBLIC_ACCESS_BLOCKED` -- a **fleet with an all-of condition** and a
  finding that names which of the four settings is missing.
* :data:`S3_DEFAULT_ENCRYPTION` -- a **fleet judged on presence**, deliberately
  not on the algorithm.
* :data:`EBS_ENCRYPTION_BY_DEFAULT` -- a **singleton scoped to one region**,
  where an unanswered call is not a failure.

Every evaluator is pure, so these run against recorded AWS response shapes. No
AWS account is reachable from the build environment, which is the reason the
purity is load-bearing rather than stylistic.
"""

from __future__ import annotations

import pytest

from ccf.posture.checks import CHECK_REGISTRY
from ccf.posture.providers import aws
from ccf.posture.types import CheckOutcome

ACCOUNT = "123456789012"


def _verdicts(findings: list) -> dict[str, str]:
    return {f.resource_id: f.verdict for f in findings}


def _rollup(check, findings) -> str:
    return CheckOutcome.from_findings(check, tuple(findings)).verdict


# ---------------------------------------------------------------------------
# AU-9 — the audit record has to be tamper-evident
# ---------------------------------------------------------------------------


def test_an_unvalidated_trail_fails_even_beside_a_validated_one() -> None:
    """Not an any-of, unlike the multi-region check on the same rows.

    That check asks whether the account records its activity, which one healthy
    trail answers. AU-9 asks whether the record is protected from modification,
    and an unvalidated trail's log files can be altered undetectably however
    many validated trails sit beside it.
    """
    findings = aws.evaluate_cloudtrail_log_file_validation(
        [
            {"Name": "org-trail", "TrailARN": "arn:aws:cloudtrail:::org-trail",
             "LogFileValidationEnabled": True},
            {"Name": "ad-hoc", "TrailARN": "arn:aws:cloudtrail:::ad-hoc",
             "LogFileValidationEnabled": False},
        ]
    )
    assert _verdicts(findings) == {
        "arn:aws:cloudtrail:::org-trail": "pass",
        "arn:aws:cloudtrail:::ad-hoc": "fail",
    }
    assert _rollup(aws.CLOUDTRAIL_LOG_FILE_VALIDATION, findings) == "fail"


def test_an_absent_validation_field_is_a_failure_not_an_unknown() -> None:
    """`describe_trails` always returns the field, and AWS's default is false.

    This is the opposite treatment from ``IsLogging``, which comes from a second
    call that can genuinely fail and is therefore reported as unknown when
    missing. Conflating the two would either invent findings or hide them.
    """
    findings = aws.evaluate_cloudtrail_log_file_validation(
        [{"Name": "quiet", "TrailARN": "arn:quiet"}]
    )
    assert _verdicts(findings) == {"arn:quiet": "fail"}
    assert "not enabled" in findings[0].observed


def test_a_validated_fleet_passes() -> None:
    findings = aws.evaluate_cloudtrail_log_file_validation(
        [
            {"Name": "a", "TrailARN": "arn:a", "LogFileValidationEnabled": True},
            {"Name": "b", "TrailARN": "arn:b", "LogFileValidationEnabled": True},
        ]
    )
    assert _rollup(aws.CLOUDTRAIL_LOG_FILE_VALIDATION, findings) == "pass"


# ---------------------------------------------------------------------------
# AC-3 / AC-4 / SC-7 — buckets must not be public
# ---------------------------------------------------------------------------


def _pab(**overrides: bool) -> dict:
    config = dict.fromkeys(aws._PUBLIC_ACCESS_BLOCK_SETTINGS, True)
    config.update(overrides)
    return config


def test_a_fully_blocked_bucket_passes() -> None:
    findings = aws.evaluate_s3_public_access_blocked(
        [{"Name": "cui-store", "PublicAccessBlockConfiguration": _pab()}]
    )
    assert _verdicts(findings) == {"cui-store": "pass"}


@pytest.mark.parametrize("setting", aws._PUBLIC_ACCESS_BLOCK_SETTINGS)
def test_any_one_setting_off_fails_and_is_named(setting: str) -> None:
    """All four are required, and the finding says which one is missing.

    The parametrization is the point: ``BlockPublicAcls`` stops new public ACLs
    while ``IgnorePublicAcls`` neutralizes ones already set, and the same split
    applies to policies. A check that accepted three of four would leave one of
    the two routes to the data open.

    The missing setting appears in ``observed``, not only in ``detail``, because
    ``observed`` is what reaches a POA&M's weakness line -- "bucket is public"
    is not something an engineer can act on.
    """
    findings = aws.evaluate_s3_public_access_blocked(
        [{"Name": "leaky", "PublicAccessBlockConfiguration": _pab(**{setting: False})}]
    )
    assert _verdicts(findings) == {"leaky": "fail"}
    assert setting in findings[0].observed


def test_a_bucket_with_no_block_configuration_fails() -> None:
    """The permissive default is in force, which is the finding.

    The connector turns AWS's ``NoSuchPublicAccessBlockConfiguration`` into an
    empty envelope precisely so this reads as a failure rather than as an error.
    """
    findings = aws.evaluate_s3_public_access_blocked(
        [{"Name": "never-configured", "PublicAccessBlockConfiguration": {}}]
    )
    assert _verdicts(findings) == {"never-configured": "fail"}


def test_a_bucket_that_could_not_be_read_is_not_reported_as_public() -> None:
    """"I could not look" and "it is open" are different facts.

    Reporting the first as the second sends somebody to remediate a bucket that
    may be fine; reporting it as a pass hides one that is not. Neither is
    acceptable, so it is escalated for review.
    """
    findings = aws.evaluate_s3_public_access_blocked(
        [{"Name": "denied", "Unreadable": "AccessDenied"}]
    )
    assert _verdicts(findings) == {"denied": "manual_review_required"}
    assert "AccessDenied" in findings[0].observed


def test_an_unreadable_bucket_does_not_make_the_check_pass() -> None:
    """A fleet of nothing but unreadable buckets must not roll up to `pass`."""
    findings = aws.evaluate_s3_public_access_blocked(
        [{"Name": "a", "Unreadable": "AccessDenied"}]
    )
    assert _rollup(aws.S3_PUBLIC_ACCESS_BLOCKED, findings) != "pass"


# ---------------------------------------------------------------------------
# SC-28 — objects and volumes encrypted at rest
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm", ["AES256", "aws:kms"])
def test_either_encryption_algorithm_satisfies_the_check(algorithm: str) -> None:
    """SSE-S3 and SSE-KMS both satisfy SC-28, and the check may not pick one.

    Which key is acceptable is an organization-defined decision under SC-28(1).
    Failing a bucket for using ``AES256`` would be this module inventing a
    requirement an assessor never set, so the algorithm is recorded and not
    judged.
    """
    findings = aws.evaluate_s3_default_encryption(
        [
            {
                "Name": "cui-store",
                "ServerSideEncryptionConfiguration": {
                    "Rules": [
                        {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": algorithm}}
                    ]
                },
            }
        ]
    )
    assert _verdicts(findings) == {"cui-store": "pass"}
    assert findings[0].detail["algorithms"] == [algorithm]


def test_a_bucket_with_no_encryption_rule_fails() -> None:
    findings = aws.evaluate_s3_default_encryption(
        [{"Name": "plain", "ServerSideEncryptionConfiguration": {}}]
    )
    assert _verdicts(findings) == {"plain": "fail"}
    assert "no default server-side encryption" in findings[0].observed


def test_a_rule_naming_no_algorithm_is_not_counted_as_encryption() -> None:
    """An empty rule is a rule that encrypts nothing.

    A truthiness check on ``Rules`` alone would pass this, which is the shape a
    bucket ends up in when a rule was created and never completed.
    """
    findings = aws.evaluate_s3_default_encryption(
        [
            {
                "Name": "half-configured",
                "ServerSideEncryptionConfiguration": {
                    "Rules": [{"ApplyServerSideEncryptionByDefault": {}}]
                },
            }
        ]
    )
    assert _verdicts(findings) == {"half-configured": "fail"}


def test_an_unreadable_encryption_configuration_is_escalated() -> None:
    findings = aws.evaluate_s3_default_encryption(
        [{"Name": "denied", "Unreadable": "AccessDenied"}]
    )
    assert _verdicts(findings) == {"denied": "manual_review_required"}


def test_ebs_default_encryption_on_passes_and_names_the_region() -> None:
    """A pass must not read as a claim about every region the account uses.

    ``EbsEncryptionByDefault`` is per region. The region the connector actually
    read is carried in ``detail`` and in the observed string, so an assessor is
    not left to assume account-wide scope the data does not support.
    """
    findings = aws.evaluate_ebs_encryption_by_default(
        [{"EbsEncryptionByDefault": True, "Region": "us-gov-west-1"}],
        account_id=ACCOUNT,
    )
    assert _verdicts(findings) == {ACCOUNT: "pass"}
    assert "us-gov-west-1" in findings[0].observed
    assert findings[0].detail["region_assessed"] == "us-gov-west-1"


def test_ebs_default_encryption_off_fails() -> None:
    findings = aws.evaluate_ebs_encryption_by_default(
        [{"EbsEncryptionByDefault": False, "Region": "us-gov-west-1"}],
        account_id=ACCOUNT,
    )
    assert _verdicts(findings) == {ACCOUNT: "fail"}


def test_an_unanswered_ebs_call_is_not_a_failure() -> None:
    """AWS's default being "off" is not licence to report an unverified account.

    An empty response means the call did not answer. Rendering that as ``fail``
    would put remediation work on an account nobody looked at, and the honest
    answer is that it is unknown.
    """
    for rows in ([], [{}]):
        findings = aws.evaluate_ebs_encryption_by_default(rows, account_id=ACCOUNT)
        assert _verdicts(findings) == {ACCOUNT: "manual_review_required"}


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def test_the_new_checks_are_registered_and_dispatchable() -> None:
    """A check absent from the registry or the evaluator map never runs.

    Both maps are asserted because a check can be registered with no evaluator
    (it then produces nothing, indistinguishable from passing) or given an
    evaluator and never registered (it never runs at all).
    """
    new = (
        aws.CLOUDTRAIL_LOG_FILE_VALIDATION,
        aws.S3_PUBLIC_ACCESS_BLOCKED,
        aws.S3_DEFAULT_ENCRYPTION,
        aws.EBS_ENCRYPTION_BY_DEFAULT,
    )
    registered = {c.key for c in CHECK_REGISTRY["aws_govcloud"]}
    for check in new:
        assert check.key in registered, check.key
        assert check.key in aws.EVALUATORS, check.key
        assert check.key in aws.ENDPOINTS, check.key
        assert check.control_ids, check.key


def test_the_log_file_validation_check_adds_no_new_aws_permission() -> None:
    """It reads the trails another check already fetched.

    Worth asserting rather than trusting the comment: if this ever acquires its
    own source token, an operator has to grant something new for a check that
    previously needed nothing, and that belongs in the runbook rather than in a
    surprise 403.
    """
    assert (
        aws.ENDPOINTS[aws.CLOUDTRAIL_LOG_FILE_VALIDATION.key]
        == aws.ENDPOINTS[aws.CLOUDTRAIL_MULTI_REGION.key]
    )
    assert set(aws.CLOUDTRAIL_LOG_FILE_VALIDATION.required_permissions) <= set(
        aws.CLOUDTRAIL_MULTI_REGION.required_permissions
    )
