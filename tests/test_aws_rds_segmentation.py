"""A database reachable from the internet is a segmentation failure.

``SC.L2-3.13.5`` -- "Implement subnetworks for publicly accessible system
components that are physically or logically separated from internal networks" --
carries five SPRS points and had no check. A publicly accessible RDS instance is
the plainest machine-readable violation of it: an internal component sitting on
the public network rather than behind the subnetwork that should separate it.

``PubliclyAccessible`` is the authoritative field. It controls whether the
instance's endpoint resolves to a public address, and AWS exposes it directly, so
this needs no inference about route tables or subnet tiers -- which is why this is
the check worth having rather than one that tries to classify subnets as "public"
or "private" from their routing and gets it wrong on a NAT gateway.

Judged per instance, so a finding names the database to go and fix.
"""

from __future__ import annotations

from typing import Any

from ccf.posture.providers import aws

_ACCOUNT = "123456789012"


def _db(
    identifier: str,
    *,
    public: bool | None = False,
    status: str = "available",
    engine: str = "postgres",
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "DBInstanceIdentifier": identifier,
        "DBInstanceStatus": status,
        "Engine": engine,
    }
    if public is not None:
        row["PubliclyAccessible"] = public
    return row


def test_a_private_instance_passes() -> None:
    findings = aws.evaluate_rds_not_publicly_accessible(
        [_db("app-db", public=False)], account_id=_ACCOUNT
    )
    assert [f.verdict for f in findings] == ["pass"]
    assert findings[0].resource_id == "app-db"
    assert findings[0].resource_type == "aws_db_instance"


def test_a_publicly_accessible_instance_fails() -> None:
    findings = aws.evaluate_rds_not_publicly_accessible(
        [_db("exposed-db", public=True)], account_id=_ACCOUNT
    )
    assert [f.verdict for f in findings] == ["fail"]
    assert "public" in findings[0].observed.lower()
    assert findings[0].detail["engine"] == "postgres"


def test_each_instance_is_judged_on_its_own() -> None:
    """One exposed database must not condemn the others, nor they excuse it."""
    findings = aws.evaluate_rds_not_publicly_accessible(
        [_db("ok-1", public=False), _db("bad", public=True), _db("ok-2", public=False)],
        account_id=_ACCOUNT,
    )
    assert {f.resource_id: f.verdict for f in findings} == {
        "ok-1": "pass",
        "bad": "fail",
        "ok-2": "pass",
    }


def test_an_instance_that_does_not_report_the_field_is_unassessable() -> None:
    """Absent is not false.

    Reading a missing ``PubliclyAccessible`` as private would report an
    unverified database as compliant, which is the overclaim direction.
    """
    findings = aws.evaluate_rds_not_publicly_accessible(
        [_db("mystery", public=None)], account_id=_ACCOUNT
    )
    assert [f.verdict for f in findings] == ["manual_review_required"]


def test_an_instance_still_being_created_is_not_yet_a_finding() -> None:
    """A database mid-creation has not settled on its final configuration.

    Failing it would make every deployment briefly non-compliant, which teaches
    an operator to ignore the check.
    """
    findings = aws.evaluate_rds_not_publicly_accessible(
        [_db("coming-up", public=True, status="creating")], account_id=_ACCOUNT
    )
    assert [f.verdict for f in findings] == ["not_applicable"]


def test_no_instances_is_not_applicable_rather_than_a_pass() -> None:
    """An account with no databases has nothing to segregate.

    Distinct from the security-group check, where an empty answer means the call
    did not answer: an account genuinely may run no RDS at all, and `pass` would
    assert a separation that was never observed.
    """
    findings = aws.evaluate_rds_not_publicly_accessible([], account_id=_ACCOUNT)
    assert [f.verdict for f in findings] == ["not_applicable"]
    assert findings[0].resource_id == _ACCOUNT


def test_the_check_is_registered_with_its_permission() -> None:
    check = aws.RDS_NOT_PUBLICLY_ACCESSIBLE
    assert check.provider == "aws_govcloud"
    assert "rds:DescribeDBInstances" in check.required_permissions
    assert check.control_ids
    assert check.expected
