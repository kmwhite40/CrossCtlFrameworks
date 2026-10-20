"""Every AWS call a check's reader makes is one its ``required_permissions`` names.

``required_permissions`` is a claim with two readers: the manual-review finding
that names what to grant when AWS says AccessDenied, and the least-privilege
policy the connector page tells a customer to attach to Concord's role. A call
missing from it is a permission the customer never grants and an operator is
never told about -- ``ssm:DescribeInstanceInformation`` was such a call. So
this runs each reader against a session that records every call and checks
the IAM action of each against the declaration, rather than trusting the list.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from ccf.connectors import aws_identity
from ccf.connectors.aws import AwsGovCloudConnector
from ccf.posture.providers import aws as aws_checks

#: boto3 operation -> IAM action where the names differ.
_IAM_ACTION = {
    ("s3", "list_buckets"): "s3:ListAllMyBuckets",
    ("s3", "get_bucket_encryption"): "s3:GetEncryptionConfiguration",
    ("s3", "get_public_access_block"): "s3:GetBucketPublicAccessBlock",
    ("rds", "describe_db_instances"): "rds:DescribeDBInstances",
    ("wafv2", "get_web_acl_for_resource"): "wafv2:GetWebACLForResource",
    ("s3", "get_object_lock_configuration"): "s3:GetBucketObjectLockConfiguration",
    ("elbv2", None): "elasticloadbalancing",
    ("accessanalyzer", None): "access-analyzer",
}
#: Calls that need no IAM permission.
_FREE = {("sts", "get_caller_identity")}


def _action(service: str, op: str) -> str:
    if (service, op) in _IAM_ACTION:
        return _IAM_ACTION[(service, op)]
    prefix = _IAM_ACTION.get((service, None), service)
    return f"{prefix}:" + "".join(part.capitalize() for part in op.split("_"))


class _Recorder:
    """A boto3 session whose every client call returns an empty answer."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def client(self, service: str, region_name: str | None = None) -> Any:
        rec = self

        class _Paginator:
            def __init__(self, op: str) -> None:
                self.op = op

            def paginate(self, **_kw: Any) -> list[dict[str, Any]]:
                rec.calls.append((service, self.op))
                return [{}]

        class _Client:
            def get_paginator(self, op: str) -> _Paginator:
                return _Paginator(op)

            def __getattr__(self, op: str) -> Any:
                def _call(**_kw: Any) -> dict[str, Any]:
                    rec.calls.append((service, op))
                    return {"Account": "123456789012"} if op == "get_caller_identity" else {}

                return _call

        return _Client()


def _readers_by_token() -> dict[str, Any]:
    conn = AwsGovCloudConnector({"access_key_id": "AKIA", "secret_access_key": "x",
                                 "account_id": "123456789012"})
    return conn._readers()


@pytest.mark.parametrize("check", aws_checks.CHECKS, ids=lambda c: c.key)
def test_each_reader_call_is_a_declared_permission(
    check: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    rec = _Recorder()
    monkeypatch.setattr(AwsGovCloudConnector, "_session", lambda self: rec)
    reader = _readers_by_token()[aws_checks.ENDPOINTS[check.key]]
    reader()
    made = {_action(s, op) for s, op in rec.calls if (s, op) not in _FREE}
    undeclared = made - set(check.required_permissions)
    assert not undeclared, (
        f"{check.key} reads AWS with {sorted(undeclared)}, which its "
        "required_permissions does not name"
    )


def test_the_action_names_are_iam_shaped() -> None:
    for check in aws_checks.CHECKS:
        for perm in check.required_permissions:
            assert re.fullmatch(r"[a-z0-9-]+:[A-Z][A-Za-z0-9]+", perm), (check.key, perm)


def test_the_permissions_policy_covers_every_check_and_the_connector() -> None:
    actions = aws_identity.required_actions(
        p for c in aws_checks.CHECKS for p in c.required_permissions
    )
    for c in aws_checks.CHECKS:
        assert set(c.required_permissions) <= set(actions), c.key
    assert set(aws_identity.CONNECTOR_PERMISSIONS) <= set(actions)
