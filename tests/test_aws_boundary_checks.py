"""The eight AWS checks ported from m365-docs-hub's boundary collector.

Each is judged here on recorded response shapes, with the cases the source got
wrong pinned: an empty fleet is not a pass, a stopped/suspended service is a
failure, an unreadable resource is for review, and the buckets judged are the
ones CloudTrail writes to.
"""

from __future__ import annotations

from typing import Any

import pytest

from ccf.connectors.aws import AwsGovCloudConnector
from ccf.posture.providers import aws as a

ACCT = "123456789012"


def _verdicts(findings: list[Any]) -> list[str]:
    return [f.verdict for f in findings]


# ── AWS Config ──────────────────────────────────────────────────────────────


def test_config_recorder() -> None:
    every = {"name": "default", "recordingGroup": {"allSupported": True},
             "recording": True, "lastStatus": "SUCCESS"}
    assert _verdicts(a.evaluate_config_recorder([], account_id=ACCT)) == ["fail"]
    assert _verdicts(a.evaluate_config_recorder([every], account_id=ACCT)) == ["pass"]
    stopped = {**every, "recording": False}
    f = a.evaluate_config_recorder([stopped], account_id=ACCT)
    assert f[0].verdict == "fail" and "not recording" in f[0].observed
    partial = {**every, "recordingGroup": {"allSupported": False, "resourceTypes": ["x"]}}
    f = a.evaluate_config_recorder([partial], account_id=ACCT)
    assert f[0].verdict == "fail" and "selected resource types" in f[0].observed
    assert _verdicts(a.evaluate_config_recorder(
        [{**every, "lastStatus": "FAILURE"}], account_id=ACCT)) == ["fail"]
    unread = {"name": "default", "recordingGroup": {"allSupported": True}}
    assert _verdicts(a.evaluate_config_recorder([unread], account_id=ACCT)) == [
        "manual_review_required"]


# ── GuardDuty ───────────────────────────────────────────────────────────────


def test_guardduty() -> None:
    assert _verdicts(a.evaluate_guardduty_enabled([], account_id=ACCT)) == ["fail"]
    assert _verdicts(a.evaluate_guardduty_enabled(
        [{"DetectorId": "d", "Status": "ENABLED"}], account_id=ACCT)) == ["pass"]
    assert _verdicts(a.evaluate_guardduty_enabled(
        [{"DetectorId": "d", "Status": "DISABLED"}], account_id=ACCT)) == ["fail"]
    assert _verdicts(a.evaluate_guardduty_enabled(
        [{"DetectorId": "d"}], account_id=ACCT)) == ["manual_review_required"]


# ── Access Analyzer ─────────────────────────────────────────────────────────


def test_access_analyzer() -> None:
    ok = {"name": "x", "type": "ACCOUNT", "status": "ACTIVE"}
    assert _verdicts(a.evaluate_access_analyzer([ok], account_id=ACCT)) == ["pass"]
    unused_only = {"name": "u", "type": "ACCOUNT_UNUSED_ACCESS", "status": "ACTIVE"}
    assert _verdicts(a.evaluate_access_analyzer([unused_only], account_id=ACCT)) == ["fail"]
    assert _verdicts(a.evaluate_access_analyzer(
        [{**ok, "status": "CREATING"}], account_id=ACCT)) == ["manual_review_required"]
    assert _verdicts(a.evaluate_access_analyzer([], account_id=ACCT)) == ["fail"]


# ── KMS rotation ────────────────────────────────────────────────────────────


def test_kms_rotation() -> None:
    base = {"KeyArn": "k1", "KeyState": "Enabled", "KeySpec": "SYMMETRIC_DEFAULT",
            "Origin": "AWS_KMS"}
    assert _verdicts(a.evaluate_kms_key_rotation([], account_id=ACCT)) == ["not_applicable"]
    rows = [
        {**base, "KeyRotationEnabled": True},
        {**base, "KeyArn": "k2", "KeyRotationEnabled": False},
        {**base, "KeyArn": "k3", "KeyState": "Disabled"},
        {**base, "KeyArn": "k4", "KeySpec": "RSA_2048"},
        {**base, "KeyArn": "k5", "Origin": "EXTERNAL"},
        {"KeyArn": "k6", "Unreadable": "AccessDeniedException"},
        {**base, "KeyArn": "k7"},
    ]
    assert _verdicts(a.evaluate_kms_key_rotation(rows, account_id=ACCT)) == [
        "pass", "fail", "not_applicable", "not_applicable", "not_applicable",
        "manual_review_required", "manual_review_required",
    ]


# ── Load balancer listeners ─────────────────────────────────────────────────

_TO_HTTPS = [{"Type": "redirect", "RedirectConfig": {"Protocol": "HTTPS"}}]


def test_elb_listeners_tls() -> None:
    assert _verdicts(a.evaluate_elb_listeners_tls([], account_id=ACCT)) == ["not_applicable"]
    rows = [
        {"ListenerArn": "l1", "Protocol": "HTTPS", "SslPolicy": "p"},
        {"ListenerArn": "l2", "Protocol": "HTTP", "DefaultActions": _TO_HTTPS, "Rules": []},
        {"ListenerArn": "l3", "Protocol": "HTTP", "DefaultActions": _TO_HTTPS,
         "Rules": [{"Actions": [{"Type": "forward"}]}]},
        {"ListenerArn": "l4", "Protocol": "HTTP", "DefaultActions": [{"Type": "forward"}],
         "Rules": []},
        {"ListenerArn": "l5", "Protocol": "TCP"},
        {"ListenerArn": "l6", "Protocol": "HTTP", "DefaultActions": _TO_HTTPS},
        {"ListenerArn": "l7", "Protocol": "GENEVE"},
    ]
    findings = a.evaluate_elb_listeners_tls(rows, account_id=ACCT)
    assert _verdicts(findings) == [
        "pass", "pass", "fail", "fail", "manual_review_required",
        "manual_review_required", "not_applicable",
    ]
    assert "payload" in findings[4].observed


# ── WAF ─────────────────────────────────────────────────────────────────────


def test_waf_public_alb() -> None:
    assert _verdicts(a.evaluate_waf_public_alb([], account_id=ACCT)) == ["not_applicable"]
    rows = [{"LoadBalancerArn": "a", "WebACL": "acl"}, {"LoadBalancerArn": "b"},
            {"LoadBalancerArn": "c", "Unreadable": "AccessDeniedException"}]
    assert _verdicts(a.evaluate_waf_public_alb(rows, account_id=ACCT)) == [
        "pass", "fail", "manual_review_required"]


# ── CloudTrail bucket Object Lock ───────────────────────────────────────────


def test_trail_bucket_object_lock() -> None:
    assert _verdicts(a.evaluate_trail_bucket_object_lock([], account_id=ACCT)) == [
        "not_applicable"]
    locked = {"ObjectLockEnabled": "Enabled",
              "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Years": 1}}}
    rows = [
        {"Bucket": "b1", "ObjectLockConfiguration": locked},
        {"Bucket": "b2", "ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}},
        {"Bucket": "b3", "ObjectLockConfiguration": None},
        {"Bucket": "b4", "Unreadable": "AccessDenied"},
    ]
    assert _verdicts(a.evaluate_trail_bucket_object_lock(rows, account_id=ACCT)) == [
        "pass", "fail", "fail", "manual_review_required"]


# ── RDS encryption ──────────────────────────────────────────────────────────


def test_rds_storage_encrypted() -> None:
    assert _verdicts(a.evaluate_rds_storage_encrypted([], account_id=ACCT)) == [
        "not_applicable"]
    rows = [
        {"DBInstanceIdentifier": "a", "DBInstanceStatus": "available", "StorageEncrypted": True},
        {"DBInstanceIdentifier": "b", "DBInstanceStatus": "available", "StorageEncrypted": False},
        {"DBInstanceIdentifier": "c", "DBInstanceStatus": "available"},
        {"DBInstanceIdentifier": "d", "DBInstanceStatus": "creating"},
    ]
    assert _verdicts(a.evaluate_rds_storage_encrypted(rows, account_id=ACCT)) == [
        "pass", "fail", "manual_review_required", "not_applicable"]


# ── readers, on a scripted session ──────────────────────────────────────────


class _ClientError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class _Script:
    """A session whose clients answer from a script: {(service, op): fn(**kw)}."""

    def __init__(self, script: dict[tuple[str, str], Any]) -> None:
        self.script = script

    def client(self, service: str, region_name: str | None = None) -> Any:
        script = self.script

        class _Pager:
            def __init__(self, op: str) -> None:
                self.op = op

            def paginate(self, **kw: Any) -> list[dict[str, Any]]:
                return script[(service, self.op)](**kw)

        class _C:
            def get_paginator(self, op: str) -> _Pager:
                return _Pager(op)

            def __getattr__(self, op: str) -> Any:
                return script[(service, op)]

        return _C()


def _conn(monkeypatch: pytest.MonkeyPatch, script: dict[tuple[str, str], Any]) -> Any:
    session = _Script(script)
    monkeypatch.setattr(AwsGovCloudConnector, "_session", lambda self: session)
    return AwsGovCloudConnector({"access_key_id": "AKIA", "secret_access_key": "x"})


def _raise(code: str) -> Any:
    def _f(**_kw: Any) -> Any:
        raise _ClientError(code)
    return _f


def test_kms_reader_skips_aws_managed_and_isolates_denials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keys = [{"KeyId": "aws-key"}, {"KeyId": "mine"}, {"KeyId": "locked", "KeyArn": "arn:locked"}]
    metas = {
        "aws-key": {"KeyManager": "AWS"},
        "mine": {"KeyManager": "CUSTOMER", "KeyArn": "arn:mine", "KeyState": "Enabled",
                 "KeySpec": "SYMMETRIC_DEFAULT", "Origin": "AWS_KMS"},
    }

    def describe(KeyId: str) -> dict[str, Any]:  # noqa: N803 -- boto3's keyword
        if KeyId == "locked":
            raise _ClientError("AccessDeniedException")
        return {"KeyMetadata": metas[KeyId]}

    conn = _conn(monkeypatch, {
        ("kms", "list_keys"): lambda **_: [{"Keys": keys[:2]}, {"Keys": keys[2:]}],
        ("kms", "describe_key"): describe,
        ("kms", "get_key_rotation_status"): lambda **_: {"KeyRotationEnabled": True},
    })
    rows = conn._read_kms_keys()
    assert [r.get("KeyArn") for r in rows] == ["arn:mine", "arn:locked"]
    assert rows[0]["KeyRotationEnabled"] is True
    assert rows[1]["Unreadable"] == "AccessDeniedException"


def test_object_lock_reader_judges_the_trail_buckets(monkeypatch: pytest.MonkeyPatch) -> None:
    def lock(Bucket: str) -> dict[str, Any]:  # noqa: N803 -- boto3's keyword
        if Bucket == "plain":
            raise _ClientError("ObjectLockConfigurationNotFoundError")
        if Bucket == "archive":
            raise _ClientError("AccessDenied")
        return {"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}}

    conn = _conn(monkeypatch, {
        ("cloudtrail", "describe_trails"): lambda **_: {"trailList": [
            {"S3BucketName": "plain"}, {"S3BucketName": "archive"},
            {"S3BucketName": "locked"}, {"S3BucketName": "plain"}, {}]},
        ("s3", "get_object_lock_configuration"): lock,
    })
    rows = {r["Bucket"]: r for r in conn._read_trail_bucket_locks()}
    assert set(rows) == {"plain", "archive", "locked"}
    assert rows["plain"]["ObjectLockConfiguration"] is None
    assert rows["archive"]["Unreadable"] == "AccessDenied"


def test_waf_reader_judges_only_internet_facing_albs(monkeypatch: pytest.MonkeyPatch) -> None:
    lbs = [
        {"LoadBalancerArn": "pub", "Type": "application", "Scheme": "internet-facing"},
        {"LoadBalancerArn": "int", "Type": "application", "Scheme": "internal"},
        {"LoadBalancerArn": "nlb", "Type": "network", "Scheme": "internet-facing"},
    ]
    conn = _conn(monkeypatch, {
        ("elbv2", "describe_load_balancers"): lambda **_: [{"LoadBalancers": lbs}],
        ("wafv2", "get_web_acl_for_resource"): lambda **_: {"WebACL": {"Name": "acl"}},
    })
    rows = conn._read_public_alb_waf()
    assert [r["LoadBalancerArn"] for r in rows] == ["pub"] and rows[0]["WebACL"] == "acl"


def test_guardduty_reader_reads_every_detector(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _conn(monkeypatch, {
        ("guardduty", "list_detectors"): lambda **_: [{"DetectorIds": ["a"]},
                                                      {"DetectorIds": ["b"]}],
        ("guardduty", "get_detector"): lambda DetectorId: {  # noqa: N803
            "Status": "DISABLED" if DetectorId == "a" else "ENABLED"},
    })
    rows = conn._read_guardduty()
    assert [r["Status"] for r in rows] == ["DISABLED", "ENABLED"]
    assert _verdicts(a.evaluate_guardduty_enabled(rows, account_id=ACCT)) == ["pass"]


def test_config_reader_joins_status_by_name(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _conn(monkeypatch, {
        ("config", "describe_configuration_recorders"): lambda **_: {
            "ConfigurationRecorders": [{"name": "default",
                                        "recordingGroup": {"allSupported": True}}]},
        ("config", "describe_configuration_recorder_status"): lambda **_: {
            "ConfigurationRecordersStatus": [{"name": "default", "recording": False}]},
    })
    rows = conn._read_config_recorders()
    assert rows[0]["recording"] is False
    assert _verdicts(a.evaluate_config_recorder(rows, account_id=ACCT)) == ["fail"]


def test_elb_reader_reads_rules_for_http_listeners(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _conn(monkeypatch, {
        ("elbv2", "describe_load_balancers"): lambda **_: [
            {"LoadBalancers": [{"LoadBalancerArn": "lb"}]}],
        ("elbv2", "describe_listeners"): lambda **_: [{"Listeners": [
            {"ListenerArn": "h", "Protocol": "HTTP", "DefaultActions": _TO_HTTPS},
            {"ListenerArn": "s", "Protocol": "HTTPS"}]}],
        ("elbv2", "describe_rules"): lambda **_: [{"Rules": [
            {"IsDefault": True, "Actions": _TO_HTTPS},
            {"IsDefault": False, "Actions": [{"Type": "forward"}]}]}],
    })
    rows = conn._read_elb_listeners()
    assert "Rules" in rows[0] and "Rules" not in rows[1]
    assert _verdicts(a.evaluate_elb_listeners_tls(rows, account_id=ACCT)) == ["fail", "pass"]
