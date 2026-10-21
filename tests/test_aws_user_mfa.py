"""IAM user MFA, judged per user from the IAM credential report.

The collector report from m365-docs-hub asked for this: its MFA figure was
approximate, and Concord's only AWS MFA check covered the root user.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from ccf.connectors.aws import AwsGovCloudConnector
from ccf.posture.providers import aws as a

ACCOUNT = "123456789012"
HEADER = "user,arn,password_enabled,mfa_active,access_key_1_active\n"


def _row(user: str, password: str, mfa: str) -> dict[str, Any]:
    return {"user": user, "arn": f"arn:aws-us-gov:iam::{ACCOUNT}:user/{user}",
            "password_enabled": password, "mfa_active": mfa}


def _verdicts(rows: list[dict[str, Any]]) -> dict[str, str]:
    return {f.resource_id: f.verdict for f in a.evaluate_user_mfa(rows, account_id=ACCOUNT)}


def test_each_console_user_is_judged_on_mfa() -> None:
    root = {"user": "<root_account>", "arn": "root", "password_enabled": "not_supported",
            "mfa_active": "false"}
    got = _verdicts([
        root,
        _row("alice", "true", "true"),
        _row("bob", "true", "false"),
        _row("ci-bot", "false", "false"),
        _row("carol", "true", "N/A"),
        {"user": "dave", "arn": "dave-arn"},
    ])
    assert "root" not in got  # ROOT_MFA_ENABLED's question, not judged twice
    assert got[f"arn:aws-us-gov:iam::{ACCOUNT}:user/alice"] == "pass"
    assert got[f"arn:aws-us-gov:iam::{ACCOUNT}:user/bob"] == "fail"
    assert got[f"arn:aws-us-gov:iam::{ACCOUNT}:user/ci-bot"] == "not_applicable"
    assert got[f"arn:aws-us-gov:iam::{ACCOUNT}:user/carol"] == "manual_review_required"
    assert got["dave-arn"] == "manual_review_required"


def test_only_root_is_no_users_and_nothing_is_unread() -> None:
    root = {"user": "<root_account>", "password_enabled": "not_supported"}
    assert _verdicts([root]) == {ACCOUNT: "not_applicable"}
    # Every report has the root row, so an empty one was not read.
    assert _verdicts([]) == {ACCOUNT: "manual_review_required"}


class _AwsError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class _Iam:
    def __init__(self, answers: list[Any]) -> None:
        self.answers = answers
        self.generated = 0

    def generate_credential_report(self) -> dict[str, Any]:
        self.generated += 1
        return {"State": "STARTED"}

    def get_credential_report(self) -> dict[str, Any]:
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return dict(answer)


def _connector(monkeypatch: pytest.MonkeyPatch, iam: _Iam) -> tuple[Any, list[float]]:
    slept: list[float] = []
    monkeypatch.setattr(AwsGovCloudConnector, "_iam", lambda self: iam)
    monkeypatch.setattr(AwsGovCloudConnector, "_sleep", lambda self, s: slept.append(s))
    conn = AwsGovCloudConnector({"access_key_id": "AKIA", "secret_access_key": "x",
                                 "account_id": ACCOUNT})
    return conn, slept


def test_the_reader_waits_for_a_report_in_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    generated = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)
    iam = _Iam([
        _AwsError("ReportInProgress"),
        _AwsError("ReportInProgress"),
        {"Content": (HEADER + "alice,arn-a,true,false,true\n").encode(),
         "GeneratedTime": generated},
    ])
    conn, slept = _connector(monkeypatch, iam)
    rows = conn._read_credential_report()
    assert rows == [{"user": "alice", "arn": "arn-a", "password_enabled": "true",
                     "mfa_active": "false", "access_key_1_active": "true",
                     "GeneratedTime": generated.isoformat()}]
    assert len(slept) == 2
    assert iam.generated == 3  # a report that expired or vanished is asked for again


def test_a_report_that_never_arrives_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    polls = AwsGovCloudConnector.CREDENTIAL_REPORT_POLLS
    iam = _Iam([_AwsError("ReportInProgress") for _ in range(polls)])
    conn, slept = _connector(monkeypatch, iam)
    with pytest.raises(_AwsError):
        conn._read_credential_report()
    assert len(slept) == polls - 1


def test_a_denial_is_not_waited_on(monkeypatch: pytest.MonkeyPatch) -> None:
    iam = _Iam([_AwsError("AccessDenied")])
    conn, slept = _connector(monkeypatch, iam)
    with pytest.raises(_AwsError):
        conn._read_credential_report()
    assert slept == []


def test_the_check_is_registered_where_a_scan_finds_it() -> None:
    assert a.USER_MFA_ENABLED in a.CHECKS
    token = a.ENDPOINTS[a.USER_MFA_ENABLED.key]
    conn = AwsGovCloudConnector({"access_key_id": "AKIA", "secret_access_key": "x",
                                 "account_id": ACCOUNT})
    assert conn._readers()[token] == conn._read_credential_report
    assert a.USER_MFA_ENABLED.key in a.ACCOUNT_SCOPED
