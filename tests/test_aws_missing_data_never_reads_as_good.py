"""No AWS check turns data it did not get into a good answer.

m365-docs-hub's AWS collectors returned constants -- S3 encryption 0, log
retention 90, key rotation false -- and passed on vacuity (no VPCs counted as
100% flow logs). Concord splits a check into a reader (calls AWS) and an
evaluator (judges rows), so a constant can enter in two places, and this file
guards both, for every check in ``CHECKS``:

* a reader that makes no AWS call can only return a constant;
* an evaluator that reads a missing field as a good value passes, or excuses
  as ``not_applicable``, a resource it never observed.

The second found four: a security group with no ``IpPermissions`` passed, a
KMS key with no ``KeyState`` and an access key with no ``Status`` were
``not_applicable``, and SRG scope rows with no resource type produced no
finding at all.
"""

from __future__ import annotations

import inspect
from datetime import UTC, datetime
from typing import Any

import pytest

from ccf.connectors.aws import AwsGovCloudConnector
from ccf.posture.providers import aws as aws_checks
from tests.test_aws_permissions_are_declared import _readers_by_token, _Recorder

#: What a row with every field missing may produce: a finding someone acts on.
_UNOBSERVED_OK = {"fail", "manual_review_required"}


def _judge(check: Any, rows: list[dict[str, Any]]) -> list[Any]:
    """Call the evaluator the way ``AwsGovCloudConnector._evaluate`` does."""
    evaluator = aws_checks.EVALUATORS[check.key]
    kwargs: dict[str, Any] = {}
    if check.key in aws_checks.ACCOUNT_SCOPED:
        kwargs["account_id"] = "123456789012"
    if check.key == aws_checks.ACCESS_KEY_ROTATION.key:
        kwargs["now"] = datetime(2026, 10, 20, tzinfo=UTC)
    if "dod_impact_level" in inspect.signature(evaluator).parameters:
        kwargs["dod_impact_level"] = "IL5"
    return list(evaluator(rows, **kwargs))


@pytest.mark.parametrize("check", aws_checks.CHECKS, ids=lambda c: c.key)
def test_a_row_with_nothing_in_it_is_never_good(check: Any) -> None:
    findings = _judge(check, [{}])
    assert findings, f"{check.key} dropped a row it could not read, without a finding"
    verdicts = {f.verdict for f in findings}
    assert verdicts <= _UNOBSERVED_OK, (
        f"{check.key} judged a row with no fields as {sorted(verdicts)}"
    )


@pytest.mark.parametrize("check", aws_checks.CHECKS, ids=lambda c: c.key)
def test_an_empty_answer_never_passes(check: Any) -> None:
    verdicts = {f.verdict for f in _judge(check, [])}
    assert "pass" not in verdicts, f"{check.key} passed on an empty answer"


@pytest.mark.parametrize("check", aws_checks.CHECKS, ids=lambda c: c.key)
def test_each_reader_asks_aws_and_an_empty_aws_never_passes(
    check: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    rec = _Recorder()
    monkeypatch.setattr(AwsGovCloudConnector, "_session", lambda self: rec)
    rows = _readers_by_token()[aws_checks.ENDPOINTS[check.key]]()
    assert rec.calls, f"{check.key}'s reader made no AWS call; its rows are a constant"
    verdicts = {f.verdict for f in _judge(check, list(rows))}
    assert "pass" not in verdicts, (
        f"{check.key} passed when every AWS call it made answered nothing"
    )
