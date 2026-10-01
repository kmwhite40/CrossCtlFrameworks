"""Reading Security Hub: pagination, the standard's own state, and refusals.

The transport half of :mod:`ccf.posture.attested`. Everything here drives
``AwsGovCloudConnector.securityhub_attestations`` against a stubbed boto3
session -- the same seam every other AWS connector test uses -- because no
organization in this deployment has an AWS credential bound and this code has
never run against a live account.

Four failure modes this pins, each of which a working implementation of the
same idea documents itself getting wrong:

**One page.** The reference implementation calls ``GetFindings`` once with
``MaxResults=100`` and scores the account on whatever came back. An account with
more than 100 findings is then scored on a prefix of its own posture, and the
missing findings read as controls nobody evaluated.

**The standard's state.** ``GetEnabledStandards`` reports a subscription's
``StandardsStatus``: ``PENDING``, ``READY``, ``FAILED``, ``DELETING`` or
``INCOMPLETE``. Only ``READY`` means the control results are current. Treating
``PENDING`` as usable reports a half-populated standard as an assessment.

**A refusal that reads as a clean account.** Security Hub not enabled, or an
IAM policy missing ``securityhub:GetFindings``, raises. Returning no
attestations with no reason is indistinguishable from an account where every
control passed.

**The wrong standard.** The findings store holds CIS and PCI findings too. A
fetch that does not filter to the NIST standard pulls them and then discards
them in the pure layer, which costs a page budget that should have gone to
800-53 findings.
"""

from __future__ import annotations

from typing import Any

import pytest

from ccf.config import get_settings
from ccf.connectors.aws import AwsGovCloudConnector
from ccf.posture.attested import NIST_80053_R5_STANDARD_ID, REQUIREMENT_PREFIX

GOV_ARN = (
    f"arn:aws-us-gov:securityhub:us-gov-west-1::{NIST_80053_R5_STANDARD_ID}"
)
COMMERCIAL_ARN = f"arn:aws:securityhub:us-east-1::{NIST_80053_R5_STANDARD_ID}"
CIS_ARN = "arn:aws-us-gov:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"


def _finding(control_id: str, status: str, resource: str = "r1") -> dict[str, Any]:
    return {
        "Id": f"{control_id}/{resource}",
        "Title": f"{control_id} title",
        "Compliance": {
            "Status": status,
            "SecurityControlId": control_id,
            "RelatedRequirements": [f"{REQUIREMENT_PREFIX} AC-3"],
            "AssociatedStandards": [{"StandardsId": NIST_80053_R5_STANDARD_ID}],
        },
    }


class _StubSecurityHub:
    """A boto3 ``securityhub`` client double that records how it was called."""

    def __init__(
        self,
        *,
        subscriptions: list[dict[str, Any]] | None = None,
        pages: list[list[dict[str, Any]]] | None = None,
        standards_error: Exception | None = None,
        findings_error: Exception | None = None,
    ) -> None:
        self._subscriptions = (
            subscriptions
            if subscriptions is not None
            else [{"StandardsArn": GOV_ARN, "StandardsStatus": "READY"}]
        )
        self._pages = pages if pages is not None else [[]]
        self._standards_error = standards_error
        self._findings_error = findings_error
        self.findings_calls: list[dict[str, Any]] = []
        self.standards_calls = 0

    def get_enabled_standards(self, **kwargs: Any) -> dict[str, Any]:
        self.standards_calls += 1
        if self._standards_error:
            raise self._standards_error
        return {"StandardsSubscriptions": self._subscriptions}

    def get_findings(self, **kwargs: Any) -> dict[str, Any]:
        self.findings_calls.append(kwargs)
        if self._findings_error:
            raise self._findings_error
        index = len(self.findings_calls) - 1
        if index >= len(self._pages):
            return {"Findings": []}
        page = self._pages[index]
        out: dict[str, Any] = {"Findings": page}
        if index + 1 < len(self._pages):
            out["NextToken"] = f"token-{index + 1}"
        return out


class _StubSession:
    def __init__(self, shub: _StubSecurityHub) -> None:
        self._shub = shub

    def client(self, service: str, **kwargs: Any) -> Any:
        if service == "securityhub":
            return self._shub
        if service == "sts":
            return _StubSts()
        raise AssertionError(f"unexpected client: {service}")


class _StubSts:
    def get_caller_identity(self) -> dict[str, Any]:
        return {"Account": "123456789012"}


def _connector(
    shub: _StubSecurityHub, monkeypatch: pytest.MonkeyPatch
) -> AwsGovCloudConnector:
    """A *configured* AWS connector whose securityhub client is the stub.

    The assertion at the end is the point. The first version of this helper left
    ``CCF_AWS_CAPTURE_ENABLED`` unset and boto3 absent, so every connector it
    built was unconfigured and ``securityhub_attestations`` returned the "not
    configured" refusal before touching the stub -- twenty tests asserting about
    a code path none of them reached. A harness that cannot produce the state it
    is testing has to say so here, not in the first assertion that happens to
    disagree.
    """
    monkeypatch.setattr(AwsGovCloudConnector, "_boto3_available", lambda self: True)
    monkeypatch.setenv("CCF_AWS_CAPTURE_ENABLED", "true")
    get_settings.cache_clear()
    conn = AwsGovCloudConnector(
        credential={
            "access_key_id": "AKIAEXAMPLE",
            "secret_access_key": "shh",
            "region": "us-gov-west-1",
            "account_id": "123456789012",
        }
    )
    monkeypatch.setattr(conn, "_session", lambda: _StubSession(shub))
    assert conn.is_configured() is True, "the harness did not produce a usable connector"
    return conn


def _client_error(code: str) -> Exception:
    err = RuntimeError(code)
    err.response = {"Error": {"Code": code}}  # type: ignore[attr-defined]
    return err


# --------------------------------------------------------------------------
# The standard has to be enabled, and ready
# --------------------------------------------------------------------------


async def test_a_ready_standard_is_read(monkeypatch: pytest.MonkeyPatch) -> None:
    shub = _StubSecurityHub(pages=[[_finding("S3.8", "PASSED")]])
    out = await _connector(shub, monkeypatch).securityhub_attestations()
    assert out["available"] is True
    assert out["reason"] is None
    assert [c.security_control_id for c in out["controls"]] == ["S3.8"]


async def test_the_standard_matches_in_either_partition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GovCloud ARNs are ``arn:aws-us-gov:``, commercial ``arn:aws:``.

    Matched on the standard suffix so the connector does not have to derive the
    partition -- the same reason it lets boto3 resolve endpoints from the region.
    """
    for arn in (GOV_ARN, COMMERCIAL_ARN):
        shub = _StubSecurityHub(
            subscriptions=[{"StandardsArn": arn, "StandardsStatus": "READY"}],
            pages=[[_finding("S3.8", "PASSED")]],
        )
        out = await _connector(shub, monkeypatch).securityhub_attestations()
        assert out["available"] is True, arn


async def test_the_standard_not_being_enabled_is_said_not_assumed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An account can run Security Hub with only CIS enabled.

    No 800-53 attestation exists in that case, and the honest report is that it
    is not enabled -- not an empty result a reader counts as zero findings.
    """
    shub = _StubSecurityHub(
        subscriptions=[{"StandardsArn": CIS_ARN, "StandardsStatus": "READY"}]
    )
    out = await _connector(shub, monkeypatch).securityhub_attestations()
    assert out["available"] is False
    assert out["controls"] == ()
    assert "not enabled" in out["reason"].lower()
    assert shub.findings_calls == [], "findings were fetched for a standard that is off"


@pytest.mark.parametrize("status", ["PENDING", "FAILED", "DELETING", "INCOMPLETE"])
async def test_a_standard_that_is_not_ready_is_not_read(
    status: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only ``READY`` means the control results are current.

    A standard mid-enablement has evaluated some of its controls and not others.
    Reading it reports a half-populated standard as an assessment, and the
    missing half as controls that passed by omission.
    """
    shub = _StubSecurityHub(
        subscriptions=[{"StandardsArn": GOV_ARN, "StandardsStatus": status}]
    )
    out = await _connector(shub, monkeypatch).securityhub_attestations()
    assert out["available"] is False
    assert status in out["reason"]
    assert shub.findings_calls == []


async def test_the_standard_list_is_paginated(monkeypatch: pytest.MonkeyPatch) -> None:
    """An account with many standards enabled can page the subscription list,
    and the NIST standard may be on the second page."""

    class _PagedStandards(_StubSecurityHub):
        def get_enabled_standards(self, **kwargs: Any) -> dict[str, Any]:
            self.standards_calls += 1
            if not kwargs.get("NextToken"):
                return {
                    "StandardsSubscriptions": [
                        {"StandardsArn": CIS_ARN, "StandardsStatus": "READY"}
                    ],
                    "NextToken": "more",
                }
            return {
                "StandardsSubscriptions": [
                    {"StandardsArn": GOV_ARN, "StandardsStatus": "READY"}
                ]
            }

    shub = _PagedStandards(pages=[[_finding("S3.8", "PASSED")]])
    out = await _connector(shub, monkeypatch).securityhub_attestations()
    assert out["available"] is True
    assert shub.standards_calls == 2


# --------------------------------------------------------------------------
# Pagination of the findings themselves
# --------------------------------------------------------------------------


async def test_every_page_of_findings_is_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """The one-page defect. Three pages must yield three controls.

    An implementation that stops after the first page scores the account on a
    prefix of its own posture, and the controls it never saw read as controls
    nobody evaluated.
    """
    shub = _StubSecurityHub(
        pages=[
            [_finding("S3.8", "PASSED")],
            [_finding("IAM.4", "FAILED")],
            [_finding("CloudTrail.1", "PASSED")],
        ]
    )
    out = await _connector(shub, monkeypatch).securityhub_attestations()
    assert [c.security_control_id for c in out["controls"]] == [
        "CloudTrail.1",
        "IAM.4",
        "S3.8",
    ]
    assert out["pages_read"] == 3
    assert out["truncated"] is False


async def test_the_next_token_is_sent_back(monkeypatch: pytest.MonkeyPatch) -> None:
    """Paging without forwarding the token re-reads page one forever."""
    shub = _StubSecurityHub(
        pages=[[_finding("S3.8", "PASSED")], [_finding("IAM.4", "FAILED")]]
    )
    await _connector(shub, monkeypatch).securityhub_attestations()
    assert shub.findings_calls[0].get("NextToken") is None
    assert shub.findings_calls[1]["NextToken"] == "token-1"


async def test_paging_stops_at_the_cap_and_says_so(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cap is needed -- a delegated administrator account's findings store is
    unbounded -- but a silent cap reports a truncated account as a whole one.

    ``truncated`` is the flag the ingest refuses to write a full result on.
    """
    pages = [[_finding(f"Svc.{i}", "FAILED")] for i in range(500)]
    conn = _connector(_StubSecurityHub(pages=pages), monkeypatch)
    out = await conn.securityhub_attestations(max_pages=3)
    assert out["pages_read"] == 3
    assert out["truncated"] is True
    assert "truncated" in (out["reason"] or "").lower()
    # Found by mutation: `truncated` alone was asserted, so hardcoding
    # `available: True` passed every test in this file. `available` is the field
    # the ingest branches on, and a truncated read that reports itself usable is
    # three pages of an account published as the whole account.
    assert out["available"] is False
    assert out["controls"], "the partial controls are still returned, for a reader"


async def test_an_account_with_no_findings_is_available_and_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Distinct from the standard being off: the standard is on and reported
    nothing, which the ingest must not turn into passing controls."""
    shub = _StubSecurityHub(pages=[[]])
    out = await _connector(shub, monkeypatch).securityhub_attestations()
    assert out["available"] is True
    assert out["controls"] == ()
    assert out["reason"] is None


# --------------------------------------------------------------------------
# The fetch filters to the right standard
# --------------------------------------------------------------------------


async def test_the_fetch_is_filtered_to_the_nist_standard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Otherwise CIS and PCI findings consume the page budget and are then
    discarded in the pure layer."""
    shub = _StubSecurityHub(pages=[[_finding("S3.8", "PASSED")]])
    await _connector(shub, monkeypatch).securityhub_attestations()
    filters = shub.findings_calls[0]["Filters"]
    assert filters["ComplianceAssociatedStandardsId"] == [
        {"Value": NIST_80053_R5_STANDARD_ID, "Comparison": "EQUALS"}
    ]


async def test_only_active_findings_are_fetched(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An ARCHIVED finding is about a resource that no longer exists. Counting
    it fails a control over a deleted bucket."""
    shub = _StubSecurityHub(pages=[[_finding("S3.8", "PASSED")]])
    await _connector(shub, monkeypatch).securityhub_attestations()
    filters = shub.findings_calls[0]["Filters"]
    assert filters["RecordState"] == [{"Value": "ACTIVE", "Comparison": "EQUALS"}]


# --------------------------------------------------------------------------
# Refusals must not read as a clean account
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "code",
    [
        "InvalidAccessException",
        "AccessDeniedException",
        "ResourceNotFoundException",
        "ThrottlingException",
    ],
)
async def test_a_refusal_is_reported_not_swallowed(
    code: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``InvalidAccessException`` is Security Hub not enabled in this region;
    ``AccessDeniedException`` is a missing IAM action. Neither is an account
    where every control passed, and the reason has to name which it was."""
    shub = _StubSecurityHub(standards_error=_client_error(code))
    out = await _connector(shub, monkeypatch).securityhub_attestations()
    assert out["available"] is False
    assert out["controls"] == ()
    assert code in out["reason"]


async def test_a_refusal_midway_through_paging_does_not_claim_a_whole_account(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Throttling on page two must not publish page one as the whole account.

    This is the sharpest version of the one-page defect: the data looks real, so
    nothing downstream has a reason to doubt it.
    """

    class _FailsOnSecondPage(_StubSecurityHub):
        def get_findings(self, **kwargs: Any) -> dict[str, Any]:
            self.findings_calls.append(kwargs)
            if len(self.findings_calls) == 1:
                return {"Findings": [_finding("S3.8", "PASSED")], "NextToken": "t"}
            raise _client_error("ThrottlingException")

    out = await _connector(_FailsOnSecondPage(), monkeypatch).securityhub_attestations()
    assert out["available"] is False
    assert out["truncated"] is True
    assert "ThrottlingException" in out["reason"]


async def test_an_unconfigured_connector_reads_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No credential, no call. The same contract ``scan`` keeps."""
    monkeypatch.setattr(AwsGovCloudConnector, "_boto3_available", lambda self: True)
    monkeypatch.setenv("CCF_AWS_CAPTURE_ENABLED", "true")
    get_settings.cache_clear()
    conn = AwsGovCloudConnector(credential=None)
    assert conn.is_configured() is False
    out = await conn.securityhub_attestations()
    assert out["available"] is False
    assert out["controls"] == ()
    assert "not configured" in out["reason"].lower()


# --------------------------------------------------------------------------
# What the result says about itself
# --------------------------------------------------------------------------


async def test_the_result_names_the_region_it_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Security Hub is regional. An attestation from us-gov-west-1 says nothing
    about resources in us-gov-east-1, and a reader comparing Concord against the
    console needs to know which region's findings these are."""
    shub = _StubSecurityHub(pages=[[_finding("S3.8", "PASSED")]])
    out = await _connector(shub, monkeypatch).securityhub_attestations()
    assert out["region"] == "us-gov-west-1"


async def test_the_result_names_the_account_it_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shub = _StubSecurityHub(pages=[[_finding("S3.8", "PASSED")]])
    out = await _connector(shub, monkeypatch).securityhub_attestations()
    assert out["account_id"] == "123456789012"


async def test_unreadable_requirements_are_surfaced_on_the_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Aggregated to the top level so the ingest can report how much of AWS's
    own mapping Concord could not attribute, without walking every control."""
    odd = {
        "Id": "IAM.8/x",
        "Title": "t",
        "Compliance": {
            "Status": "PASSED",
            "SecurityControlId": "IAM.8",
            "RelatedRequirements": [f"{REQUIREMENT_PREFIX} AC-2(j)"],
        },
    }
    shub = _StubSecurityHub(pages=[[odd, _finding("S3.8", "PASSED")]])
    out = await _connector(shub, monkeypatch).securityhub_attestations()
    assert out["unreadable_requirements"] == [f"{REQUIREMENT_PREFIX} AC-2(j)"]
