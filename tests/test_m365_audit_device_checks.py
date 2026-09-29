"""Audit-trail, device-compliance and risky-user checks, against real Graph shapes."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ccf.posture.providers import m365

TENANT = "d0529da6-0000-0000-0000-000000000000"
NOW = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)


def _stamp(days_ago: int) -> str:
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- AU-2 / AU-12 audit currency ---------------------------------------------


def test_a_recent_signin_record_passes() -> None:
    rows = [{"createdDateTime": _stamp(1)}]
    f = m365.evaluate_signin_audit_current(rows, tenant_id=TENANT, now=NOW)
    assert [x.verdict for x in f] == ["pass"]


def test_an_audit_trail_that_has_gone_quiet_fails() -> None:
    rows = [{"createdDateTime": _stamp(m365.AUDIT_RECENCY_DAYS + 1)}]
    f = m365.evaluate_signin_audit_current(rows, tenant_id=TENANT, now=NOW)
    assert [x.verdict for x in f] == ["fail"]
    assert "day(s) old" in f[0].observed


def test_no_audit_records_at_all_is_a_failure_not_a_shrug() -> None:
    """A tenant with no audit records is either not producing them, has lost
    the permission, or has let retention expire them. Every one of those is
    the finding AU-2 exists to catch; not-applicable would turn the absence of
    an audit trail into silence.
    """
    f = m365.evaluate_signin_audit_current([], tenant_id=TENANT, now=NOW)
    assert [x.verdict for x in f] == ["fail"]
    assert "no sign-in record" in f[0].observed


def test_the_directory_audit_check_reads_its_own_timestamp_field() -> None:
    """`directoryAudits` dates records with `activityDateTime`, not
    `createdDateTime` -- reading the wrong field would make every tenant look
    like it had no audit trail."""
    rows = [{"activityDateTime": _stamp(1)}]
    result = m365.evaluate_directory_audit_current(rows, tenant_id=TENANT, now=NOW)
    assert result[0].verdict == "pass"
    # The sign-in evaluator must not accept that field, or the two would be
    # interchangeable and the distinction above meaningless.
    assert m365.evaluate_signin_audit_current(rows, tenant_id=TENANT, now=NOW)[0].verdict == "fail"


def test_the_newest_record_decides_not_the_first_returned() -> None:
    rows = [{"createdDateTime": _stamp(30)}, {"createdDateTime": _stamp(1)}]
    assert m365.evaluate_signin_audit_current(rows, tenant_id=TENANT, now=NOW)[0].verdict == "pass"


# --- CM-6 device compliance ---------------------------------------------------


def test_a_noncompliant_device_is_named() -> None:
    rows = [
        {"id": "1", "deviceName": "LAPTOP-A", "complianceState": "noncompliant"},
        {"id": "2", "deviceName": "LAPTOP-B", "complianceState": "compliant"},
    ]
    f = m365.evaluate_device_compliance(rows)
    failing = [x for x in f if x.verdict == "fail"]
    assert len(failing) == 1
    assert "LAPTOP-A" in failing[0].observed


@pytest.mark.parametrize("state", sorted(m365.DEVICE_UNEVALUATED_STATES))
def test_an_unevaluated_device_is_not_scored_as_a_failure(state: str) -> None:
    """A device Intune has not evaluated has not been shown to be
    non-compliant. Scoring it as one invents a finding."""
    f = m365.evaluate_device_compliance([{"id": "1", "complianceState": state}])
    assert [x.verdict for x in f] == ["not_applicable"]


@pytest.mark.parametrize("state", sorted(m365.DEVICE_NONCOMPLIANT_STATES))
def test_every_noncompliant_state_fails(state: str) -> None:
    """`inGracePeriod` and `conflict` are not compliance -- a grace period is
    a deadline, not a pass."""
    f = m365.evaluate_device_compliance([{"id": "1", "complianceState": state}])
    assert [x.verdict for x in f] == ["fail"]


# --- AC-2(12) risky users -----------------------------------------------------


@pytest.mark.parametrize("state", ["remediated", "dismissed", "confirmedSafe"])
def test_a_dispositioned_user_passes_whatever_the_disposition(state: str) -> None:
    """The control is about responding to the signal, not about the verdict:
    dismissing a false positive is a response."""
    rows = [{"id": "u1", "userPrincipalName": "a@x.gov", "riskState": state}]
    assert [f.verdict for f in m365.evaluate_risky_users_resolved(rows)] == ["pass"]


@pytest.mark.parametrize("state", sorted(m365.RISK_UNRESOLVED_STATES))
def test_a_user_nobody_has_dealt_with_fails(state: str) -> None:
    rows = [
        {"id": "u1", "userPrincipalName": "a@x.gov", "riskState": state, "riskLevel": "high"}
    ]
    f = m365.evaluate_risky_users_resolved(rows)
    assert [x.verdict for x in f] == ["fail"]
    assert "a@x.gov" in f[0].observed


# --- pagination ---------------------------------------------------------------


def test_the_audit_checks_are_the_only_single_page_reads() -> None:
    """Following `@odata.nextLink` on a `$top=1` audit query walked a tenant's
    whole sign-in log and earned a 429, which the per-check isolation reported
    as `manual_review_required` -- a rate limit wearing the costume of a
    finding. A fleet check must keep paginating, or it would judge a fleet from
    its first page."""
    assert set(m365.FIRST_PAGE_ONLY) == {
        m365.SIGNIN_AUDIT_CURRENT.key,
        m365.DIRECTORY_AUDIT_CURRENT.key,
    }
    assert m365.DEVICE_COMPLIANCE.key not in m365.FIRST_PAGE_ONLY
    assert m365.STALE_ACCOUNTS.key not in m365.FIRST_PAGE_ONLY


@pytest.mark.asyncio
async def test_a_single_page_read_does_not_follow_the_next_link() -> None:
    """Driven through `_get_all`, because the bound is in the fetch and a test
    of the mapping alone would pass with the wiring absent."""
    import httpx  # noqa: PLC0415

    from ccf.connectors.msgraph import MsGraphConnector  # noqa: PLC0415

    calls: list[str] = []

    async def _serve(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(
            200,
            json={
                "value": [{"createdDateTime": _stamp(0)}],
                "@odata.nextLink": "https://graph.microsoft.us/v1.0/auditLogs/signIns?$skiptoken=x",
            },
        )

    connector = MsGraphConnector(
        credential={"tenant_id": TENANT, "client_id": "c", "client_secret": "s"}
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(_serve)) as client:
        rows = await connector._get_all(
            client, "/v1.0/auditLogs/signIns?$top=1", {}, max_pages=1
        )

    assert len(calls) == 1, "followed the next link on a single-page read"
    assert len(rows) == 1
