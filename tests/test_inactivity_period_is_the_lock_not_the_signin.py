"""The session-lock ODP must come from the session lock.

Found by reading a generated SSP for a real tenant. Under AC.L2-3.1.10 -- "Use
session lock with pattern-hiding displays to prevent access and viewing of data
after a period of inactivity" -- it said:

    Organization-defined parameters - inactivity period = 8 hours
    (captured from msgraph)

Eight hours. No assessor accepts an eight-hour screen lock for 3.1.10, and the
organization had never set one: the value was the tenant's Conditional Access
**sign-in frequency**, which is how often a user must re-authenticate, mapped
onto the session-lock ODP. Different setting, different control.

What makes it a defect rather than a loose approximation is that the same SSP
also carried a **passing** `m365.device.session_lock_enforced`, a check that
passes only when a device compliance policy locks within fifteen minutes. One
document, two contradictory statements about one setting -- and the wrong one
was the one rendered as the organization's own claim, with a source attribution
("captured from msgraph") that made it look verified.

The fix reads the lock timeout from the same field, through the same function,
that the check evaluates. These tests exist to keep the narrative and the
verdict reading the same setting.
"""

from __future__ import annotations

import httpx
import pytest

from ccf.connectors.msgraph import MsGraphConnector
from ccf.posture.providers import m365

_SIGNIN_FREQUENCY_HOURS = 8
_LOCK_MINUTES = 10


def _policies() -> dict[str, object]:
    return {
        "value": [
            {"id": "dcp-encrypt", "displayName": "Encryption only"},
            {
                "id": "dcp-zero",
                "displayName": "Unconfigured lock",
                "passwordRequired": True,
                "passwordMinutesOfInactivityBeforeLock": 0,
            },
            {
                "id": "dcp-lax",
                "displayName": "Lax lock",
                "passwordRequired": True,
                "passwordMinutesOfInactivityBeforeLock": 30,
            },
            {
                "id": "dcp-strict",
                "displayName": "Corp devices",
                "passwordRequired": True,
                "passwordMinutesOfInactivityBeforeLock": _LOCK_MINUTES,
            },
        ]
    }


def _handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if request.method == "POST" and url.endswith("/oauth2/v2.0/token"):
        return httpx.Response(200, json={"access_token": "t", "expires_in": 3599})
    if "/identity/conditionalAccess/policies" in url:
        # Deliberately a different number, in different units, from the lock
        # policy: a fixture where both sources agree cannot tell them apart,
        # which is exactly how the original defect survived.
        return httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "pol-freq",
                        "displayName": "Re-authenticate",
                        "state": "enabled",
                        "sessionControls": {
                            "signInFrequency": {
                                "isEnabled": True,
                                "value": _SIGNIN_FREQUENCY_HOURS,
                                "type": "hours",
                            }
                        },
                    }
                ]
            },
        )
    if "/deviceManagement/deviceCompliancePolicies" in url:
        return httpx.Response(200, json=_policies())
    return httpx.Response(404, json={"error": {"code": "unknownPath", "message": url}})


@pytest.fixture
def connector(monkeypatch: pytest.MonkeyPatch) -> MsGraphConnector:
    conn = MsGraphConnector(
        credential={
            "tenant_id": "t-1",
            "client_id": "c-1",
            "client_secret": "s-1",
        }
    )
    transport = httpx.MockTransport(_handler)
    original = httpx.AsyncClient

    def _client(*args: object, **kwargs: object) -> httpx.AsyncClient:
        kwargs["transport"] = transport
        return original(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr("ccf.connectors.msgraph.httpx.AsyncClient", _client)
    return conn


@pytest.mark.asyncio
async def test_the_captured_period_is_the_lock_timeout(
    connector: MsGraphConnector,
) -> None:
    """The regression: 8 hours of sign-in frequency must not become the lock."""
    caps = await connector.capture()
    by_key = {c.odp_key: c for c in caps}
    assert "inactivity_period" in by_key, "the session-lock ODP must still be captured"
    captured = by_key["inactivity_period"]

    assert captured.value == f"{_LOCK_MINUTES} minutes", (
        f"expected the device policy's lock timeout, got {captured.value!r} -- "
        "the sign-in frequency is not the session lock"
    )
    assert "hours" not in captured.value, (
        "an hours-valued inactivity period is the sign-in frequency leaking back in"
    )
    assert str(_SIGNIN_FREQUENCY_HOURS) not in captured.value


@pytest.mark.asyncio
async def test_the_source_names_the_policy_the_value_came_from(
    connector: MsGraphConnector,
) -> None:
    """An assessor checking the claim needs to know where to look.

    The old value cited "Conditional Access" while describing a device lock,
    which sent anyone verifying it to the wrong blade.
    """
    caps = await connector.capture()
    captured = next(c for c in caps if c.odp_key == "inactivity_period")
    assert "device compliance" in captured.source.lower()
    assert "Conditional Access" not in captured.source
    assert "Corp devices" in captured.source
    assert captured.detail["lock_minutes"] == _LOCK_MINUTES
    # High, not medium: this is the setting itself rather than a stand-in.
    assert captured.confidence == "high"


@pytest.mark.asyncio
async def test_the_soonest_real_lock_wins_and_zero_is_not_a_lock(
    connector: MsGraphConnector,
) -> None:
    """30 and 10 are both configured; 0 and absent are not locks at all.

    Intune reports 0 for "not configured" on some platforms, so reading it as
    an immediate lock would turn an unset policy into the strongest claim in
    the document.
    """
    caps = await connector.capture()
    captured = next(c for c in caps if c.odp_key == "inactivity_period")
    assert captured.value == "10 minutes"
    assert captured.value != "0 minutes"


@pytest.mark.asyncio
async def test_no_configured_lock_captures_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Better unfilled than filled with a number nobody set.

    The ODP then renders as organization-defined and outstanding, which is true,
    instead of borrowing whatever other duration happened to be readable.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if request.method == "POST" and url.endswith("/oauth2/v2.0/token"):
            return httpx.Response(200, json={"access_token": "t", "expires_in": 3599})
        if "/identity/conditionalAccess/policies" in url:
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "id": "pol-freq",
                            "displayName": "Re-authenticate",
                            "state": "enabled",
                            "sessionControls": {
                                "signInFrequency": {
                                    "isEnabled": True,
                                    "value": 8,
                                    "type": "hours",
                                }
                            },
                        }
                    ]
                },
            )
        if "/deviceManagement/deviceCompliancePolicies" in url:
            return httpx.Response(200, json={"value": [{"id": "dcp", "displayName": "None"}]})
        return httpx.Response(404, json={})

    conn = MsGraphConnector(
        credential={"tenant_id": "t", "client_id": "c", "client_secret": "s"}
    )
    transport = httpx.MockTransport(handler)
    original = httpx.AsyncClient

    def _client(*args: object, **kwargs: object) -> httpx.AsyncClient:
        kwargs["transport"] = transport
        return original(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr("ccf.connectors.msgraph.httpx.AsyncClient", _client)
    caps = await conn.capture()
    assert "inactivity_period" not in {c.odp_key for c in caps}, (
        "an unset lock must not be filled from the sign-in frequency"
    )


@pytest.mark.asyncio
async def test_a_missing_intune_permission_does_not_discard_the_other_captures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The new Graph call is guarded on its own.

    `capture()`'s outer handler returns `[]`, so folding the device-policy read
    into it would let one ungranted permission -- Intune's, which the runbook
    already flags as commonly missing -- silently discard every parameter this
    connector captures, including MFA enforcement.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if request.method == "POST" and url.endswith("/oauth2/v2.0/token"):
            return httpx.Response(200, json={"access_token": "t", "expires_in": 3599})
        if "/identity/conditionalAccess/policies" in url:
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "id": "pol-mfa",
                            "displayName": "Require MFA",
                            "state": "enabled",
                            "grantControls": {"builtInControls": ["mfa"]},
                        }
                    ]
                },
            )
        if "/deviceManagement/deviceCompliancePolicies" in url:
            return httpx.Response(403, json={"error": {"code": "Authorization_RequestDenied"}})
        return httpx.Response(404, json={})

    conn = MsGraphConnector(
        credential={"tenant_id": "t", "client_id": "c", "client_secret": "s"}
    )
    transport = httpx.MockTransport(handler)
    original = httpx.AsyncClient

    def _client(*args: object, **kwargs: object) -> httpx.AsyncClient:
        kwargs["transport"] = transport
        return original(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr("ccf.connectors.msgraph.httpx.AsyncClient", _client)
    caps = await conn.capture()
    assert {c.odp_key for c in caps} == {"mfa_enforced"}, (
        "a 403 on device policies must not take the Conditional Access captures with it"
    )


def test_the_narrative_and_the_check_read_the_same_field() -> None:
    """One definition: the capture calls the evaluator's own extractor.

    If these diverge, the SSP can once again state a lock period the check
    disagrees with -- which is the whole defect, in its most durable form.
    """
    policy = {
        "passwordRequired": True,
        "passwordMinutesOfInactivityBeforeLock": 12,
    }
    assert m365.lock_minutes(policy) == 12
    assert m365.lock_minutes({"passwordMinutesOfInactivityBeforeLock": 0}) is None
    assert m365.lock_minutes({}) is None
