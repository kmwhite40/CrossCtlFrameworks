"""scan() orchestration: dispatch, isolation, and 403-is-not-empty."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from ccf.connectors.msgraph import MsGraphConnector
from ccf.posture.providers.m365 import LEGACY_AUTH_BLOCKED, MFA_REGISTERED, STALE_ACCOUNTS

CRED = {"tenant_id": "t-1", "client_id": "c-1", "client_secret": "s-1"}


# Patched onto the class, so these fakes receive `self` first -- calling
# self._get_all(client, url, headers) becomes fake(self, client, url, headers).
async def _token_ok(self: Any, client: Any) -> str:
    return "token"


async def test_unconfigured_scans_nothing() -> None:
    assert await MsGraphConnector(credential=None).scan() == []


async def test_scan_returns_one_outcome_per_check(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_get_all(
        self: Any, client: Any, url: str, headers: Any
    ) -> list[dict[str, Any]]:
        if "userRegistrationDetails" in url:
            return [{"id": "u1", "userPrincipalName": "a@x.gov", "isMfaRegistered": True}]
        return []

    monkeypatch.setattr(MsGraphConnector, "_token", _token_ok)
    monkeypatch.setattr(MsGraphConnector, "_get_all", fake_get_all)

    outcomes = await MsGraphConnector(credential=CRED).scan()
    keys = {o.check_key for o in outcomes}
    assert keys == {MFA_REGISTERED.key, LEGACY_AUTH_BLOCKED.key, STALE_ACCOUNTS.key}
    mfa = next(o for o in outcomes if o.check_key == MFA_REGISTERED.key)
    assert mfa.verdict == "pass"
    legacy = next(o for o in outcomes if o.check_key == LEGACY_AUTH_BLOCKED.key)
    assert legacy.verdict == "fail"  # no policy blocks legacy auth


async def test_forbidden_is_manual_review_not_not_applicable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """THE most important test here. A missing app permission must never read
    as a clean fleet -- zero findings would roll up to not_applicable and hide
    a broken check behind a benign-looking verdict."""

    async def forbidden(
        self: Any, client: Any, url: str, headers: Any
    ) -> list[dict[str, Any]]:
        request = httpx.Request("GET", url)
        raise httpx.HTTPStatusError(
            "Forbidden", request=request, response=httpx.Response(403, request=request)
        )

    monkeypatch.setattr(MsGraphConnector, "_token", _token_ok)
    monkeypatch.setattr(MsGraphConnector, "_get_all", forbidden)

    outcomes = await MsGraphConnector(credential=CRED).scan()
    assert outcomes, "a forbidden scan must still report outcomes"
    for o in outcomes:
        assert o.verdict == "manual_review_required", o.check_key
        assert o.verdict != "not_applicable"
        assert o.findings, "the reason must be visible as a finding"
        assert "403" in o.findings[0].observed

    mfa = next(o for o in outcomes if o.check_key == MFA_REGISTERED.key)
    assert "AuditLog.Read.All" in mfa.findings[0].observed


async def test_one_check_failing_does_not_lose_the_others(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def selective(
        self: Any, client: Any, url: str, headers: Any
    ) -> list[dict[str, Any]]:
        if "userRegistrationDetails" in url:
            raise RuntimeError("graph exploded")
        return []

    monkeypatch.setattr(MsGraphConnector, "_token", _token_ok)
    monkeypatch.setattr(MsGraphConnector, "_get_all", selective)

    outcomes = await MsGraphConnector(credential=CRED).scan()
    assert len(outcomes) == 3
    mfa = next(o for o in outcomes if o.check_key == MFA_REGISTERED.key)
    assert mfa.verdict == "manual_review_required"
    legacy = next(o for o in outcomes if o.check_key == LEGACY_AUTH_BLOCKED.key)
    assert legacy.verdict == "fail"  # unaffected by its neighbour


async def test_scan_never_raises_when_the_token_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def no_token(*a: Any, **k: Any) -> None:
        raise httpx.ConnectError("dns")

    monkeypatch.setattr(MsGraphConnector, "_token", no_token)
    assert await MsGraphConnector(credential=CRED).scan() == []


async def test_scan_returns_empty_when_token_is_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def none_token(*a: Any, **k: Any) -> None:
        return None

    monkeypatch.setattr(MsGraphConnector, "_token", none_token)
    assert await MsGraphConnector(credential=CRED).scan() == []


async def test_stale_check_receives_a_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """evaluate_stale_accounts needs `now`; scan must supply it."""

    async def one_old_user(
        self: Any, client: Any, url: str, headers: Any
    ) -> list[dict[str, Any]]:
        if "users?" in url:
            return [
                {
                    "id": "u1",
                    "userPrincipalName": "old@x.gov",
                    "accountEnabled": True,
                    "signInActivity": {"lastSignInDateTime": "2020-01-01T00:00:00Z"},
                }
            ]
        return []

    monkeypatch.setattr(MsGraphConnector, "_token", _token_ok)
    monkeypatch.setattr(MsGraphConnector, "_get_all", one_old_user)

    outcomes = await MsGraphConnector(credential=CRED).scan()
    stale = next(o for o in outcomes if o.check_key == STALE_ACCOUNTS.key)
    assert stale.verdict == "fail"
    assert stale.failing == 1
