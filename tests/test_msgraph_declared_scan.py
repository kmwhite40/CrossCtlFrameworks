"""The connector executes declared checks beside the platform's."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from ccf.connectors.msgraph import MsGraphConnector
from ccf.posture.declared import DeclaredSpec
from ccf.posture.providers import m365
from ccf.posture.resolve import ResolvedCheck
from ccf.posture.types import PostureCheck

CRED = {"tenant_id": "t-1", "client_id": "c-1", "client_secret": "s-1"}

GUEST_CHECK = PostureCheck(
    key="org.no_guest_accounts",
    title="No guest accounts",
    provider="msgraph",
    resource_type="entra_user",
    expected="no guest account exists in the directory",
    control_ids=("AC-2", "AC-6"),
    required_permissions=("User.Read.All",),
)

GUEST_RESOLVED = ResolvedCheck(
    check=GUEST_CHECK,
    endpoint="/v1.0/users?$select=id,userPrincipalName,userType",
    source="pack:test",
    spec=DeclaredSpec(
        mode="per_resource",
        resource_type="entra_user",
        resource_id_field="userPrincipalName",
        predicate={"op": "not_equals", "path": "userType", "value": "Guest"},
        expected="no guest account exists in the directory",
    ),
)

# A Form A check as resolution actually produces it: the pack's OWN key, with
# evaluator_key pointing at the platform logic it reuses. Using the platform
# check's key here would make the two indistinguishable and hide a dispatch
# that looked up the wrong one.
STALE_60 = ResolvedCheck(
    check=replace(
        m365.STALE_ACCOUNTS,
        key="org.stale_accounts.60d",
        expected="no enabled account has been inactive longer than 60 days",
    ),
    endpoint=m365.ENDPOINTS[m365.STALE_ACCOUNTS.key],
    source="pack:test",
    evaluator_key=m365.STALE_ACCOUNTS.key,
    parameters={"threshold_days": 60},
)


async def _token_ok(self: Any, client: Any) -> str:
    return "token"


async def test_a_declared_check_runs_and_reports_per_resource(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_get_all(self: Any, client: Any, url: str, headers: Any) -> list[dict[str, Any]]:
        assert "userType" in url, "the declared check's own endpoint must be used"
        return [
            {"userPrincipalName": "member@x.gov", "userType": "Member"},
            {"userPrincipalName": "guest@x.gov", "userType": "Guest"},
        ]

    monkeypatch.setattr(MsGraphConnector, "_token", _token_ok)
    monkeypatch.setattr(MsGraphConnector, "_get_all", fake_get_all)

    outcomes = await MsGraphConnector(credential=CRED).scan(checks=(GUEST_RESOLVED,))
    assert len(outcomes) == 1
    outcome = outcomes[0]
    assert outcome.check_key == "org.no_guest_accounts"
    assert outcome.verdict == "fail"
    assert outcome.evaluated == 2
    assert outcome.failing == 1
    assert outcome.expected == "no guest account exists in the directory"
    assert {f.resource_id for f in outcome.findings} == {"member@x.gov", "guest@x.gov"}


async def test_a_declared_check_that_is_forbidden_names_its_permission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The 403-is-not-empty rule must hold for declared checks too, or a pack's
    check silently reports a clean fleet."""

    async def forbidden(self: Any, client: Any, url: str, headers: Any) -> list[dict[str, Any]]:
        request = httpx.Request("GET", url)
        raise httpx.HTTPStatusError(
            "Forbidden", request=request, response=httpx.Response(403, request=request)
        )

    monkeypatch.setattr(MsGraphConnector, "_token", _token_ok)
    monkeypatch.setattr(MsGraphConnector, "_get_all", forbidden)

    outcomes = await MsGraphConnector(credential=CRED).scan(checks=(GUEST_RESOLVED,))
    assert outcomes[0].verdict == "manual_review_required"
    assert "User.Read.All" in outcomes[0].findings[0].observed
    assert "403" in outcomes[0].findings[0].observed


async def test_a_parameterized_platform_check_uses_the_declared_threshold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    idle_75 = (datetime.now(UTC) - timedelta(days=75)).isoformat().replace("+00:00", "Z")

    async def fake_get_all(self: Any, client: Any, url: str, headers: Any) -> list[dict[str, Any]]:
        return [
            {
                "userPrincipalName": "idle@x.gov",
                "accountEnabled": True,
                "signInActivity": {"lastSignInDateTime": idle_75},
            }
        ]

    monkeypatch.setattr(MsGraphConnector, "_token", _token_ok)
    monkeypatch.setattr(MsGraphConnector, "_get_all", fake_get_all)

    at_60 = await MsGraphConnector(credential=CRED).scan(checks=(STALE_60,))
    assert at_60[0].check_key == "org.stale_accounts.60d", "runs under the pack's key"
    assert at_60[0].verdict == "fail", "a 60-day threshold must fail a 75-day-idle account"
    assert "60 days" in at_60[0].expected

    default = ResolvedCheck(
        check=m365.STALE_ACCOUNTS,
        endpoint=m365.ENDPOINTS[m365.STALE_ACCOUNTS.key],
        source="platform",
        evaluator_key=m365.STALE_ACCOUNTS.key,
    )
    at_90 = await MsGraphConnector(credential=CRED).scan(checks=(default,))
    assert at_90[0].verdict == "pass", "the platform default must be unaffected"


async def test_one_bad_declared_check_does_not_discard_the_others(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per-check isolation must cover declared checks -- a pack's broken rule
    cannot take a tenant's whole scan down."""
    broken = ResolvedCheck(
        check=PostureCheck(
            key="org.broken",
            title="Broken",
            provider="msgraph",
            resource_type="entra_user",
            expected="something",
            control_ids=("AC-2",),
        ),
        endpoint="/v1.0/users",
        source="pack:test",
        spec=DeclaredSpec(
            mode="sometimes",  # rejected at install; simulates a pre-validation row
            resource_type="entra_user",
            predicate={"op": "truthy", "path": "x"},
            expected="something",
        ),
    )

    async def fake_get_all(self: Any, client: Any, url: str, headers: Any) -> list[dict[str, Any]]:
        return [{"userPrincipalName": "member@x.gov", "userType": "Member"}]

    monkeypatch.setattr(MsGraphConnector, "_token", _token_ok)
    monkeypatch.setattr(MsGraphConnector, "_get_all", fake_get_all)

    outcomes = await MsGraphConnector(credential=CRED).scan(checks=(broken, GUEST_RESOLVED))
    keys = {o.check_key for o in outcomes}
    assert "org.no_guest_accounts" in keys, "the good check must still have run"
    broken_outcome = next((o for o in outcomes if o.check_key == "org.broken"), None)
    assert broken_outcome is not None, "a broken check must report, not vanish"
    assert broken_outcome.verdict == "manual_review_required"


async def test_no_checks_argument_still_runs_the_platform_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every existing caller of scan() behaves exactly as before."""

    async def fake_get_all(self: Any, client: Any, url: str, headers: Any) -> list[dict[str, Any]]:
        return []

    monkeypatch.setattr(MsGraphConnector, "_token", _token_ok)
    monkeypatch.setattr(MsGraphConnector, "_get_all", fake_get_all)

    outcomes = await MsGraphConnector(credential=CRED).scan()
    assert {o.check_key for o in outcomes} == {c.key for c in m365.CHECKS}


async def test_an_empty_checks_tuple_scans_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Explicitly empty is not the same as unspecified -- it must not silently
    fall back to the platform registry."""
    monkeypatch.setattr(MsGraphConnector, "_token", _token_ok)
    assert await MsGraphConnector(credential=CRED).scan(checks=()) == []
