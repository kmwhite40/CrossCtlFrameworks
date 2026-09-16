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


# ── host safety: a hostile endpoint must never leave the process off-host ────
# CRITICAL 1, PR #13 review, layer 3 of 3: even if packs.catalog (install) and
# posture.resolve (resolve) were both bypassed, the connector itself must
# never send the org's bearer token to a host other than the configured
# graph_base_url. Unlike layers 1/2 (which reject these two payloads on
# format alone), this layer's mechanism is httpx.URL(base).join(path), which
# resolves both documented tricks as harmless *same-host* paths rather than
# raising -- see the report for the verified httpx.URL behaviour this rests
# on. The invariant under test is therefore "no request ever reaches a
# non-graph.microsoft.us host", which is the property that actually matters,
# checked directly against what the mock transport received.

HOSTILE_ENDPOINTS = [".attacker.example/v1.0/users", "@attacker.example/x"]


@pytest.mark.parametrize(
    "hostile_endpoint",
    HOSTILE_ENDPOINTS,
    ids=["no-trailing-slash-host-suffix", "userinfo"],
)
async def test_scan_never_sends_a_hostile_endpoints_request_off_host(
    monkeypatch: pytest.MonkeyPatch, hostile_endpoint: str
) -> None:
    """End to end through scan() -> _get_all, with the real (unmocked)
    connector code and only the HTTP transport swapped out -- so this proves
    what actually would have left the process, not just what a helper
    function returns in isolation. This is the exact vulnerable path
    described in the PR #13 review: a Form A/B pack rule's ``endpoint``
    reaching a scheduled scan. Run against the pre-fix connector (raw string
    concatenation), this fails and the recorded host is the attacker's; see
    the report for that output.
    """
    seen_hosts: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_hosts.append(request.url.host)
        return httpx.Response(404, json={"error": "not a real Graph route"})

    class _MockedAsyncClient(httpx.AsyncClient):
        def __init__(self, *a: Any, **kw: Any) -> None:
            kw["transport"] = httpx.MockTransport(handler)
            super().__init__(*a, **kw)

    monkeypatch.setattr(httpx, "AsyncClient", _MockedAsyncClient)
    monkeypatch.setattr(MsGraphConnector, "_token", _token_ok)

    hostile = ResolvedCheck(
        check=GUEST_CHECK,
        endpoint=hostile_endpoint,
        source="pack:test",
        spec=GUEST_RESOLVED.spec,
    )
    await MsGraphConnector(credential=CRED).scan(checks=(hostile,))

    assert seen_hosts, "expected the request to at least be attempted"
    assert all(h == "graph.microsoft.us" for h in seen_hosts), (
        f"a request reached an off-host target for {hostile_endpoint!r}: {seen_hosts!r}"
    )


async def test_an_absolute_off_host_target_is_refused_not_sent() -> None:
    """The case _safe_url's explicit host check exists for: a target that IS
    absolute (unlike the two tricks above, which a relative-reference join
    defangs by construction) -- e.g. what a compromised or hostile
    ``@odata.nextLink`` could contain. This must raise before any request is
    attempted, not merely resolve somewhere unexpected."""
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, json={"value": []})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError, match="off-host"):
            await MsGraphConnector()._get_all(
                client, "https://attacker.example/v1.0/users", {}
            )
    assert calls == [], f"a request reached the transport: {calls!r}"


async def test_a_hostile_next_link_does_not_pull_page_two_off_host() -> None:
    """@odata.nextLink comes from the response body -- a hostile or
    compromised page one must not be able to redirect page two's
    token-bearing request off-host."""
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(
            200,
            json={
                "value": [{"id": "a"}],
                "@odata.nextLink": "https://attacker.example/v1.0/users?page=2",
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError, match="off-host"):
            await MsGraphConnector()._get_all(
                client, "https://graph.microsoft.us/v1.0/users", {}
            )
    assert len(calls) == 1, "page one is legitimate and must have been requested"
    assert calls[0].startswith("https://graph.microsoft.us/"), calls[0]


@pytest.mark.parametrize("hostile_endpoint", HOSTILE_ENDPOINTS)
async def test_scan_reports_a_hostile_endpoint_as_unrunnable(
    monkeypatch: pytest.MonkeyPatch, hostile_endpoint: str
) -> None:
    """A ResolvedCheck built by hand (bypassing install and resolve entirely,
    the way a defect elsewhere in the pipeline might) must still come back as
    an ordinary manual_review_required outcome through scan()'s existing
    per-check isolation -- not raise out of scan(), and not report a clean
    fleet. No mock transport is needed: the host check raises before any
    request is attempted."""
    hostile = ResolvedCheck(
        check=GUEST_CHECK,
        endpoint=hostile_endpoint,
        source="pack:test",
        spec=GUEST_RESOLVED.spec,
    )
    monkeypatch.setattr(MsGraphConnector, "_token", _token_ok)
    outcomes = await MsGraphConnector(credential=CRED).scan(checks=(hostile,))
    assert len(outcomes) == 1
    assert outcomes[0].verdict == "manual_review_required"
