"""Graph pagination, and the permission field every check carries."""

from __future__ import annotations

import httpx
import pytest

from ccf.connectors.msgraph import GraphPaginationTruncatedError, MsGraphConnector
from ccf.posture.checks import PostureCheck


def test_posture_check_carries_required_permissions() -> None:
    c = PostureCheck(
        key="k", title="t", provider="msgraph", resource_type="entra_user",
        expected="e", control_ids=("IA-2",),
        required_permissions=("AuditLog.Read.All",),
    )
    assert c.required_permissions == ("AuditLog.Read.All",)


def test_required_permissions_defaults_to_empty() -> None:
    """Additive on a frozen dataclass: existing constructions keep working."""
    c = PostureCheck(
        key="k", title="t", provider="msgraph", resource_type="entra_user",
        expected="e", control_ids=("IA-2",),
    )
    assert c.required_permissions == ()


async def test_get_all_follows_next_link() -> None:
    """A finding on page two must not be invisible."""
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if "skiptoken" in str(request.url):
            return httpx.Response(200, json={"value": [{"id": "b"}]})
        return httpx.Response(
            200,
            json={
                "value": [{"id": "a"}],
                "@odata.nextLink": "https://graph.microsoft.us/v1.0/users?$skiptoken=X",
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        rows = await MsGraphConnector()._get_all(
            client, "https://graph.microsoft.us/v1.0/users", {}
        )
    assert [r["id"] for r in rows] == ["a", "b"]
    assert len(calls) == 2


async def test_get_all_single_page_makes_one_request() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, json={"value": [{"id": "only"}]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        rows = await MsGraphConnector()._get_all(
            client, "https://graph.microsoft.us/v1.0/users", {}
        )
    assert len(rows) == 1
    assert len(calls) == 1


async def test_get_all_raises_when_truncated_at_the_page_cap() -> None:
    """A self-referential nextLink must not spin forever, and a fleet that is
    still paginating when the cap is hit must never be silently accepted as
    complete -- a truncated fleet must never produce ``pass``."""
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(
            200,
            json={
                "value": [{"id": len(calls)}],
                "@odata.nextLink": "https://graph.microsoft.us/v1.0/users?$skiptoken=loop",
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(GraphPaginationTruncatedError):
            await MsGraphConnector()._get_all(
                client, "https://graph.microsoft.us/v1.0/users", {}
            )
    # Bounded: the cap is still respected, it just no longer resolves quietly.
    assert len(calls) == MsGraphConnector._MAX_PAGES


async def test_get_all_does_not_raise_when_the_last_page_has_no_next_link() -> None:
    """Hitting the cap on the exact page that also happens to be the last page
    is a complete fleet, not a truncation -- must not raise."""
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if len(calls) < MsGraphConnector._MAX_PAGES:
            return httpx.Response(
                200,
                json={
                    "value": [{"id": len(calls)}],
                    "@odata.nextLink": "https://graph.microsoft.us/v1.0/users?$skiptoken=n",
                },
            )
        return httpx.Response(200, json={"value": [{"id": len(calls)}]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        rows = await MsGraphConnector()._get_all(
            client, "https://graph.microsoft.us/v1.0/users", {}
        )
    assert len(rows) == MsGraphConnector._MAX_PAGES
    assert len(calls) == MsGraphConnector._MAX_PAGES


async def test_get_all_raises_on_error_status() -> None:
    """scan() relies on this raising so it can map 403 to manual review."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": {"message": "Insufficient privileges"}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(httpx.HTTPStatusError):
            await MsGraphConnector()._get_all(
                client, "https://graph.microsoft.us/v1.0/users", {}
            )


async def test_get_all_retries_once_after_429_honoring_retry_after() -> None:
    """Graph throttles hard; one bounded retry keeps a fleet check usable."""
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if len(calls) == 1:
            return httpx.Response(429, headers={"Retry-After": "0"}, json={})
        return httpx.Response(200, json={"value": [{"id": "a"}]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        rows = await MsGraphConnector()._get_all(
            client, "https://graph.microsoft.us/v1.0/users", {}
        )
    assert [r["id"] for r in rows] == ["a"]
    assert len(calls) == 2


async def test_get_all_raises_after_a_second_consecutive_429() -> None:
    """One retry only -- a persistent 429 must surface, not loop forever."""
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(429, headers={"Retry-After": "0"}, json={})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(httpx.HTTPStatusError):
            await MsGraphConnector()._get_all(
                client, "https://graph.microsoft.us/v1.0/users", {}
            )
    assert len(calls) == 2


async def test_get_all_tolerates_a_missing_value_array() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        assert (
            await MsGraphConnector()._get_all(
                client, "https://graph.microsoft.us/v1.0/users", {}
            )
            == []
        )
