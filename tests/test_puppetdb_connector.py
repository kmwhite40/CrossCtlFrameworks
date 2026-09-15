"""The PuppetDB connector: verify, scan, and the reads it deliberately skips."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from ccf.connectors import get_connector
from ccf.connectors import puppetdb as puppetdb_mod
from ccf.connectors.puppetdb import PuppetDbConnector
from ccf.posture.providers import puppetdb as checks

CRED = {"base_url": "https://puppetdb.acme.gov:8081", "token": "tok"}

NODES = [
    {
        "certname": "web01.acme.gov",
        "report_timestamp": "2026-09-15T11:30:00Z",
        "latest_report_status": "unchanged",
    },
    {
        "certname": "broken01.acme.gov",
        "report_timestamp": "2026-09-15T11:31:00Z",
        "latest_report_status": "failed",
    },
]


class _Fake:
    """Records the requests the connector makes."""

    def __init__(self, *, status: int = 200, nodes: list[dict] | None = None,
                 facts: list[dict] | None = None) -> None:
        self.status = status
        self.nodes = nodes if nodes is not None else NODES
        self.facts = facts or []
        self.calls: list[tuple[str, dict[str, Any] | None]] = []

    async def __aenter__(self) -> _Fake:
        return self

    async def __aexit__(self, *a: object) -> None:
        return None

    async def get(
        self, url: str, headers: dict[str, str], params: dict[str, Any] | None = None
    ) -> httpx.Response:
        self.calls.append((url, params))
        request = httpx.Request("GET", url)
        if self.status != 200:
            return httpx.Response(self.status, request=request)
        body = self.facts if "/facts" in url else self.nodes
        return httpx.Response(200, json=body, request=request)


def _patch(monkeypatch: pytest.MonkeyPatch, fake: _Fake) -> None:
    monkeypatch.setattr(puppetdb_mod.httpx, "AsyncClient", lambda **k: fake)


# ── configuration ────────────────────────────────────────────────────────────


def test_a_base_url_is_enough_to_be_configured() -> None:
    """Many PuppetDB deployments sit behind mTLS rather than bearer auth, so
    refusing to try without a token would be wrong."""
    assert PuppetDbConnector(credential={"base_url": "https://pdb"}).is_configured()


def test_no_credential_is_not_configured() -> None:
    assert PuppetDbConnector().is_configured() is False
    assert PuppetDbConnector(credential={"token": "t"}).is_configured() is False


def test_it_is_resolvable_from_the_registry() -> None:
    conn = get_connector("puppetdb", credential=CRED)
    assert isinstance(conn, PuppetDbConnector)


def test_a_token_is_sent_as_the_puppetdb_auth_header() -> None:
    headers = PuppetDbConnector(credential=CRED)._headers()
    assert headers["X-Authentication"] == "tok"


def test_no_token_sends_no_auth_header() -> None:
    headers = PuppetDbConnector(credential={"base_url": "https://pdb"})._headers()
    assert "X-Authentication" not in headers


# ── capture is deliberately empty ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_capture_is_always_empty() -> None:
    """Puppet facts describe the machine, not the policy values ODPs track.
    Inventing a mapping from `kernel` to an ODP would be worse than nothing."""
    assert await PuppetDbConnector(credential=CRED).capture() == []
    assert PuppetDbConnector.PARAMETER_MAP == {}


# ── verify ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_verify_reports_the_node_count(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _Fake()
    _patch(monkeypatch, fake)
    out = await PuppetDbConnector(credential=CRED).verify()
    assert out["connected"] is True
    assert out["nodes"] == 2


@pytest.mark.asyncio
async def test_verify_without_a_url_says_so() -> None:
    out = await PuppetDbConnector().verify()
    assert out["connected"] is False
    assert "base_url" in out["reason"]


@pytest.mark.asyncio
async def test_verify_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _Fake(status=500)
    _patch(monkeypatch, fake)
    out = await PuppetDbConnector(credential=CRED).verify()
    assert out["connected"] is False


# ── scan ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scan_returns_one_outcome_per_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _Fake()
    _patch(monkeypatch, fake)
    outcomes = await PuppetDbConnector(credential=CRED).scan()
    assert {o.check_key for o in outcomes} == {c.key for c in checks.CHECKS}


@pytest.mark.asyncio
async def test_one_query_serves_both_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    """PuppetDB returns the run status and the report timestamp on the same
    node record, so two queries would be two round trips for one answer."""
    fake = _Fake()
    _patch(monkeypatch, fake)
    await PuppetDbConnector(credential=CRED).scan()
    assert len([c for c in fake.calls if "/nodes" in c[0]]) == 1


@pytest.mark.asyncio
async def test_a_failing_node_fails_the_run_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _Fake()
    _patch(monkeypatch, fake)
    outcomes = await PuppetDbConnector(credential=CRED).scan()
    run = next(o for o in outcomes if o.check_key == checks.NODE_LAST_RUN_OK.key)
    assert run.verdict == "fail"
    assert run.failing == 1
    assert run.evaluated == 2


@pytest.mark.asyncio
async def test_a_403_is_manual_review_not_an_empty_fleet(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Zero findings roll up to not_applicable, so returning nothing would hide
    an unauthorized PuppetDB behind a benign verdict."""
    fake = _Fake(status=403)
    _patch(monkeypatch, fake)
    outcomes = await PuppetDbConnector(credential=CRED).scan()
    assert len(outcomes) == len(checks.CHECKS)
    for outcome in outcomes:
        assert outcome.verdict == "manual_review_required"
        assert "403" in outcome.findings[0].observed
        assert "PuppetDB query" in outcome.findings[0].observed


@pytest.mark.asyncio
async def test_unconfigured_scans_nothing() -> None:
    assert await PuppetDbConnector().scan() == []


@pytest.mark.asyncio
async def test_an_explicitly_empty_check_list_scans_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _Fake()
    _patch(monkeypatch, fake)
    assert await PuppetDbConnector(credential=CRED).scan(()) == []
    assert fake.calls == [], "nothing should have been queried"


# ── facts ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_nodes_with_facts_attaches_only_the_inventory_facts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A PuppetDB fact set runs to hundreds of keys; copying all of them would
    turn an inventory record into a data dump nobody reads."""
    fake = _Fake(
        nodes=[NODES[0]],
        facts=[
            {"certname": "web01.acme.gov", "name": "os", "value": "RedHat"},
            {"certname": "web01.acme.gov", "name": "ipaddress", "value": "10.0.0.5"},
            {"certname": "web01.acme.gov", "name": "uptime_seconds", "value": 99},
        ],
    )
    _patch(monkeypatch, fake)
    nodes = await PuppetDbConnector(credential=CRED).nodes_with_facts()
    assert nodes[0]["facts"] == {"os": "RedHat", "ipaddress": "10.0.0.5"}
    assert "uptime_seconds" not in nodes[0]["facts"]


@pytest.mark.asyncio
async def test_facts_are_fetched_once_for_the_whole_fleet(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A thousand nodes must not be a thousand round trips."""
    fake = _Fake(nodes=NODES, facts=[])
    _patch(monkeypatch, fake)
    await PuppetDbConnector(credential=CRED).nodes_with_facts()
    assert len([c for c in fake.calls if "/facts" in c[0]]) == 1


@pytest.mark.asyncio
async def test_nodes_with_facts_is_empty_when_unconfigured() -> None:
    assert await PuppetDbConnector().nodes_with_facts() == []
