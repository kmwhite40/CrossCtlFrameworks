"""The PuppetDB connector: verify, scan, and the reads it deliberately skips."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from ccf.connectors import get_connector
from ccf.connectors import puppetdb as puppetdb_mod
from ccf.connectors.puppetdb import PuppetDbConnector
from ccf.posture.providers import puppetdb as checks
from ccf.posture.resolve import ResolvedCheck

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
    """Records the requests the connector makes.

    ``node_total``/``fact_total`` set the ``X-Records`` header PuppetDB sends
    when ``include_total=true`` is passed -- ``None`` (the default) omits the
    header entirely, matching a PuppetDB build that doesn't support it and
    leaving truncation undetectable, exactly as before this was added.
    ``body`` overrides the response with an arbitrary (non-list) payload.
    """

    def __init__(self, *, status: int = 200, nodes: list[dict] | None = None,
                 facts: list[dict] | None = None, body: Any = None,
                 node_total: int | None = None, fact_total: int | None = None) -> None:
        self.status = status
        self.nodes = nodes if nodes is not None else NODES
        self.facts = facts or []
        self.body = body
        self.node_total = node_total
        self.fact_total = fact_total
        self.calls: list[tuple[str, dict[str, Any] | None]] = []
        self.client_kwargs: dict[str, Any] = {}

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
        if self.body is not None:
            return httpx.Response(200, json=self.body, request=request)
        is_facts = "/facts" in url
        resp_body = self.facts if is_facts else self.nodes
        total = self.fact_total if is_facts else self.node_total
        resp_headers = {"X-Records": str(total)} if total is not None else {}
        return httpx.Response(200, json=resp_body, headers=resp_headers, request=request)


def _patch(monkeypatch: pytest.MonkeyPatch, fake: _Fake) -> None:
    def _make(**kwargs: Any) -> _Fake:
        fake.client_kwargs = kwargs
        return fake

    monkeypatch.setattr(puppetdb_mod.httpx, "AsyncClient", _make)


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


@pytest.mark.asyncio
async def test_scan_accepts_checks_by_keyword_like_the_base_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CRITICAL 1: the sole production caller is
    ``posture.scan.scan_for_system``, which calls ``conn.scan(checks=resolved)``
    by keyword (see tests/test_msgraph_declared_scan.py for the same call
    against msgraph). Before the fix, the parameter was named ``checks_``
    -- the module's own ``from ..posture.providers import puppetdb as checks``
    import shadowed the name a caller had to use -- so this call raised
    ``TypeError: scan() got an unexpected keyword argument 'checks'`` in
    production. Every other test in this file calls scan() or scan(())
    positionally, so none of them could have caught it.
    """
    fake = _Fake()
    _patch(monkeypatch, fake)
    resolved = tuple(
        ResolvedCheck(check=c, endpoint="/pdb/query/v4/nodes", source="platform")
        for c in checks.CHECKS
    )
    outcomes = await PuppetDbConnector(credential=CRED).scan(checks=resolved)
    assert {o.check_key for o in outcomes} == {c.key for c in checks.CHECKS}


# ── a 200 that is not a fleet ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_200_with_a_non_list_body_is_not_an_empty_fleet(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PuppetDB returns a JSON error object with a 200 for some malformed
    queries. Treating that as [] would roll up to not_applicable -- "no
    fleet" -- rather than "could not look"."""
    fake = _Fake(body={"error": "malformed AST query"})
    _patch(monkeypatch, fake)
    outcomes = await PuppetDbConnector(credential=CRED).scan()
    assert len(outcomes) == len(checks.CHECKS)
    for outcome in outcomes:
        assert outcome.verdict == "manual_review_required"


# ── truncation ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_fleet_larger_than_max_nodes_is_manual_review_not_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CRITICAL 2: a 6,200-node fleet read at the 5,000-node cap must never
    roll up to pass -- the unmanaged nodes could be exactly the ones sorted
    outside the page that was read."""
    fake = _Fake(nodes=NODES, node_total=6200)
    _patch(monkeypatch, fake)
    outcomes = await PuppetDbConnector(credential=CRED).scan()
    assert len(outcomes) == len(checks.CHECKS)
    for outcome in outcomes:
        assert outcome.verdict == "manual_review_required"
        assert "larger" in outcome.findings[0].observed.lower()


@pytest.mark.asyncio
async def test_a_fleet_within_max_nodes_is_not_flagged_truncated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _Fake(nodes=NODES, node_total=len(NODES))
    _patch(monkeypatch, fake)
    outcomes = await PuppetDbConnector(credential=CRED).scan()
    assert all(o.verdict != "manual_review_required" for o in outcomes)


@pytest.mark.asyncio
async def test_a_puppetdb_without_x_records_is_unaffected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An older PuppetDB (or a proxy that drops the header) sends no
    X-Records -- truncation is then undetectable, and scanning proceeds
    exactly as it did before this check existed, not worse."""
    fake = _Fake(nodes=NODES)
    _patch(monkeypatch, fake)
    outcomes = await PuppetDbConnector(credential=CRED).scan()
    assert all(o.verdict != "manual_review_required" for o in outcomes)


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


@pytest.mark.asyncio
async def test_the_facts_query_is_filtered_server_side(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """IMPORTANT 6: filtering in Python only after pulling every fact is what
    let the row cap start truncating around 300 nodes -- a real node carries
    200-500 facts. Filtering server-side means the cap is spent on facts
    actually worth keeping."""
    fake = _Fake(nodes=NODES, facts=[])
    _patch(monkeypatch, fake)
    await PuppetDbConnector(credential=CRED).nodes_with_facts()
    _, params = next(c for c in fake.calls if "/facts" in c[0])
    assert params is not None
    query = json.loads(params["query"])
    assert query[:2] == ["in", "name"]
    assert set(query[2]) == set(puppetdb_mod.INVENTORY_FACTS)


@pytest.mark.asyncio
async def test_nodes_with_facts_refuses_a_truncated_fact_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A truncated facts read must never silently populate -- and, on a later
    sync, overwrite -- props with a partial fact set."""
    fake = _Fake(
        nodes=[NODES[0]],
        facts=[{"certname": "web01.acme.gov", "name": "os", "value": "RedHat"}],
        fact_total=999_999,
    )
    _patch(monkeypatch, fake)
    with pytest.raises(puppetdb_mod.PuppetDbTruncatedError):
        await PuppetDbConnector(credential=CRED).nodes_with_facts()


# ── base_url validation ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_non_https_base_url_is_refused_before_any_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """IMPORTANT 5: the X-Authentication token must never reach a
    cleartext-HTTP request, and a cloud-metadata-shaped URL over plain http
    must not be treated any differently from one over https."""
    fake = _Fake()
    _patch(monkeypatch, fake)
    conn = PuppetDbConnector(
        credential={"base_url": "http://169.254.169.254", "token": "tok"}
    )
    outcomes = await conn.scan()
    assert len(outcomes) == len(checks.CHECKS)
    for outcome in outcomes:
        assert outcome.verdict == "manual_review_required"
        assert "https" in outcome.findings[0].detail["error"]
    assert fake.calls == [], "an invalid base_url must never reach a request"


def test_a_base_url_with_a_path_is_rejected() -> None:
    with pytest.raises(puppetdb_mod.PuppetDbConfigError):
        puppetdb_mod._validate_base_url("https://pdb.example.gov/extra/path")


def test_a_base_url_with_a_query_is_rejected() -> None:
    with pytest.raises(puppetdb_mod.PuppetDbConfigError):
        puppetdb_mod._validate_base_url("https://pdb.example.gov?x=1")


def test_a_base_url_with_no_host_is_rejected() -> None:
    with pytest.raises(puppetdb_mod.PuppetDbConfigError):
        puppetdb_mod._validate_base_url("https://")


def test_an_rfc1918_base_url_is_allowed() -> None:
    """Unlike ccf.packs.sync.validate_pack_source_url (whose shape this
    reuses), private/link-local hosts are NOT rejected: PuppetDB is normally
    an internal service, so banning RFC1918 here would reject exactly the
    deployments this connector exists to talk to."""
    puppetdb_mod._validate_base_url("https://10.0.0.5:8081")
    puppetdb_mod._validate_base_url("https://169.254.169.254")


@pytest.mark.asyncio
async def test_the_client_never_follows_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A hostile redirect must not carry the auth token off-host."""
    fake = _Fake()
    _patch(monkeypatch, fake)
    await PuppetDbConnector(credential=CRED).scan()
    assert fake.client_kwargs.get("follow_redirects") is False
