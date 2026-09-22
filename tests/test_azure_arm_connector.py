"""The Azure Government (ARM) config-capture connector.

Three things are under test and they are deliberately separable:

* **The contract.** ``is_configured()`` is False without this org's own
  credential, ``capture()`` returns ``[]`` rather than raising on *any*
  provider failure, ``scan()`` returns ``[]`` (no posture checks in this
  branch), and ``PARAMETER_MAP`` is populated even with no credential because
  ``api/routes/ssp.py`` shows it for an unconfigured connector.
* **The scope boundary.** ARM is infrastructure; Entra ID identity is
  ``msgraph``'s. Asserted as a real disjointness check between the two
  ``PARAMETER_MAP``s rather than trusted to a docstring, because the two
  connectors capture for the *same* Microsoft tenant and a collision would put
  two answers for one ODP into one SSP.
* **The wiring.** ``PLATFORM_CONNECTOR_KEYS["azure"]`` and the end-to-end
  consequence: an Azure project with a configured connector AND a fresh
  ``CaptureSnapshot`` loses the manual-evidence marker; without either, it
  keeps it (the rule that landed at 0eadea4 -- liveness is proved by the
  capture artifact, not by the status columns).

Every provider call is driven through a stubbed ``httpx`` transport against
recorded ARM response shapes, including the token POST -- no monkeypatched
``_token``, so "a token failure produces no captures" exercises the real OAuth
path rather than a stand-in for it. No live Azure tenant is touched.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, select

from ccf.config import get_settings
from ccf.connectors import connector_keys, get_connector, list_connectors
from ccf.connectors.azure_arm import ArmPaginationTruncatedError, AzureArmConnector
from ccf.connectors.msgraph import MsGraphConnector
from ccf.db import session_scope
from ccf.governance.automation import PLATFORM_TO_SSP, derive_system, generate_ssp
from ccf.models import (
    CaptureSnapshot,
    Organization,
    ScoringControl,
    SSPControlEntry,
    SSPProject,
    System,
    SystemProfile,
)
from ccf.models_grc import ConnectorConfig
from ccf.scoring.parser import load_seed
from ccf.ssp.platforms import (
    MANUAL_EVIDENCE_MARKER,
    MANUAL_EVIDENCE_NOTE,
    NO_TENANT_CAPTURE_NOTE,
    PLATFORM_CONNECTOR_KEYS,
)

CRED = {
    "tenant_id": "t-gov-1",
    "client_id": "c-gov-1",
    "client_secret": "s-gov-1",
    "subscription_id": "11111111-2222-3333-4444-555555555555",
}

#: An 800-171 requirement id ("3.13.16"), which is the namespace this connector
#: emits -- see the module docstring of ``ccf.connectors.azure_arm`` for the
#: measurement behind that choice.
_NIST_171 = re.compile(r"^\d+\.\d+\.\d+$")


# ── recorded ARM response shapes ────────────────────────────────────────────
#
# Trimmed to the fields the mappers read, with the *unhealthy* member kept in
# each collection: a fixture where every resource complies cannot tell a real
# fleet count from a hardcoded "all".

STORAGE_ACCOUNTS = {
    "value": [
        {
            "name": "cuistore01",
            "properties": {
                "encryption": {
                    "services": {"blob": {"enabled": True}, "file": {"enabled": True}},
                    "keySource": "Microsoft.Storage",
                },
                "supportsHttpsTrafficOnly": True,
                "minimumTlsVersion": "TLS1_2",
            },
        },
        {
            "name": "legacylogs",
            "properties": {
                "encryption": {
                    "services": {"blob": {"enabled": True}, "file": {"enabled": False}}
                },
                "supportsHttpsTrafficOnly": False,
                "minimumTlsVersion": "TLS1_0",
            },
        },
    ]
}

# Paginated on purpose: ARM's continuation key is ``nextLink``, Graph's is
# ``@odata.nextLink``, and a connector that read the wrong one would return
# page one and report it as the whole subscription.
WORKSPACES_PAGE_1 = {
    "value": [{"name": "law-prod", "properties": {"retentionInDays": 90}}],
    "nextLink": (
        "https://management.usgovcloudapi.net/subscriptions/"
        f"{CRED['subscription_id']}/providers/Microsoft.OperationalInsights/"
        "workspaces?api-version=2022-10-01&$skiptoken=PAGE2"
    ),
}
WORKSPACES_PAGE_2 = {
    "value": [{"name": "law-dev", "properties": {"retentionInDays": 30}}]
}

POLICY_ASSIGNMENTS = {
    "value": [
        {
            "name": "fedramp-h",
            "properties": {"displayName": "FedRAMP High", "enforcementMode": "Default"},
        },
        {
            "name": "tag-audit",
            "properties": {"displayName": "Audit tags", "enforcementMode": "DoNotEnforce"},
        },
    ]
}

SECURITY_PRICINGS = {
    "value": [
        {"name": "VirtualMachines", "properties": {"pricingTier": "Standard"}},
        {"name": "StorageAccounts", "properties": {"pricingTier": "Standard"}},
        {"name": "Containers", "properties": {"pricingTier": "Free"}},
    ]
}


def _default_handler(request: httpx.Request) -> httpx.Response:
    """Route a stubbed request to its recorded ARM (or token) response."""
    url = str(request.url)
    if request.method == "POST" and url.endswith("/oauth2/v2.0/token"):
        return httpx.Response(200, json={"access_token": "arm-token", "expires_in": 3599})
    if "Microsoft.Storage/storageAccounts" in url:
        return httpx.Response(200, json=STORAGE_ACCOUNTS)
    if "Microsoft.OperationalInsights/workspaces" in url:
        page = WORKSPACES_PAGE_2 if "PAGE2" in url else WORKSPACES_PAGE_1
        return httpx.Response(200, json=page)
    if "Microsoft.Authorization/policyAssignments" in url:
        return httpx.Response(200, json=POLICY_ASSIGNMENTS)
    if "Microsoft.Security/pricings" in url:
        return httpx.Response(200, json=SECURITY_PRICINGS)
    return httpx.Response(404, json={"error": {"code": "NotFound", "message": url}})


def _stub(
    monkeypatch: pytest.MonkeyPatch,
    handler: Callable[[httpx.Request], httpx.Response] = _default_handler,
) -> None:
    """Route every ``httpx.AsyncClient`` through ``handler``.

    The connector builds its own client, so the transport is injected by
    subclassing rather than passed in -- the pattern
    ``tests/test_msgraph_declared_scan.py`` already uses. The whole flow goes
    through it, token POST included.
    """

    class _MockedAsyncClient(httpx.AsyncClient):
        def __init__(self, *a: Any, **kw: Any) -> None:
            kw["transport"] = httpx.MockTransport(handler)
            super().__init__(*a, **kw)

    monkeypatch.setattr(httpx, "AsyncClient", _MockedAsyncClient)


def _by_key(caps: list[Any]) -> dict[str, Any]:
    return {c.odp_key: c for c in caps}


# ── 1/2/6: the base contract, with no credential ────────────────────────────


def test_is_configured_requires_the_whole_bundle_including_the_subscription() -> None:
    """A subscription id is not optional: every ARM read below is scoped to one.

    A credential without it authenticates perfectly well and can read nothing,
    which would report "configured" to the onboarding page and capture zero.
    """
    assert AzureArmConnector(credential=None).is_configured() is False
    assert AzureArmConnector(credential={}).is_configured() is False
    assert AzureArmConnector(credential={k: v for k, v in CRED.items() if k != "subscription_id"}) \
        .is_configured() is False
    assert AzureArmConnector(credential={k: v for k, v in CRED.items() if k != "client_secret"}) \
        .is_configured() is False
    assert AzureArmConnector(credential=CRED).is_configured() is True


async def test_unconfigured_captures_and_scans_nothing() -> None:
    conn = AzureArmConnector()
    assert conn.is_configured() is False
    assert await conn.capture() == []
    assert await conn.scan() == []
    assert await conn.scan(()) == []


async def test_unconfigured_capture_makes_no_network_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ``[]`` above must come from the credential check, not from a 404.

    Without this, the previous test would pass just as happily if
    ``is_configured()`` were ignored and every ARM call simply failed -- the
    "passes because the code path was never reached" trap in reverse.
    """
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return _default_handler(request)

    _stub(monkeypatch, handler)
    assert await AzureArmConnector().capture() == []
    assert calls == [], f"unconfigured capture reached the network: {calls}"


def test_parameter_map_is_populated_without_a_credential() -> None:
    """``api/routes/ssp.py`` returns ``PARAMETER_MAP`` for an unconfigured
    connector so the UI can show what it *would* pull."""
    conn = AzureArmConnector()
    assert conn.is_configured() is False
    assert conn.PARAMETER_MAP, "an unconfigured connector must still advertise its coverage"
    assert all(isinstance(v, str) and v for v in conn.PARAMETER_MAP.values())
    # And through the registry, the way the route reaches it.
    listed = {c.key: c for c in list_connectors()}
    assert listed["azure_arm"].PARAMETER_MAP == AzureArmConnector.PARAMETER_MAP


def test_the_registry_and_platform_mapping_know_about_azure() -> None:
    assert "azure_arm" in connector_keys()
    assert isinstance(get_connector("azure_arm"), AzureArmConnector)
    assert PLATFORM_CONNECTOR_KEYS["azure"] == "azure_arm"


# ── 8: the scope boundary, enforced ─────────────────────────────────────────


def test_parameter_map_is_disjoint_from_msgraph() -> None:
    """ARM and Graph capture for the SAME Microsoft tenant.

    A shared ODP key would produce two ``CaptureSnapshot`` rows competing for
    one ``(organization_id, connector, odp_key)`` slot and two different
    answers for one blank in one SSP. Asserted, not merely intended.
    """
    overlap = set(AzureArmConnector.PARAMETER_MAP) & set(MsGraphConnector.PARAMETER_MAP)
    assert overlap == set(), f"azure_arm and msgraph both claim {sorted(overlap)}"
    # The identity keys named in the module docstring are specifically absent.
    for identity_key in (
        "mfa_enforced",
        "nonlocal_maintenance_mfa",
        "session_termination_condition",
        "inactivity_period",
        "audit_retention_period",
        "password_generations_prohibited",
    ):
        assert identity_key not in AzureArmConnector.PARAMETER_MAP


# ── 5: what a real capture emits ────────────────────────────────────────────


async def test_capture_reads_every_recorded_source(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub(monkeypatch)
    caps = await AzureArmConnector(credential=CRED).capture()
    got = _by_key(caps)

    # The map and the emitted keys cannot drift apart: with every source
    # answering, the connector emits exactly what it advertises.
    assert set(got) == set(AzureArmConnector.PARAMETER_MAP)
    assert len(caps) == len(got), "one capture per ODP key -- no duplicate rows"

    # Fleet arithmetic, not a hardcoded verdict: 1 of the 2 recorded accounts
    # encrypts BOTH blob and file, and 1 of 2 requires HTTPS.
    assert got["encryption_at_rest"].value == (
        "1 of 2 storage accounts encrypt blob and file data at rest"
    )
    assert got["encryption_at_rest"].confidence == "medium"
    assert got["transmission_confidentiality"].value.startswith("1 of 2 storage accounts")
    assert "TLS1_0" in got["transmission_confidentiality"].value
    # Pagination followed: page 2's 30-day workspace is the shortest.
    assert got["log_retention_period"].value == "30 days"
    # The DoNotEnforce assignment is audit-only and must not be counted.
    assert got["configuration_baseline_enforcement"].value.startswith(
        "1 enforcing Azure Policy assignment(s)"
    )
    assert "FedRAMP High" in got["configuration_baseline_enforcement"].value
    assert "Audit tags" not in got["configuration_baseline_enforcement"].value
    # Free-tier plans are not protection.
    assert got["malicious_code_protection"].value == (
        "Microsoft Defender for Cloud enabled for StorageAccounts, VirtualMachines"
    )
    assert "Containers" not in got["malicious_code_protection"].value


async def test_every_capture_carries_a_joinable_800_171_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``nist_id`` is the join key that decides whether a capture is ever read.

    ``governance/automation.py`` keys ``caps_by_nist`` on it and matches
    ``SSPControlEntry.nist_id``, so a ``None`` or a wrong-namespace id is
    stored and silently never rendered.
    """
    _stub(monkeypatch)
    caps = await AzureArmConnector(credential=CRED).capture()
    assert caps
    for cap in caps:
        assert cap.nist_id, f"{cap.odp_key} would never reach a narrative"
        assert _NIST_171.match(cap.nist_id), (
            f"{cap.odp_key} emits {cap.nist_id!r}, not an 800-171 id -- "
            "an azure project's entries are 800-171 throughout"
        )
        assert cap.value, f"{cap.odp_key} captured an empty value"
        assert cap.odp_key in AzureArmConnector.PARAMETER_MAP
        assert cap.source, f"{cap.odp_key} has no stated origin"
        # The other namespace is carried, never emitted as a second nist_id.
        assert cap.detail["nist_80053_id"]
        assert not _NIST_171.match(cap.detail["nist_80053_id"])


async def test_captured_nist_ids_are_real_800_171_practices(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """And they exist in the catalogue an Azure project is actually seeded from.

    A well-formed id for a practice that does not exist joins to nothing, which
    is indistinguishable from a capture that was never made. Checked against
    the shipped CMMC seed -- the source ``ScoringControl`` rows are loaded from
    and the source ``ssp/seed.py`` copies ``nist_id`` out of -- rather than
    against whatever happens to be in the test database.
    """
    _stub(monkeypatch)
    caps = await AzureArmConnector(credential=CRED).capture()
    emitted = {c.nist_id for c in caps}
    catalogue = {rec.get("nist_id") for rec in load_seed()}
    assert len(catalogue) > 100, "the CMMC seed did not load"
    assert emitted <= catalogue, f"no 800-171 practice for {sorted(emitted - catalogue)}"


# ── 3/4: capture never raises ───────────────────────────────────────────────


async def test_token_failure_produces_no_captures(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 401 from the token endpoint yields ``[]``, not an exception.

    Driven through the real ``_token`` over the stubbed transport, so this
    fails if the OAuth call stops raising for a rejected client secret.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(401, json={"error": "invalid_client"})
        raise AssertionError("no ARM call may be made without a token")

    _stub(monkeypatch, handler)
    assert await AzureArmConnector(credential=CRED).capture() == []


async def test_a_token_response_without_an_access_token_produces_no_captures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HTTP 200 with a body that carries no token is still no token."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(200, json={"token_type": "Bearer"})
        raise AssertionError("no ARM call may be made without a token")

    _stub(monkeypatch, handler)
    assert await AzureArmConnector(credential=CRED).capture() == []


@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(lambda r: httpx.Response(403, json={"error": "Forbidden"}), id="403"),
        pytest.param(lambda r: httpx.Response(500, text="boom"), id="500"),
        pytest.param(lambda r: httpx.Response(200, text="<html>not json</html>"), id="malformed"),
        pytest.param(
            lambda r: (_ for _ in ()).throw(httpx.ConnectTimeout("timed out")), id="timeout"
        ),
        pytest.param(
            lambda r: (_ for _ in ()).throw(httpx.ConnectError("refused")), id="transport"
        ),
    ],
)
async def test_one_failing_source_degrades_to_partial_results_never_an_exception(
    monkeypatch: pytest.MonkeyPatch, failure: Callable[[httpx.Request], httpx.Response]
) -> None:
    """A gap on one ARM provider must not discard the sources that did answer.

    A service principal with Reader on storage but nothing on
    ``Microsoft.Security`` is the ordinary case, not the exotic one.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        if "Microsoft.Security/pricings" in str(request.url):
            return failure(request)
        return _default_handler(request)

    _stub(monkeypatch, handler)
    caps = await AzureArmConnector(credential=CRED).capture()
    got = _by_key(caps)
    assert "malicious_code_protection" not in got, "a failed read must not emit a value"
    assert set(got) == set(AzureArmConnector.PARAMETER_MAP) - {"malicious_code_protection"}


async def test_every_source_failing_yields_an_empty_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(200, json={"access_token": "arm-token"})
        raise httpx.ReadTimeout("timed out")

    _stub(monkeypatch, handler)
    assert await AzureArmConnector(credential=CRED).capture() == []


async def test_an_empty_subscription_captures_nothing_rather_than_a_false_all(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No resources is not "everything complies"."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(200, json={"access_token": "arm-token"})
        return httpx.Response(200, json={"value": []})

    _stub(monkeypatch, handler)
    assert await AzureArmConnector(credential=CRED).capture() == []


# ── transport guards ────────────────────────────────────────────────────────


async def test_capture_follows_arm_nextlink_and_not_the_odata_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ARM paginates with ``nextLink``; ``@odata.nextLink`` is Graph's.

    A connector that read Graph's key would stop at page one and report a
    90-day retention for a subscription whose shortest workspace keeps 30.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if request.method == "POST":
            return httpx.Response(200, json={"access_token": "arm-token"})
        if "Microsoft.OperationalInsights/workspaces" not in url:
            return httpx.Response(200, json={"value": []})
        if "PAGE2" in url:
            return httpx.Response(200, json=WORKSPACES_PAGE_2)
        # Both keys present, pointing at DIFFERENT pages: reading the Graph one
        # lands on a workspace that would flip the answer.
        return httpx.Response(
            200,
            json={
                **WORKSPACES_PAGE_1,
                "@odata.nextLink": WORKSPACES_PAGE_1["nextLink"].replace("PAGE2", "ODATA"),
            },
        )

    _stub(monkeypatch, handler)
    caps = _by_key(await AzureArmConnector(credential=CRED).capture())
    assert caps["log_retention_period"].value == "30 days"


async def test_an_off_host_nextlink_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """``nextLink`` comes from a response body and following it carries the
    org's ARM bearer token, so a host change must stop the fetch."""
    reached: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        reached.append(request.url.host)
        if request.method == "POST":
            return httpx.Response(200, json={"access_token": "arm-token"})
        if "Microsoft.Storage/storageAccounts" in str(request.url):
            return httpx.Response(
                200,
                json={
                    **STORAGE_ACCOUNTS,
                    "nextLink": "https://attacker.example/steal?api-version=2023-01-01",
                },
            )
        return httpx.Response(200, json={"value": []})

    _stub(monkeypatch, handler)
    caps = await AzureArmConnector(credential=CRED).capture()
    assert "attacker.example" not in reached, "the bearer token was sent off-host"
    # The refused source contributes nothing; the rest of the run is unharmed.
    assert "encryption_at_rest" not in _by_key(caps)


async def test_pagination_stops_rather_than_returning_a_partial_subscription() -> None:
    """A self-referential ``nextLink`` raises instead of spinning or truncating.

    Raised inside ``_get_all``, which ``capture()`` then swallows per source --
    tested at the helper so the assertion is about the guard itself and not
    about ``capture()``'s outer ``except`` happening to catch something.
    """
    conn = AzureArmConnector(credential=CRED)
    path = conn._sub_path("providers/Microsoft.Storage/storageAccounts", "2023-01-01")
    loop = f"{get_settings().arm_base_url}{path}&$skiptoken=LOOP"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"value": [{"name": "s"}], "nextLink": loop})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ArmPaginationTruncatedError):
            await conn._get_all(client, path, {})


async def test_verify_reports_the_endpoint_it_reached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub(monkeypatch)
    result = await AzureArmConnector(credential=CRED).verify()
    assert result["connected"] is True
    assert result["subscription"] == CRED["subscription_id"]
    assert result["arm_endpoint"] == get_settings().arm_base_url

    assert (await AzureArmConnector().verify())["connected"] is False


# ── 7: the end-to-end consequence for an Azure project ──────────────────────

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@asynccontextmanager
async def _azure_tenant(
    name: str,
    prefix: str,
    *,
    connector_type: str | None = None,
    captured_at: datetime | None = None,
) -> AsyncIterator[list[SSPControlEntry]]:
    """One Azure Gov org + system, optionally with a real ``ConnectorConfig``
    and a real ``CaptureSnapshot``, run through the production SSP path.

    The snapshot's ``nist_id`` is left NULL deliberately: a capture keyed to one
    of the seeded controls would be rendered into the narrative, and a fixture
    that supplies the text under assertion proves nothing. What is under test
    here is the *caveat*, which must turn on the artifact's existence alone.

    ``ScoringControl`` is a GLOBAL table, so the prefixed rows this inserts are
    always deleted again in ``finally`` or they leak into every later test.
    """
    control_ids = [f"AC.{prefix}-3.1.1", f"PE.{prefix}-3.10.1"]
    org_id: int | None = None
    proj_id: int | None = None
    try:
        async with session_scope() as session:
            org = Organization(name=name)
            session.add(org)
            await session.flush()
            org_id = org.id
            sysrow = System(organization_id=org.id, name=f"{name} system")
            session.add(sysrow)
            await session.flush()
            session.add_all(
                [
                    ScoringControl(
                        control_id=control_ids[0],
                        nist_id=f"AC-{prefix}-1",
                        domain="AC",
                        title="Access Control",
                        point_value="5",
                        requirement="limit system access to authorized users",
                        m365_coverage_status="Customer Responsibility",
                        sort_order=1,
                    ),
                    ScoringControl(
                        control_id=control_ids[1],
                        nist_id=f"PE-{prefix}-1",
                        domain="PE",
                        title="Physical Access",
                        point_value="1",
                        requirement="limit physical access to organizational systems",
                        m365_coverage_status="Microsoft Coverage",
                        sort_order=2,
                    ),
                ]
            )
            await session.flush()
            if connector_type is not None:
                session.add(
                    ConnectorConfig(
                        organization_id=org.id,
                        name=f"{name} connector",
                        connector_type=connector_type,
                        status="configured",
                        last_sync=datetime.now(UTC),
                        objects_discovered=12,
                    )
                )
                if captured_at is not None:
                    session.add(
                        CaptureSnapshot(
                            organization_id=org.id,
                            connector=connector_type,
                            odp_key="encryption_at_rest",
                            value="2 of 2 storage accounts encrypt blob and file data at rest",
                            captured_at=captured_at,
                        )
                    )
                await session.flush()
            profile = SystemProfile(
                system_id=sysrow.id, environment_type="cloud", cloud_platform="azure_gov"
            )
            session.add(profile)
            await session.flush()
            await derive_system(
                session,
                system_id=sysrow.id,
                org_id=sysrow.organization_id,
                profile=profile,
                create_poams=False,
            )
            proj_id = await generate_ssp(session, system=sysrow, profile=profile)
            entries = list(
                (
                    await session.execute(
                        select(SSPControlEntry).where(SSPControlEntry.project_id == proj_id)
                    )
                )
                .scalars()
                .all()
            )
        yield entries
    finally:
        async with session_scope() as session:
            await session.execute(
                delete(ScoringControl).where(ScoringControl.control_id.in_(control_ids))
            )
            if proj_id is not None:
                await session.execute(delete(SSPProject).where(SSPProject.id == proj_id))
            if org_id is not None:
                await session.execute(delete(Organization).where(Organization.id == org_id))


def _texts(entries: list[SSPControlEntry]) -> dict[str, str]:
    return {
        e.control_id: "\n".join((p.get("text") or "") for p in e.part_narratives or [])
        for e in entries
    }


def test_azure_gov_maps_to_the_ssp_azure_platform() -> None:
    """The precondition the DB tests below rest on, pinned separately so a
    failure there is not misread as a connector problem."""
    assert PLATFORM_TO_SSP["azure_gov"] == "azure"


async def test_an_azure_tenant_with_a_live_arm_capture_loses_the_marker() -> None:
    """A configured ``azure_arm`` connector AND a fresh capture artifact.

    This is the whole point of the branch: before it, no combination of
    configuration could clear an Azure statement, because the platform had no
    connector at all.
    """
    async with _azure_tenant(
        "Azure Live Capture Org",
        "AZLIVE",
        connector_type="azure_arm",
        captured_at=datetime.now(UTC),
    ) as entries:
        assert entries, "expected seeded SSP entries"
        for control_id, text in _texts(entries).items():
            assert MANUAL_EVIDENCE_MARKER not in text, (
                f"{control_id} still flagged with a live Azure capture: {text!r}"
            )


async def test_an_azure_tenant_with_no_connector_row_keeps_the_marker() -> None:
    """And the reason stated is now the true one: Concord ships an Azure
    connector, this tenant has simply never captured with it."""
    async with _azure_tenant("Azure No Connector Org", "AZNONE") as entries:
        assert entries
        for control_id, text in _texts(entries).items():
            assert NO_TENANT_CAPTURE_NOTE in text, f"{control_id} unflagged: {text!r}"
            assert MANUAL_EVIDENCE_NOTE not in text, (
                f"{control_id} claims Concord ships no Azure connector, which is now false"
            )


async def test_status_columns_without_a_capture_artifact_do_not_clear_the_marker() -> None:
    """The rule that landed at 0eadea4: liveness is proved by the artifact.

    The connector row here is ``configured``, freshly synced and reports twelve
    discovered objects -- exactly what the credential-free mock sync route
    writes -- and it must not be enough.
    """
    async with _azure_tenant(
        "Azure Mock Sync Org", "AZMOCK", connector_type="azure_arm", captured_at=None
    ) as entries:
        assert entries
        for control_id, text in _texts(entries).items():
            assert NO_TENANT_CAPTURE_NOTE in text, (
                f"{control_id} cleared by status columns alone: {text!r}"
            )


async def test_a_stale_capture_artifact_does_not_clear_the_marker() -> None:
    async with _azure_tenant(
        "Azure Stale Capture Org",
        "AZSTALE",
        connector_type="azure_arm",
        captured_at=datetime.now(UTC) - timedelta(days=400),
    ) as entries:
        assert entries
        for control_id, text in _texts(entries).items():
            assert NO_TENANT_CAPTURE_NOTE in text, f"{control_id} cleared by a stale capture"


async def test_a_graph_capture_does_not_evidence_the_azure_platform() -> None:
    """The scope boundary, end to end.

    ``msgraph`` and ``azure_arm`` authenticate against the same Microsoft
    tenant, so a healthy Graph connector is the most plausible way an Azure
    infrastructure claim could get evidenced by something that never looked at
    the infrastructure. It must not.
    """
    async with _azure_tenant(
        "Azure Graph Only Org",
        "AZGRAPH",
        connector_type="msgraph",
        captured_at=datetime.now(UTC),
    ) as entries:
        assert entries
        for control_id, text in _texts(entries).items():
            assert NO_TENANT_CAPTURE_NOTE in text, (
                f"{control_id} evidenced by an identity-only capture: {text!r}"
            )
