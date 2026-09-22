"""A connector must emit exactly what its ``PARAMETER_MAP`` advertises.

``connectors/base.py`` defines ``PARAMETER_MAP`` as what a connector *would*
pull even before credentials are configured, and ``api/routes/ssp.py`` returns
it for an unconfigured connector so the UI can show it. That makes it a claim
made to an operator about the product -- and nothing asserted it was true.

It was not. ``aws_govcloud`` advertised six ODP keys and emitted two;
``msgraph`` advertised six and emitted two. Ten of those twelve advertisements
described no code. Worse, one of the two AWS captures that *did* run emitted
``nist_id="SC-28"``, and ``nist_id`` is the join key
``governance/automation.py`` matches against ``SSPControlEntry.nist_id``: every
AWS project's entries are 800-171 throughout, so the EBS-encryption value was
read from the account, stored, and silently discarded at the join on every run.

Four things are under test here, and they are deliberately separable:

* **Parity**, per connector, behaviourally: drive ``capture()`` with every
  source answering and assert the emitted ``odp_key`` set equals the map's keys.
* **The AWS capture now renders**: an ``aws_govcloud`` project seeded with the
  namespace its entries really carry receives the encryption value in its
  narrative -- and does not receive it under the id the connector used to emit.
* **The map survives the shrink**: the unconfigured-connector UI path still gets
  a populated map from every connector, through the registry the route uses.
* **No accidental key sharing** between connectors.

Why this is behavioural and not a source scan
---------------------------------------------
A grep for ``odp_key="..."`` literals is the obvious way to write this guard and
it is wrong. ``azure_arm`` (and now ``aws``) construct every
``CapturedParameter`` through a ``_captured(odp_key, ...)`` helper, so a literal
scan reports them as emitting **nothing** and the guard passes them vacuously --
a harness that cannot fail. Only running ``capture()`` and reading ``odp_key``
off the returned objects is immune to how the object was constructed;
``test_a_source_text_scan_would_be_blind_to_two_connectors`` pins that the naive
form really would be fooled, so nobody "simplifies" this file back into one.

Every provider call is stubbed. No live tenant, account or subscription is
touched: Graph and ARM run over an ``httpx.MockTransport`` including the token
POST, and AWS runs over a fake ``boto3`` session injected at ``_session`` -- the
single integration seam ``connectors/aws.py`` documents.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, select

from ccf.config import get_settings
from ccf.connectors import list_connectors
from ccf.connectors.aws import AwsGovCloudConnector
from ccf.connectors.azure_arm import AzureArmConnector
from ccf.connectors.base import ConfigConnector
from ccf.connectors.msgraph import MsGraphConnector
from ccf.db import session_scope
from ccf.governance.automation import (
    PLATFORM_TO_SSP,
    derive_system,
    generate_ssp,
    generate_statements,
)
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

#: An 800-171 requirement id ("3.13.16"), the namespace every connector here
#: emits -- see each connector's module docstring for the measurement.
_NIST_171 = re.compile(r"^\d+\.\d+\.\d+$")


# ── stubbed transports ──────────────────────────────────────────────────────
#
# Each fixture makes EVERY source of its connector answer. That is the whole
# point: parity can only be measured on a run where nothing is missing, or a
# connector that lost a sub-capture would look identical to one whose provider
# was merely unreachable.


def _graph_handler(request: httpx.Request) -> httpx.Response:
    """Token POST + the one Conditional Access read ``msgraph.capture`` makes."""
    url = str(request.url)
    if request.method == "POST" and url.endswith("/oauth2/v2.0/token"):
        return httpx.Response(200, json={"access_token": "graph-token", "expires_in": 3599})
    if "/identity/conditionalAccess/policies" in url:
        return httpx.Response(
            200,
            json={
                "value": [
                    # Disabled, and it would satisfy both mappers if it were
                    # read -- a fixture whose every member is usable cannot
                    # tell a mapper that filters from one that does not.
                    {
                        "id": "pol-off",
                        "displayName": "Legacy (reporting only)",
                        "state": "disabled",
                        "grantControls": {"builtInControls": ["mfa"]},
                        "sessionControls": {
                            "signInFrequency": {
                                "isEnabled": True,
                                "value": 99,
                                "type": "hours",
                            }
                        },
                    },
                    {
                        "id": "pol-mfa",
                        "displayName": "Require MFA for all users",
                        "state": "enabled",
                        "grantControls": {"builtInControls": ["mfa"]},
                    },
                    {
                        "id": "pol-freq",
                        "displayName": "Re-authenticate hourly",
                        "state": "enabled",
                        "sessionControls": {
                            "signInFrequency": {
                                "isEnabled": True,
                                "value": 15,
                                "type": "minutes",
                            }
                        },
                    },
                ]
            },
        )
    return httpx.Response(404, json={"error": {"code": "unknownPath", "message": url}})


_ARM_SUB = "11111111-2222-3333-4444-555555555555"


def _arm_handler(request: httpx.Request) -> httpx.Response:
    """Token POST + one recorded response per ARM provider ``capture()`` reads."""
    url = str(request.url)
    if request.method == "POST" and url.endswith("/oauth2/v2.0/token"):
        return httpx.Response(200, json={"access_token": "arm-token", "expires_in": 3599})
    if "Microsoft.Storage/storageAccounts" in url:
        return httpx.Response(
            200,
            json={
                "value": [
                    {
                        "name": "cuistore01",
                        "properties": {
                            "encryption": {
                                "services": {
                                    "blob": {"enabled": True},
                                    "file": {"enabled": True},
                                }
                            },
                            "supportsHttpsTrafficOnly": True,
                            "minimumTlsVersion": "TLS1_2",
                        },
                    }
                ]
            },
        )
    if "Microsoft.OperationalInsights/workspaces" in url:
        return httpx.Response(
            200, json={"value": [{"name": "law-prod", "properties": {"retentionInDays": 90}}]}
        )
    if "Microsoft.Authorization/policyAssignments" in url:
        return httpx.Response(
            200,
            json={
                "value": [
                    {
                        "name": "fedramp-h",
                        "properties": {
                            "displayName": "FedRAMP High",
                            "enforcementMode": "Default",
                        },
                    }
                ]
            },
        )
    if "Microsoft.Security/pricings" in url:
        return httpx.Response(
            200,
            json={
                "value": [{"name": "VirtualMachines", "properties": {"pricingTier": "Standard"}}]
            },
        )
    return httpx.Response(404, json={"error": {"code": "NotFound", "message": url}})


def _stub_httpx(
    monkeypatch: pytest.MonkeyPatch, handler: Callable[[httpx.Request], httpx.Response]
) -> None:
    """Route every ``httpx.AsyncClient`` through ``handler``.

    Both connectors build their own client, so the transport is injected by
    subclassing rather than passed in -- the pattern
    ``tests/test_azure_arm_connector.py`` already uses. The token POST goes
    through it too, so no ``_token`` is monkeypatched out.
    """

    class _MockedAsyncClient(httpx.AsyncClient):
        def __init__(self, *a: Any, **kw: Any) -> None:
            kw["transport"] = httpx.MockTransport(handler)
            super().__init__(*a, **kw)

    monkeypatch.setattr(httpx, "AsyncClient", _MockedAsyncClient)


class _FakeLogsPaginator:
    def paginate(self) -> Any:
        # A group with no retention (AWS's "never expire") is kept in the
        # fixture: the reader must skip it rather than read it as 0 days.
        return iter(
            [
                {"logGroups": [{"logGroupName": "/aws/lambda/a", "retentionInDays": 365}]},
                {
                    "logGroups": [
                        {"logGroupName": "/aws/ecs/b", "retentionInDays": 90},
                        {"logGroupName": "/aws/ecs/never"},
                    ]
                },
            ]
        )


class _FakeLogsClient:
    def get_paginator(self, name: str) -> _FakeLogsPaginator:
        assert name == "describe_log_groups", f"unexpected paginator {name!r}"
        return _FakeLogsPaginator()


class _FakeEc2Client:
    def get_ebs_encryption_by_default(self) -> dict[str, Any]:
        return {"EbsEncryptionByDefault": True}


class _FakeBotoSession:
    """The object ``AwsGovCloudConnector._session()`` returns, stubbed.

    ``_session`` is the connector's documented integration seam -- the one
    place boto3 is constructed -- so replacing it exercises ``capture()``, its
    per-sub-capture isolation and the real ``CapturedParameter`` construction
    while touching no AWS account.
    """

    def __init__(self) -> None:
        self.clients: list[str] = []

    def client(self, name: str, region_name: str | None = None) -> Any:
        self.clients.append(name)
        if name == "logs":
            return _FakeLogsClient()
        if name == "ec2":
            return _FakeEc2Client()
        raise AssertionError(f"capture() asked for an unstubbed AWS client: {name!r}")


def _aws_connector(monkeypatch: pytest.MonkeyPatch) -> AwsGovCloudConnector:
    """A configured AWS connector whose every source answers."""
    monkeypatch.setattr(AwsGovCloudConnector, "_boto3_available", lambda self: True)
    monkeypatch.setattr(AwsGovCloudConnector, "_session", lambda self: _FakeBotoSession())
    monkeypatch.setenv("CCF_AWS_CAPTURE_ENABLED", "true")
    get_settings.cache_clear()
    return AwsGovCloudConnector(
        credential={"access_key_id": "AKIAEXAMPLE", "secret_access_key": "shh"}
    )


def _msgraph_connector(monkeypatch: pytest.MonkeyPatch) -> MsGraphConnector:
    _stub_httpx(monkeypatch, _graph_handler)
    return MsGraphConnector(
        credential={"tenant_id": "t-1", "client_id": "c-1", "client_secret": "s-1"}
    )


def _azure_arm_connector(monkeypatch: pytest.MonkeyPatch) -> AzureArmConnector:
    _stub_httpx(monkeypatch, _arm_handler)
    return AzureArmConnector(
        credential={
            "tenant_id": "t-gov-1",
            "client_id": "c-gov-1",
            "client_secret": "s-gov-1",
            "subscription_id": _ARM_SUB,
        }
    )


#: connector key → a builder returning a configured instance with every source
#: answering. A connector with a ``PARAMETER_MAP`` and no entry here fails
#: ``test_every_connector_with_a_parameter_map_is_covered_by_the_guard``, so the
#: guard cannot be escaped by adding a connector.
HARNESSES: dict[str, Callable[[pytest.MonkeyPatch], ConfigConnector]] = {
    "aws_govcloud": _aws_connector,
    "msgraph": _msgraph_connector,
    "azure_arm": _azure_arm_connector,
}


@pytest.fixture(autouse=True)
def _restore_settings_cache() -> Any:
    """``_aws_connector`` sets a feature-flag env var read through an lru_cache."""
    yield
    get_settings.cache_clear()


# ── 1: the parity guard ─────────────────────────────────────────────────────


def test_every_connector_with_a_parameter_map_is_covered_by_the_guard() -> None:
    """A new connector cannot quietly opt out of parity.

    Read off the registry ``api/routes/ssp.py`` itself iterates, so a connector
    that ships a ``PARAMETER_MAP`` without a harness here fails rather than
    simply not being tested -- the failure mode this whole file exists for.
    """
    advertising = {c.key for c in list_connectors() if c.PARAMETER_MAP}
    assert advertising == set(HARNESSES), (
        "connectors advertising a PARAMETER_MAP with no parity harness: "
        f"{sorted(advertising - set(HARNESSES))}; harnesses for connectors that "
        f"no longer advertise one: {sorted(set(HARNESSES) - advertising)}"
    )


@pytest.mark.parametrize("key", sorted(HARNESSES))
async def test_a_connector_emits_exactly_what_it_advertises(
    key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The root-cause guard: ``PARAMETER_MAP`` is a claim, so it is measured.

    Behavioural by construction -- the emitted keys are read off the objects
    ``capture()`` returned, never off the source text, so it holds whether a
    connector builds ``CapturedParameter`` with literal kwargs (``msgraph``) or
    through a helper (``aws``, ``azure_arm``).
    """
    conn = HARNESSES[key](monkeypatch)
    advertised = set(type(conn).PARAMETER_MAP)
    assert advertised, f"{key} must advertise something for this guard to mean anything"
    assert conn.is_configured() is True, f"{key}'s harness did not produce a usable credential"

    caps = await conn.capture()
    assert caps, f"{key} captured nothing -- the harness is not driving its sources"
    emitted = {c.odp_key for c in caps}

    assert emitted == advertised, (
        f"{key} advertises {sorted(advertised)} but emits {sorted(emitted)}; "
        f"advertised and never captured: {sorted(advertised - emitted)}; "
        f"captured and never advertised: {sorted(emitted - advertised)}"
    )
    assert len(caps) == len(emitted), f"{key} emitted duplicate rows for one ODP key"


@pytest.mark.parametrize("key", sorted(HARNESSES))
async def test_every_capture_carries_a_joinable_800_171_id(
    key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``nist_id`` decides whether a capture is ever read.

    ``governance/automation.py`` keys ``caps_by_nist`` on it and matches
    ``SSPControlEntry.nist_id``; ``api/routes/ssp.py``'s autofill builds
    ``by_nist`` the same way. Every project of every platform that has a
    connector carries 800-171 ids, so a ``None`` or an 800-53 id here is stored
    and silently never rendered -- exactly what ``encryption_at_rest`` did.
    """
    conn = HARNESSES[key](monkeypatch)
    caps = await conn.capture()
    assert caps
    for cap in caps:
        assert cap.nist_id, f"{key}/{cap.odp_key} would never reach a narrative"
        assert _NIST_171.match(cap.nist_id), (
            f"{key}/{cap.odp_key} emits {cap.nist_id!r}, not an 800-171 id -- "
            "no project of a connector-backed platform carries 800-53 ids"
        )
        assert cap.value, f"{key}/{cap.odp_key} captured an empty value"
        assert cap.source, f"{key}/{cap.odp_key} has no stated origin"


def test_a_source_text_scan_would_be_blind_to_two_connectors() -> None:
    """Why the guard above runs ``capture()`` instead of grepping.

    ``aws`` and ``azure_arm`` construct every ``CapturedParameter`` through a
    ``_captured(odp_key, ...)`` helper. A guard built on scanning for
    ``odp_key="..."`` literals would find none for either, conclude they emit
    nothing, and pass vacuously -- a harness that cannot fail. Pinned as a fact
    about these files so the behavioural form is not "simplified" away.
    """
    literal = re.compile(r'odp_key\s*=\s*"([a-z0-9_]+)"')
    root = Path(__file__).resolve().parents[1] / "src" / "ccf" / "connectors"
    scanned = {
        key: set(literal.findall((root / f"{module}.py").read_text()))
        for key, module in (
            ("aws_govcloud", "aws"),
            ("azure_arm", "azure_arm"),
            ("msgraph", "msgraph"),
        )
    }
    assert scanned["aws_govcloud"] == set(), "aws no longer builds captures through a helper"
    assert scanned["azure_arm"] == set(), "azure_arm no longer builds captures through a helper"
    # msgraph does use literals -- which is precisely what makes a scan look
    # like it works, on one connector out of three.
    assert scanned["msgraph"] == set(MsGraphConnector.PARAMETER_MAP)


# ── 3: the shrunk map still reaches the UI ──────────────────────────────────


@pytest.mark.parametrize("key", sorted(HARNESSES))
def test_an_unconfigured_connector_still_advertises_a_populated_map(key: str) -> None:
    """``api/routes/ssp.py`` returns ``PARAMETER_MAP`` for an unconfigured
    connector (``GET /connectors`` and the ``autofill`` early return) so the UI
    can show what it would pull. Removing the four false AWS claims and the
    four false Graph ones must not empty the map and blank that screen.
    """
    listed = {c.key: c for c in list_connectors()}
    conn = listed[key]
    assert conn.is_configured() is False, "no credential is bound in a bare registry instance"
    assert conn.PARAMETER_MAP, f"{key} would show an empty coverage list to an operator"
    assert all(isinstance(v, str) and v for v in conn.PARAMETER_MAP.values())


# ── 4: no accidental key sharing ────────────────────────────────────────────

#: The one ODP key two connectors may both claim, and why.
#:
#: ``aws_govcloud`` and ``azure_arm`` capture different clouds: an SSP project
#: declares exactly one platform, so only one of them can ever be the connector
#: for a given project, and ``CaptureSnapshot``'s unique key is
#: ``(organization_id, connector, odp_key)`` -- two connectors are two rows, not
#: a collision. An organization running both clouds gets both values rendered,
#: each attributed to the connector that read it ("captured from aws_govcloud"),
#: which is two measurements honestly labelled rather than one blank with two
#: competing answers.
#:
#: That is NOT true of ``msgraph`` and ``azure_arm``, which capture the SAME
#: Microsoft tenant -- see ``connectors/azure_arm.py``'s scope boundary. They
#: must share nothing, and the assertion below holds them to it.
DELIBERATE_OVERLAPS: dict[frozenset[str], set[str]] = {
    frozenset({"aws_govcloud", "azure_arm"}): {"encryption_at_rest"},
}


def test_no_two_connectors_advertise_the_same_key_by_accident() -> None:
    maps = {c.key: set(c.PARAMETER_MAP) for c in list_connectors() if c.PARAMETER_MAP}
    found: dict[frozenset[str], set[str]] = {}
    for a in sorted(maps):
        for b in sorted(maps):
            if a >= b:
                continue
            shared = maps[a] & maps[b]
            if shared:
                found[frozenset({a, b})] = shared
    undeclared = sorted(
        (sorted(pair), sorted(shared))
        for pair, shared in found.items()
        if found.get(pair) != DELIBERATE_OVERLAPS.get(pair)
    )
    missing = sorted(
        (sorted(pair), sorted(shared))
        for pair, shared in DELIBERATE_OVERLAPS.items()
        if found.get(pair) != shared
    )
    assert found == DELIBERATE_OVERLAPS, (
        f"ODP key sharing that is not declared deliberate: {undeclared}; "
        f"declared overlaps that no longer exist (delete the entry): {missing}"
    )


def test_msgraph_and_azure_arm_stay_disjoint() -> None:
    """The one overlap that is never acceptable, stated on its own.

    They authenticate against the same Microsoft tenant, so a shared key means
    two ``CaptureSnapshot`` rows filling one SSP blank with two different
    answers. Kept separate from the table above so this cannot be made to pass
    by adding an entry to ``DELIBERATE_OVERLAPS``.
    """
    overlap = set(MsGraphConnector.PARAMETER_MAP) & set(AzureArmConnector.PARAMETER_MAP)
    assert overlap == set(), f"msgraph and azure_arm both claim {sorted(overlap)}"


# ── 2: the AWS capture now reaches the document ─────────────────────────────

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@asynccontextmanager
async def _aws_tenant(name: str, prefix: str) -> AsyncIterator[tuple[int, int]]:
    """One AWS GovCloud org + system + SSP project, via the production path.

    The seeded controls carry the ``nist_id``s an AWS project really has --
    measured, 800-171 throughout -- so the join under test is the product's own
    and not one the fixture arranged to succeed.

    ``ScoringControl`` is a GLOBAL table, so the prefixed rows inserted here are
    always deleted again in ``finally`` or they leak into every later test.
    """
    control_ids = [f"SC.{prefix}-3.13.16", f"AU.{prefix}-3.3.1"]
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
                        nist_id="3.13.16",
                        domain="SC",
                        title="Protection of CUI at Rest",
                        point_value="5",
                        requirement="protect the confidentiality of CUI at rest",
                        m365_coverage_status="Customer Responsibility",
                        sort_order=1,
                    ),
                    ScoringControl(
                        control_id=control_ids[1],
                        nist_id="3.3.1",
                        domain="AU",
                        title="Audit Record Retention",
                        point_value="5",
                        requirement="create and retain system audit records",
                        m365_coverage_status="Customer Responsibility",
                        sort_order=2,
                    ),
                ]
            )
            await session.flush()
            session.add(
                ConnectorConfig(
                    organization_id=org.id,
                    name=f"{name} connector",
                    connector_type="aws_govcloud",
                    status="configured",
                    last_sync=datetime.now(UTC),
                    objects_discovered=12,
                )
            )
            profile = SystemProfile(
                system_id=sysrow.id, environment_type="cloud", cloud_platform="aws_govcloud"
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
        yield org_id, proj_id
    finally:
        async with session_scope() as session:
            await session.execute(
                delete(ScoringControl).where(ScoringControl.control_id.in_(control_ids))
            )
            if proj_id is not None:
                await session.execute(delete(SSPProject).where(SSPProject.id == proj_id))
            if org_id is not None:
                await session.execute(delete(Organization).where(Organization.id == org_id))


async def _render_with_snapshot(
    org_id: int, proj_id: int, *, control_id: str, odp_key: str, value: str, nist_id: str
) -> str:
    """Store one capture under ``nist_id`` and return the narrative it produced.

    The snapshot is replaced rather than added to, so the two calls in the test
    below differ in exactly one thing: the namespace of the join key.
    """
    async with session_scope() as session:
        await session.execute(
            delete(CaptureSnapshot).where(CaptureSnapshot.organization_id == org_id)
        )
        session.add(
            CaptureSnapshot(
                organization_id=org_id,
                connector="aws_govcloud",
                odp_key=odp_key,
                value=value,
                nist_id=nist_id,
                captured_at=datetime.now(UTC),
            )
        )
        await session.flush()
        project = (
            await session.execute(select(SSPProject).where(SSPProject.id == proj_id))
        ).scalar_one()
        profile = (
            await session.execute(
                select(SystemProfile).where(SystemProfile.system_id == project.system_id)
            )
        ).scalar_one()
        await generate_statements(session, project=project, profile=profile)
        entry = (
            await session.execute(
                select(SSPControlEntry).where(
                    SSPControlEntry.project_id == proj_id,
                    SSPControlEntry.control_id == control_id,
                )
            )
        ).scalar_one()
        return "\n".join((p.get("text") or "") for p in entry.part_narratives or [])


def test_aws_govcloud_maps_to_the_ssp_aws_platform() -> None:
    """The precondition the DB test below rests on, pinned separately so a
    failure there is not misread as a connector problem."""
    assert PLATFORM_TO_SSP["aws_govcloud"] == "aws_govcloud"


async def test_the_captured_ebs_encryption_value_now_reaches_an_aws_narrative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A real captured value finally arriving in the document it was read for.

    This is a visible change to generated AWS documents: an account with default
    EBS encryption on now says so in its SC-family statement. It is correct --
    the value was always captured, and the wrong ``nist_id`` threw it away at
    the join.

    The second half is the same render under the id the connector used to emit.
    It is not a hypothetical: ``"SC-28"`` is what shipped, and no AWS project
    has an 800-53 id on any entry, so this is exactly what every AWS customer
    got. Asserting both halves is what makes the first half evidence of a fix
    rather than evidence that the pipeline works.
    """
    conn = _aws_connector(monkeypatch)
    caps = {c.odp_key: c for c in await conn.capture()}
    cap = caps["encryption_at_rest"]
    # Pinned explicitly: reverting this line is the mutation this test catches.
    assert cap.nist_id == "3.13.16"
    assert cap.detail["nist_80053_id"] == "SC-28", "the 800-53 equivalent is carried, not emitted"
    assert cap.value == "enabled"

    async with _aws_tenant("AWS Capture Parity Org", "AWSPAR") as (org_id, proj_id):
        control_id = "SC.AWSPAR-3.13.16"
        rendered = await _render_with_snapshot(
            org_id,
            proj_id,
            control_id=control_id,
            odp_key=cap.odp_key,
            value=cap.value,
            nist_id=cap.nist_id or "",
        )
        assert "encryption at rest = enabled (captured from aws_govcloud)" in rendered, (
            f"the captured EBS value did not reach the narrative: {rendered!r}"
        )

        stranded = await _render_with_snapshot(
            org_id,
            proj_id,
            control_id=control_id,
            odp_key=cap.odp_key,
            value=cap.value,
            nist_id="SC-28",
        )
        assert "encryption at rest" not in stranded, (
            "an 800-53 nist_id reached the narrative, so this test would pass "
            f"whatever namespace the connector emitted: {stranded!r}"
        )
