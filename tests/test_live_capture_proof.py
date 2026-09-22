"""Live capture is proved by the artifact, not by a status column.

``fix/connector-backed-claim`` made the SSP's "this is evidenced" claim depend
on whether *this tenant* has a working connector rather than on whether Concord
ships one. It then read that fact from four self-reported status columns of
``ConnectorConfig`` -- and one code path in the product writes exactly those
four columns with no credentials at all: ``POST /connector-configs`` creates a
row, ``POST /connector-configs/{id}/sync`` is a mock that sets ``status``,
``last_sync``, ``objects_discovered`` and ``error_message``. Both are gated on
``get_principal`` only, so **two API calls from a viewer** manufactured an
"evidenced by automated capture" claim in a document filed with a federal
regulator.

The proof therefore moves to the artifact a real capture produces:
``CaptureSnapshot``. These tests drive the real production paths -- the real
HTTP routes with auth enabled, the real ``derive_system`` -> ``generate_ssp``
-> ``generate_statements`` against the real database -- never a monkeypatched
predicate, which would only prove the mock works.
"""

from __future__ import annotations

import itertools
import os
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.connectors import credentials as connector_credentials
from ccf.db import session_scope
from ccf.governance.automation import derive_system, generate_ssp
from ccf.governance.control_tests import (
    connector_backing_state,
    evaluate_test,
    organization_capture_is_live,
)
from ccf.models import (
    CaptureSnapshot,
    Organization,
    ScoringControl,
    SSPControlEntry,
    SSPProject,
    System,
    SystemProfile,
    User,
)
from ccf.models_grc import ConnectorConfig, ControlTest
from ccf.ssp.platforms import MANUAL_EVIDENCE_MARKER, NO_TENANT_CAPTURE_NOTE

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture
def _auth_enabled() -> AsyncIterator[None]:
    """Real auth, so the routes run under a real role-bearing principal.

    With auth disabled every request is ``SYSTEM_PRINCIPAL``, whose ``org_id``
    is ``None`` and which is unconditionally global (``auth_deps.py``) -- the
    created ``ConnectorConfig`` would be filed under no organization at all and
    the reproduction would not reproduce anything.
    """
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


def _now() -> datetime:
    return datetime.now(UTC)


async def _seed_controls(session, prefix: str) -> list[str]:
    """A customer-responsibility domain (AC) and a platform-inherited one (PE).

    ``ScoringControl`` is a GLOBAL shared table, so the caller must delete these
    again or they leak into every later test in the session.
    """
    control_ids = [f"AC.{prefix}-3.1.1", f"PE.{prefix}-3.10.1"]
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
    return control_ids


class _Tenant:
    """The ids a test needs to drive the routes and then generate the SSP."""

    def __init__(
        self, org_id: int, system_id: int, token: str, prefix: str, proj_ids: list[int]
    ) -> None:
        self.org_id = org_id
        self.system_id = system_id
        self.token = token
        self.prefix = prefix
        # Shared with ``_tenant``'s ``finally``: ``SSPProject`` is not reached
        # by the organization cascade, so ``_generate`` has to record what it
        # created or the row outlives the test.
        self.proj_ids = proj_ids

    @property
    def auth(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}


@asynccontextmanager
async def _tenant(
    name: str, prefix: str, cloud_platform: str, *, role: str = "viewer"
) -> AsyncIterator[_Tenant]:
    """One org + a role-bearing user + a system with a declared cloud platform.

    Seeded rows are removed in ``finally`` -- ``ScoringControl`` is global and
    would otherwise leak into every later test in the session.
    """
    n = next(_SEQ)
    control_ids: list[str] = []
    org_id: int | None = None
    proj_ids: list[int] = []
    try:
        async with session_scope() as session:
            org = Organization(name=f"{name} {n}")
            session.add(org)
            await session.flush()
            org_id = org.id
            user = User(
                email=f"{prefix.lower()}-{n}@example.test",
                organization_id=org.id,
                role=role,
                active=True,
                password_hash=hash_password("pw"),
                api_token=new_api_token(),
            )
            session.add(user)
            sysrow = System(organization_id=org.id, name=f"{name} system")
            session.add(sysrow)
            await session.flush()
            control_ids = await _seed_controls(session, prefix)
            session.add(
                SystemProfile(
                    system_id=sysrow.id,
                    environment_type="cloud",
                    cloud_platform=cloud_platform,
                )
            )
            await session.flush()
            t = _Tenant(org.id, sysrow.id, user.api_token, prefix, proj_ids)
        yield t
    finally:
        async with session_scope() as session:
            if control_ids:
                await session.execute(
                    delete(ScoringControl).where(ScoringControl.control_id.in_(control_ids))
                )
            if proj_ids:
                await session.execute(delete(SSPProject).where(SSPProject.id.in_(proj_ids)))
            if org_id is not None:
                await session.execute(delete(Organization).where(Organization.id == org_id))


async def _generate(t: _Tenant) -> list[SSPControlEntry]:
    """Run the real derivation + SSP generation and return this project's entries."""
    async with session_scope() as session:
        sysrow = await session.get(System, t.system_id)
        assert sysrow is not None
        profile = (
            (
                await session.execute(
                    select(SystemProfile).where(SystemProfile.system_id == t.system_id)
                )
            )
            .scalars()
            .one()
        )
        await derive_system(
            session,
            system_id=sysrow.id,
            org_id=sysrow.organization_id,
            profile=profile,
            create_poams=False,
        )
        proj_id = await generate_ssp(session, system=sysrow, profile=profile)
        t.proj_ids.append(proj_id)
        return list(
            (
                await session.execute(
                    select(SSPControlEntry).where(SSPControlEntry.project_id == proj_id)
                )
            )
            .scalars()
            .all()
        )


def _texts(entries: list[SSPControlEntry]) -> dict[str, str]:
    return {
        e.control_id: "\n".join((p.get("text") or "") for p in e.part_narratives or [])
        for e in entries
    }


# --- §4.1 The two-call reproduction -----------------------------------------


@pytest.mark.asyncio
@pytest.mark.usefixtures("_auth_enabled")
async def test_two_api_calls_and_no_credentials_do_not_evidence_anything() -> None:
    """The whole change in one test.

    A ``viewer`` -- the least-privileged authenticated role -- creates a
    connector with no credential and calls the mock sync. Those two calls write
    exactly the four columns the backing ladder reads, and nothing else: no
    ``CaptureSnapshot`` exists, so nothing has actually been captured. The SSP
    must still carry the manual-evidence caveat and must still downgrade the
    platform-sourced "Implemented".
    """
    async with _tenant("Mock Sync AWS Org", "MOCKSYNC", "aws_govcloud") as t:
        async with _client() as client:
            created = await client.post(
                "/api/connector-configs",
                json={"name": "AWS GovCloud", "connector_type": "aws_govcloud"},
                headers=t.auth,
            )
            assert created.status_code == 201, created.text
            cfg_id = created.json()["id"]
            synced = await client.post(
                f"/api/connector-configs/{cfg_id}/sync", headers=t.auth
            )
            assert synced.status_code == 200, synced.text
            body = synced.json()

        # The mock really did set every column the ladder reads -- this test
        # fails for the right reason, not because the two calls did nothing.
        assert body["status"] == "configured"
        assert body["last_sync"] is not None
        assert body["objects_discovered"] > 0
        assert body["error_message"] is None

        async with session_scope() as session:
            snapshots = (
                await session.execute(
                    select(CaptureSnapshot).where(CaptureSnapshot.organization_id == t.org_id)
                )
            ).scalars().all()
        assert not snapshots, "the mock sync must not have produced any capture artifact"

        entries = await _generate(t)
        assert entries, "expected seeded SSP entries"
        for control_id, text in _texts(entries).items():
            assert MANUAL_EVIDENCE_MARKER in text, (
                f"{control_id} claims automated capture evidenced it after a mock "
                f"sync that captured nothing: {text!r}"
            )
            assert NO_TENANT_CAPTURE_NOTE in text
        pe = [e for e in entries if e.control_id.startswith("PE.")]
        assert pe, "expected the platform-inherited PE entry"
        for e in pe:
            assert "Implemented" not in (e.implementation_status or []), (
                f"{e.control_id} still claims {e.implementation_status} after a mock sync"
            )


# --- §4.2 Each rung, independently, on real rows ----------------------------


@asynccontextmanager
async def _org_with(
    name: str,
    *,
    connector_type: str = "aws_govcloud",
    status: str = "configured",
    last_sync: datetime | None = None,
    objects_discovered: int = 42,
    captured_at: datetime | None = None,
    credential: dict | None = None,
) -> AsyncIterator[int]:
    """An org with one real ``ConnectorConfig`` and optionally one real
    ``CaptureSnapshot``, each column of each set explicitly. Yields the org id.

    Deleting the ``Organization`` cascades to both rows (``ondelete="CASCADE"``).
    """
    n = next(_SEQ)
    org_id: int | None = None
    try:
        async with session_scope() as session:
            org = Organization(name=f"{name} {n}")
            session.add(org)
            await session.flush()
            org_id = org.id
            session.add(
                ConnectorConfig(
                    organization_id=org.id,
                    name=f"{name} connector",
                    connector_type=connector_type,
                    status=status,
                    last_sync=last_sync,
                    objects_discovered=objects_discovered,
                )
            )
            if captured_at is not None:
                session.add(
                    CaptureSnapshot(
                        organization_id=org.id,
                        connector=connector_type,
                        odp_key="mfa_enforced",
                        value="true",
                        captured_at=captured_at,
                    )
                )
            await session.flush()
            if credential is not None:
                await connector_credentials.set_credential(
                    session, org.id, connector_type, credential
                )
        yield org_id
    finally:
        async with session_scope() as session:
            if org_id is not None:
                await session.execute(delete(Organization).where(Organization.id == org_id))


async def _is_live(org_id: int, connector_type: str = "aws_govcloud") -> bool:
    async with session_scope() as session:
        return await organization_capture_is_live(
            session, organization_id=org_id, connector_type=connector_type
        )


@pytest.mark.asyncio
async def test_rung1_a_usable_connector_is_required_even_with_a_fresh_capture() -> None:
    """Rung 1: an unconfigured connector cannot evidence anything, however much
    it captured. The artifact here is fresh -- only the status column is wrong."""
    async with _org_with(
        "Rung1 Unconfigured", status="not_configured", last_sync=_now(), captured_at=_now()
    ) as org_id:
        assert await _is_live(org_id) is False


@pytest.mark.asyncio
async def test_rung1_a_never_synced_connector_is_not_live_with_a_fresh_capture() -> None:
    async with _org_with(
        "Rung1 Never Synced", last_sync=None, captured_at=_now()
    ) as org_id:
        assert await _is_live(org_id) is False


@pytest.mark.asyncio
async def test_rung1_an_empty_sync_is_not_live_with_a_fresh_capture() -> None:
    async with _org_with(
        "Rung1 Empty", last_sync=_now(), objects_discovered=0, captured_at=_now()
    ) as org_id:
        assert await _is_live(org_id) is False


@pytest.mark.asyncio
async def test_rung2_a_healthy_connector_with_no_capture_artifact_is_not_live() -> None:
    """Rung 2, the rung the mock cannot fabricate. Every status column reads
    exactly as the mock sync leaves it; no ``CaptureSnapshot`` exists."""
    async with _org_with("Rung2 No Snapshot", last_sync=_now(), captured_at=None) as org_id:
        assert await _is_live(org_id) is False


@pytest.mark.asyncio
async def test_rung2_a_stale_capture_artifact_is_not_live_though_the_sync_is_fresh() -> None:
    """Spec §2.1: staleness is measured on the ARTIFACT, not on ``last_sync``.

    ``last_sync`` says the connector ran today; ``captured_at`` says it has
    produced nothing for over a year. Where they disagree the artifact is the
    honest one, and the tenant is not live.
    """
    async with _org_with(
        "Rung2 Stale Snapshot", last_sync=_now(), captured_at=_now() - timedelta(days=400)
    ) as org_id:
        assert await _is_live(org_id) is False


@pytest.mark.asyncio
async def test_a_capture_artifact_for_a_different_connector_does_not_count() -> None:
    """The snapshot must be for THIS connector. ``CaptureSnapshot.connector``
    holds ``conn.key``, the same value space as ``ConnectorConfig
    .connector_type``, so a fresh msgraph capture must not back AWS GovCloud."""
    async with _org_with("Cross Connector", last_sync=_now(), captured_at=None) as org_id:
        async with session_scope() as session:
            session.add(
                CaptureSnapshot(
                    organization_id=org_id,
                    connector="msgraph",
                    odp_key="mfa_enforced",
                    value="true",
                    captured_at=_now(),
                )
            )
        assert await _is_live(org_id) is False


@pytest.mark.asyncio
async def test_another_orgs_capture_artifact_does_not_count() -> None:
    """``CaptureSnapshot`` is organization-scoped too. A neighbour's fresh
    capture is not evidence about this tenant."""
    async with (
        _org_with("Artifact Neighbour", last_sync=_now(), captured_at=_now()),
        _org_with("Artifact Isolated", last_sync=_now(), captured_at=None) as org_id,
    ):
        assert await _is_live(org_id) is False


@pytest.mark.asyncio
async def test_all_three_rungs_together_are_live() -> None:
    """A usable connector, a recent artifact, and (msgraph) a credential that
    cannot be a host profile: live."""
    async with _org_with(
        "All Rungs", connector_type="msgraph", last_sync=_now(), captured_at=_now()
    ) as org_id:
        assert await _is_live(org_id, "msgraph") is True


# --- §4.3 A real capture must still evidence --------------------------------


@pytest.mark.asyncio
@pytest.mark.usefixtures("_auth_enabled")
async def test_a_real_capture_still_evidences_with_no_caveat() -> None:
    """A fix that makes nothing ever count is not a fix.

    A configured, recently-synced, non-empty connector **and** real
    ``CaptureSnapshot`` rows: the caveat must be ABSENT and the
    platform-sourced "Implemented" retained.
    """
    async with _tenant("Really Captured AWS Org", "REALCAP", "aws_govcloud") as t:
        async with session_scope() as session:
            session.add(
                ConnectorConfig(
                    organization_id=t.org_id,
                    name="AWS GovCloud",
                    connector_type="aws_govcloud",
                    status="configured",
                    last_sync=_now(),
                    objects_discovered=42,
                )
            )
            session.add(
                CaptureSnapshot(
                    organization_id=t.org_id,
                    connector="aws_govcloud",
                    odp_key="mfa_enforced",
                    value="true",
                    captured_at=_now(),
                )
            )

        entries = await _generate(t)
        assert entries
        for control_id, text in _texts(entries).items():
            assert MANUAL_EVIDENCE_MARKER not in text, (
                f"{control_id} over-flagged despite a real capture: {text!r}"
            )
        pe = [e for e in entries if e.control_id.startswith("PE.")]
        assert pe
        assert all("Implemented" in (e.implementation_status or []) for e in pe)


# --- §4.4 The mock sync is development-only ---------------------------------


@pytest.fixture
def _production_env() -> AsyncIterator[None]:
    """A non-dev environment the app will actually start in.

    ``enforce_secure_config`` refuses startup outside dev unless auth is on,
    the session secret is not the default, and CORS is not wildcard -- so all
    three have to be real here, not just ``CCF_ENV``.
    """
    previous = {
        k: os.environ.get(k)
        for k in (
            "CCF_ENV",
            "CCF_AUTH_ENABLED",
            "CCF_AUTH_SESSION_SECRET",
            "CCF_API_CORS_ORIGINS",
        )
    }
    os.environ["CCF_ENV"] = "production"
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    # A JSON list: pydantic-settings parses list fields from the env as JSON.
    os.environ["CCF_API_CORS_ORIGINS"] = '["https://concord.example"]'
    get_settings.cache_clear()
    yield
    for k, v in previous.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    get_settings.cache_clear()


@pytest.mark.asyncio
@pytest.mark.usefixtures("_auth_enabled")
async def test_the_mock_sync_still_works_in_development() -> None:
    """Gating it must not delete a credential-free demo path that is in use."""
    async with _tenant("Dev Mock Org", "DEVMOCK", "aws_govcloud") as t:
        async with _client() as client:
            created = await client.post(
                "/api/connector-configs",
                json={"name": "AWS GovCloud", "connector_type": "aws_govcloud"},
                headers=t.auth,
            )
            assert created.status_code == 201, created.text
            synced = await client.post(
                f"/api/connector-configs/{created.json()['id']}/sync", headers=t.auth
            )
        assert synced.status_code == 200, synced.text
        assert synced.json()["status"] == "configured"


@pytest.mark.asyncio
async def test_the_mock_sync_is_refused_outside_development(
    _production_env: None,
) -> None:
    """Defence in depth (spec §2.2): rung 2 already means a mock sync evidences
    nothing, but a future write path to those columns must not reopen this --
    and a mock that silently does nothing in production is worse than one that
    says so, hence a refusal rather than a no-op."""
    async with _tenant("Prod Mock Org", "PRODMOCK", "aws_govcloud") as t:
        async with _client() as client:
            created = await client.post(
                "/api/connector-configs",
                json={"name": "AWS GovCloud", "connector_type": "aws_govcloud"},
                headers=t.auth,
            )
            assert created.status_code == 201, created.text
            cfg_id = created.json()["id"]
            synced = await client.post(
                f"/api/connector-configs/{cfg_id}/sync", headers=t.auth
            )
        assert synced.status_code == 503, synced.text
        assert "development-only" in synced.json()["detail"]

        # And it really wrote nothing: the four columns are untouched.
        async with session_scope() as session:
            cfg = await session.get(ConnectorConfig, cfg_id)
            assert cfg is not None
            assert cfg.status != "configured"
            assert cfg.last_sync is None
            assert cfg.objects_discovered == 0


# --- §4.5 A host profile is not a tenant credential -------------------------


@pytest.fixture
def _credential_storage(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("CCF_AI_CREDENTIAL_MASTER_KEY", "unit-test-master-key-32-chars-xx")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.mark.asyncio
@pytest.mark.usefixtures("_credential_storage")
async def test_a_profile_backed_aws_credential_is_not_live_tenant_capture() -> None:
    """Spec §3. ``profile`` is resolved from the HOST's ``~/.aws/credentials``
    -- one shared identity for the whole deployment. Capture under it keeps
    working; it just cannot license the sentence "this organization's own
    automated capture evidences this control"."""
    async with _org_with(
        "Host Profile AWS",
        last_sync=_now(),
        captured_at=_now(),
        credential={"profile": "concord-host", "region": "us-gov-west-1"},
    ) as org_id:
        assert await _is_live(org_id) is False


@pytest.mark.asyncio
@pytest.mark.usefixtures("_credential_storage")
async def test_an_access_key_pair_for_the_same_org_is_live_tenant_capture() -> None:
    """Asserted separately from the profile case so §3 cannot quietly collapse
    into "AWS never counts" -- which would look like a passing fix and would be
    a silent regression in what AWS tenants are told."""
    async with _org_with(
        "Tenant Key AWS",
        last_sync=_now(),
        captured_at=_now(),
        credential={
            "access_key_id": "AKIAEXAMPLEEXAMPLE",
            "secret_access_key": "s3cr3t-example-key-material",
            "region": "us-gov-west-1",
        },
    ) as org_id:
        assert await _is_live(org_id) is True


@pytest.mark.asyncio
@pytest.mark.usefixtures("_credential_storage")
async def test_an_access_key_pair_wins_when_a_profile_is_also_present() -> None:
    """``AwsGovCloudConnector._session`` prefers the key pair when both are on
    the bundle, so the identity that actually captured is the tenant's."""
    async with _org_with(
        "Both Identities AWS",
        last_sync=_now(),
        captured_at=_now(),
        credential={
            "access_key_id": "AKIAEXAMPLEEXAMPLE",
            "secret_access_key": "s3cr3t-example-key-material",
            "profile": "concord-host",
        },
    ) as org_id:
        assert await _is_live(org_id) is True


@pytest.mark.asyncio
@pytest.mark.usefixtures("_credential_storage")
async def test_a_profile_backed_credential_for_another_connector_is_unaffected() -> None:
    """The check is named for AWS specifically and must stay that way: no other
    provider accepts a host profile, so a ``profile`` key on an msgraph bundle
    is not a host identity and must not be treated as one."""
    async with _org_with(
        "MsGraph Profile Key",
        connector_type="msgraph",
        last_sync=_now(),
        captured_at=_now(),
        credential={"profile": "irrelevant", "client_secret": "x"},
    ) as org_id:
        assert await _is_live(org_id, "msgraph") is True


# --- §4.6 Control tests are deliberately unchanged --------------------------


_LADDER_CASES = [
    ("missing", None),
    ("unsynced", {"status": "not_configured", "last_sync": _now(), "objects_discovered": 5}),
    ("unsynced", {"status": "configured", "last_sync": None, "objects_discovered": 5}),
    (
        "stale",
        {
            "status": "configured",
            "last_sync": _now() - timedelta(days=120),
            "objects_discovered": 5,
        },
    ),
    ("empty", {"status": "configured", "last_sync": _now(), "objects_discovered": 0}),
    ("current", {"status": "configured", "last_sync": _now(), "objects_discovered": 5}),
]


@pytest.mark.parametrize(("expected", "row"), _LADDER_CASES)
def test_connector_backing_state_is_unchanged(expected: str, row: dict | None) -> None:
    """Spec §2.3: ``connector_backing_state`` keeps its current definition.

    Pinned as a table so widening the SSP rule into it -- e.g. by teaching this
    function about ``CaptureSnapshot`` -- fails here rather than silently
    altering what every tenant's control tests report.
    """
    conn = None if row is None else ConnectorConfig(connector_type="aws_govcloud", **row)
    assert connector_backing_state(conn, _now().date(), 30) == expected


@pytest.mark.asyncio
async def test_control_tests_still_trust_the_status_columns() -> None:
    """The recorded decision, asserted rather than assumed (spec §2.3).

    The SAME org and connector -- healthy status columns, no capture artifact --
    must give a connector-backed control test ``pass`` while the SSP claim is
    NOT live. Control tests are an internal check; the SSP claim is a federal
    assertion, and widening this change into the scheduler would alter what
    tenants' tests report in the branch that fixes a document claim. It needs
    its own measurement of what currently passes, so it is recorded here.
    """
    async with _org_with("Control Test Org", last_sync=_now(), captured_at=None) as org_id:
        test = ControlTest(
            organization_id=org_id,
            control_id="AC-2",
            name="Account management is captured",
            method="connector",
            connector_type="aws_govcloud",
            frequency="monthly",
        )
        async with session_scope() as session:
            status, detail, _ref = await evaluate_test(session, test, _now().date())
        assert status == "pass", detail
        assert "current" in detail

        assert await _is_live(org_id) is False, (
            "the SSP claim must NOT be live for the very same rows the control "
            "test passes on -- that difference is the recorded decision"
        )
