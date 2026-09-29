"""Configuring a connector credential through the UI, per organization.

The page and the credential API used to disagree about whether an
organization was required: `/connectors` tolerated `None`, listing every
tenant's connectors and creating rows with a NULL organization, while
`/api/connector-settings` refused an org-less caller outright. These pin the
agreement.
"""

from __future__ import annotations

import os
import uuid

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, User
from ccf.models_grc import ConnectorConfig

pytestmark = pytest.mark.usefixtures("fresh_engine")

_MSGRAPH = {
    "tenant_id": "11111111-2222-3333-4444-555555555555",
    "client_id": "66666666-7777-8888-9999-000000000000",
    "client_secret": "super-secret-value",
}


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def _env():
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    os.environ["CCF_AI_CREDENTIAL_MASTER_KEY"] = "unit-test-master-key-32-chars-xx"
    get_settings.cache_clear()
    yield
    for key in (
        "CCF_AUTH_ENABLED",
        "CCF_AUTH_SESSION_SECRET",
        "CCF_AI_CREDENTIAL_MASTER_KEY",
    ):
        os.environ.pop(key, None)
    get_settings.cache_clear()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _org_admin(name: str) -> tuple[int, str]:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        user = User(
            email=f"admin-{uuid.uuid4().hex[:6]}@{name.lower().replace(' ', '-')}.test",
            organization_id=org.id,
            role="admin",
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(user)
        await s.flush()
        return org.id, user.api_token


async def _connector(org_id: int, connector_type: str = "msgraph") -> int:
    async with session_scope() as s:
        cfg = ConnectorConfig(
            organization_id=org_id, name=f"{connector_type} probe", connector_type=connector_type
        )
        s.add(cfg)
        await s.flush()
        return cfg.id


# --- the org requirement -----------------------------------------------------


@pytest.mark.asyncio
async def test_an_org_less_session_gets_a_page_not_another_tenants_connectors() -> None:
    """Auth disabled means no organization, which used to list every tenant's rows."""
    org_id, _token = await _org_admin(f"Conn Leak {uuid.uuid4().hex[:6]}")
    await _connector(org_id)

    os.environ["CCF_AUTH_ENABLED"] = "false"
    get_settings.cache_clear()
    try:
        async with _client() as c:
            r = await c.get("/connectors")
    finally:
        os.environ["CCF_AUTH_ENABLED"] = "true"
        get_settings.cache_clear()

    assert r.status_code == 400
    assert "No organization in this session" in r.text
    assert "msgraph probe" not in r.text


@pytest.mark.asyncio
async def test_an_org_less_session_cannot_create_a_null_org_connector() -> None:
    os.environ["CCF_AUTH_ENABLED"] = "false"
    get_settings.cache_clear()
    try:
        async with _client() as c:
            r = await c.post(
                "/connectors", data={"name": "orphan", "connector_type": "msgraph"}
            )
    finally:
        os.environ["CCF_AUTH_ENABLED"] = "true"
        get_settings.cache_clear()

    assert r.status_code == 400
    async with session_scope() as s:
        orphans = (
            await s.execute(
                select(ConnectorConfig).where(ConnectorConfig.organization_id.is_(None))
            )
        ).scalars().all()
        assert orphans == []


# --- storing a credential ----------------------------------------------------


@pytest.mark.asyncio
async def test_a_complete_credential_is_stored_and_only_its_last_four_shown() -> None:
    org_id, token = await _org_admin(f"Conn Store {uuid.uuid4().hex[:6]}")
    cfg_id = await _connector(org_id)

    async with _client() as c:
        r = await c.post(
            f"/connectors/{cfg_id}/credential", data=_MSGRAPH, headers=_auth(token)
        )
    assert r.status_code == 303 and "saved=1" in r.headers["location"]

    async with session_scope() as s:
        cfg = await s.get(ConnectorConfig, cfg_id)
        assert cfg.status == "configured"
        assert cfg.key_last4 == "…alue"
        assert cfg.encrypted_credential
        assert "super-secret-value" not in cfg.encrypted_credential

    async with _client() as c:
        page = await c.get(f"/connectors/{cfg_id}", headers=_auth(token))
    assert "super-secret-value" not in page.text, "the secret must never be echoed back"
    assert "…alue" in page.text


@pytest.mark.asyncio
async def test_an_incomplete_credential_is_refused_not_marked_configured() -> None:
    """It used to be stored, displayed as `…{}`, and reported as configured."""
    org_id, token = await _org_admin(f"Conn Partial {uuid.uuid4().hex[:6]}")
    cfg_id = await _connector(org_id)

    async with _client() as c:
        r = await c.post(
            f"/connectors/{cfg_id}/credential",
            data={"tenant_id": _MSGRAPH["tenant_id"]},
            headers=_auth(token),
        )
    assert r.status_code == 303
    assert "client_id" in r.headers["location"], "the missing fields must be named"

    async with session_scope() as s:
        cfg = await s.get(ConnectorConfig, cfg_id)
        assert cfg.encrypted_credential is None
        assert cfg.status != "configured"


@pytest.mark.asyncio
async def test_a_blank_secret_field_keeps_the_stored_value() -> None:
    """A secret cannot be read back, so re-saving to change a project key must
    not wipe the key the operator can no longer retype."""
    org_id, token = await _org_admin(f"Conn Merge {uuid.uuid4().hex[:6]}")
    cfg_id = await _connector(org_id, "jira")

    async with _client() as c:
        first = await c.post(
            f"/connectors/{cfg_id}/credential",
            data={
                "base_url": "https://acme.atlassian.net",
                "email": "svc@acme.test",
                "api_token": "ATATT-first-token",
                "project_key": "SEC",
            },
            headers=_auth(token),
        )
        assert "saved=1" in first.headers["location"]

        second = await c.post(
            f"/connectors/{cfg_id}/credential",
            data={"base_url": "", "email": "", "api_token": "", "project_key": "OPS"},
            headers=_auth(token),
        )
    assert "saved=1" in second.headers["location"], second.headers["location"]

    from ccf.connectors.credentials import resolve_credential  # noqa: PLC0415

    async with session_scope() as s:
        cfg = await s.get(ConnectorConfig, cfg_id)
        assert cfg.config["project_key"] == "OPS"
        secret = await resolve_credential(s, org_id, "jira")
        assert secret["api_token"] == "ATATT-first-token"


# --- tenancy -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_another_organization_cannot_write_a_credential_to_this_connector() -> None:
    """The owning org is asserted first, so a route that refused everything fails too."""
    owner_id, owner_token = await _org_admin(f"Conn Owner {uuid.uuid4().hex[:6]}")
    _outsider_id, outsider_token = await _org_admin(f"Conn Outsider {uuid.uuid4().hex[:6]}")
    cfg_id = await _connector(owner_id)

    async with _client() as c:
        mine = await c.post(
            f"/connectors/{cfg_id}/credential", data=_MSGRAPH, headers=_auth(owner_token)
        )
        assert "saved=1" in mine.headers["location"]

        theirs = await c.post(
            f"/connectors/{cfg_id}/credential",
            data=_MSGRAPH,
            headers=_auth(outsider_token),
        )
    assert theirs.status_code == 404


@pytest.mark.asyncio
async def test_another_organization_cannot_open_or_test_this_connector() -> None:
    owner_id, owner_token = await _org_admin(f"Conn Read {uuid.uuid4().hex[:6]}")
    _outsider, outsider_token = await _org_admin(f"Conn Read Out {uuid.uuid4().hex[:6]}")
    cfg_id = await _connector(owner_id)

    async with _client() as c:
        assert (await c.get(f"/connectors/{cfg_id}", headers=_auth(owner_token))).status_code == 200
        assert (
            await c.get(f"/connectors/{cfg_id}", headers=_auth(outsider_token))
        ).status_code == 404
        assert (
            await c.post(f"/connectors/{cfg_id}/test", headers=_auth(outsider_token))
        ).status_code == 404


# --- the connection test -----------------------------------------------------


@pytest.mark.asyncio
async def test_testing_without_a_credential_names_what_is_missing() -> None:
    org_id, token = await _org_admin(f"Conn Untested {uuid.uuid4().hex[:6]}")
    cfg_id = await _connector(org_id)

    async with _client() as c:
        r = await c.post(f"/connectors/{cfg_id}/test", headers=_auth(token))
    assert r.status_code == 303
    assert "not%20configured" in r.headers["location"]


@pytest.mark.asyncio
async def test_a_failed_test_records_the_providers_own_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The provider's refusal is the actionable part and must survive the trip."""
    org_id, token = await _org_admin(f"Conn Verify {uuid.uuid4().hex[:6]}")
    cfg_id = await _connector(org_id)

    async with _client() as c:
        await c.post(f"/connectors/{cfg_id}/credential", data=_MSGRAPH, headers=_auth(token))

    from ccf.connectors.msgraph import MsGraphConnector  # noqa: PLC0415

    async def _refuse(self):
        return {"connected": False, "reason": "AADSTS7000215: Invalid client secret provided."}

    monkeypatch.setattr(MsGraphConnector, "verify", _refuse)
    async with _client() as c:
        r = await c.post(f"/connectors/{cfg_id}/test", headers=_auth(token))

    assert "AADSTS7000215" in r.headers["location"]
    async with session_scope() as s:
        cfg = await s.get(ConnectorConfig, cfg_id)
        assert cfg.status == "error"
        assert "AADSTS7000215" in cfg.error_message


@pytest.mark.asyncio
async def test_a_successful_test_clears_the_previous_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id, token = await _org_admin(f"Conn Verify Ok {uuid.uuid4().hex[:6]}")
    cfg_id = await _connector(org_id)

    async with _client() as c:
        await c.post(f"/connectors/{cfg_id}/credential", data=_MSGRAPH, headers=_auth(token))

    from ccf.connectors.msgraph import MsGraphConnector  # noqa: PLC0415

    async def _ok(self):
        return {"connected": True, "tenant": "contoso.onmicrosoft.com"}

    monkeypatch.setattr(MsGraphConnector, "verify", _ok)
    async with _client() as c:
        r = await c.post(f"/connectors/{cfg_id}/test", headers=_auth(token))

    assert "tested=1" in r.headers["location"]
    async with session_scope() as s:
        cfg = await s.get(ConnectorConfig, cfg_id)
        assert cfg.status == "configured"
        assert cfg.error_message is None


def test_a_failed_token_request_reports_entras_own_code() -> None:
    """AADSTS codes distinguish a wrong tenant from a wrong secret.

    ``str(HTTPStatusError)`` yields only "Client error '400 Bad Request' for
    url ...", which says none of that and points the reader at an MDN page
    about HTTP status codes. The code is in the response body, which was
    discarded.
    """
    import httpx  # noqa: PLC0415

    from ccf.connectors.msgraph import _aad_reason  # noqa: PLC0415

    request = httpx.Request("POST", "https://login.microsoftonline.us/t/oauth2/v2.0/token")
    response = httpx.Response(
        400,
        json={
            "error": "unauthorized_client",
            "error_description": (
                "AADSTS700016: Application with identifier '66666666' was not found "
                "in the directory.\nTrace ID: abc\nTimestamp: 2026-09-25"
            ),
        },
        request=request,
    )
    reason = _aad_reason(
        httpx.HTTPStatusError("Client error '400 Bad Request'", request=request, response=response)
    )
    assert reason.startswith("AADSTS700016")
    assert "Trace ID" not in reason, "only the first line is the actionable sentence"


def test_a_transport_failure_without_a_response_still_reports_something() -> None:
    """No response body to read: the exception text is all there is, and
    returning an empty reason would render as 'the provider did not say why'."""
    from ccf.connectors.msgraph import _aad_reason  # noqa: PLC0415

    assert _aad_reason(OSError("name resolution failed")) == "name resolution failed"


@pytest.mark.asyncio
async def test_verify_routes_a_token_failure_through_the_aad_reader() -> None:
    """Pins the wiring, not just the helper.

    Testing ``_aad_reason`` alone left ``verify()`` free to go back to
    ``str(e)``: both mutations had to fail, and only one did. This drives
    ``verify()`` itself and asserts the AADSTS code survives the trip.
    """
    import httpx  # noqa: PLC0415

    from ccf.connectors.msgraph import MsGraphConnector  # noqa: PLC0415

    request = httpx.Request("POST", "https://login.microsoftonline.us/t/oauth2/v2.0/token")
    response = httpx.Response(
        401,
        json={
            "error": "invalid_client",
            "error_description": "AADSTS7000215: Invalid client secret provided.\nTrace ID: x",
        },
        request=request,
    )

    async def _raise(self, client):
        raise httpx.HTTPStatusError(
            "Client error '401 Unauthorized'", request=request, response=response
        )

    connector = MsGraphConnector(credential=dict(_MSGRAPH))
    original = MsGraphConnector._token
    MsGraphConnector._token = _raise
    try:
        result = await connector.verify()
    finally:
        MsGraphConnector._token = original

    assert result["connected"] is False
    assert result["reason"].startswith("AADSTS7000215")


# --- the credential must land on the row you were editing ---------------------


@pytest.mark.asyncio
async def test_a_credential_is_written_to_the_connector_it_was_entered_on() -> None:
    """It used to be written to whichever row matched the type first.

    `set_credential` looked the row up by (organization, connector_type) and
    took the first match, ignoring which connector the form belonged to. With
    two msgraph rows in one organization, a credential entered on the second
    was silently stored on the first: the row filled in stayed "not
    configured" and the other one changed underneath. Seen in a real
    deployment, where it read as "the scan is not populating".
    """
    org_id, token = await _org_admin(f"Conn Route {uuid.uuid4().hex[:6]}")
    first = await _connector(org_id)
    # Created directly, because the create route now refuses a second of a type.
    async with session_scope() as s:
        row = ConnectorConfig(
            organization_id=org_id, name="second msgraph", connector_type="msgraph"
        )
        s.add(row)
        await s.flush()
        second = row.id

    async with _client() as c:
        r = await c.post(
            f"/connectors/{second}/credential", data=_MSGRAPH, headers=_auth(token)
        )
    assert "saved=1" in r.headers["location"]

    async with session_scope() as s:
        target = await s.get(ConnectorConfig, second)
        other = await s.get(ConnectorConfig, first)
        assert target.encrypted_credential is not None, "the edited row got nothing"
        assert other.encrypted_credential is None, "the other row was written to"


@pytest.mark.asyncio
async def test_a_second_connector_of_the_same_type_is_refused() -> None:
    """Credentials are keyed by (organization, type), so a second row of a type
    can never hold its own -- it only makes ownership ambiguous."""
    org_id, token = await _org_admin(f"Conn Dup {uuid.uuid4().hex[:6]}")
    async with _client() as c:
        first = await c.post(
            "/connectors",
            data={"name": "one", "connector_type": "msgraph"},
            headers=_auth(token),
        )
        assert first.status_code == 303, "the first of a type must be allowed"

        second = await c.post(
            "/connectors",
            data={"name": "two", "connector_type": "msgraph"},
            headers=_auth(token),
        )
    assert second.status_code == 409

    async with session_scope() as s:
        rows = (
            await s.execute(
                select(ConnectorConfig).where(
                    ConnectorConfig.organization_id == org_id,
                    ConnectorConfig.connector_type == "msgraph",
                )
            )
        ).scalars().all()
        assert len(rows) == 1


# --- the development sync must not manufacture capture counts -----------------


@pytest.mark.asyncio
async def test_sync_reports_no_credential_and_writes_nothing() -> None:
    """Those four columns are what `connector_backing_state` reads to decide a
    control is evidenced by automated capture."""
    org_id, token = await _org_admin(f"Conn Mock {uuid.uuid4().hex[:6]}")
    cfg_id = await _connector(org_id)

    async with _client() as c:
        r = await c.post(f"/connectors/{cfg_id}/sync", headers=_auth(token))
    assert r.status_code == 303
    from urllib.parse import unquote  # noqa: PLC0415

    assert "no stored credential" in unquote(r.headers["location"])

    async with session_scope() as s:
        cfg = await s.get(ConnectorConfig, cfg_id)
        assert cfg.objects_discovered == 0
        assert cfg.evidence_produced == 0
        assert cfg.last_sync is None


@pytest.mark.asyncio
async def test_sync_asks_the_provider_and_never_invents_capture_counts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stored credential is not a working one.

    Sync used to write `100 objects / 10 evidence` without contacting
    anything. Gating it on a credential being *present* was not enough: in a
    real deployment the credential was present and could not authenticate, and
    the row still displayed `configured, 100 objects, 10 evidence` -- which
    read as a working integration and hid the real error. So it asks the
    provider, and capture counts are left to real capture.
    """
    from ccf.connectors.msgraph import MsGraphConnector  # noqa: PLC0415

    org_id, token = await _org_admin(f"Conn Sync Verify {uuid.uuid4().hex[:6]}")
    cfg_id = await _connector(org_id)
    async with _client() as c:
        await c.post(f"/connectors/{cfg_id}/credential", data=_MSGRAPH, headers=_auth(token))

    async def _refuse(self):
        return {"connected": False, "reason": "AADSTS700016: Application not found."}

    monkeypatch.setattr(MsGraphConnector, "verify", _refuse)
    async with _client() as c:
        r = await c.post(f"/connectors/{cfg_id}/sync", headers=_auth(token))

    from urllib.parse import unquote  # noqa: PLC0415

    assert "AADSTS700016" in unquote(r.headers["location"])
    async with session_scope() as s:
        cfg = await s.get(ConnectorConfig, cfg_id)
        assert cfg.status == "error"
        assert "AADSTS700016" in cfg.error_message
        assert cfg.objects_discovered == 0, "capture counts were invented"
        assert cfg.evidence_produced == 0
        assert cfg.last_sync is None, "a failed verify is not a sync"

    async def _ok(self):
        return {"connected": True, "tenant": "contoso"}

    monkeypatch.setattr(MsGraphConnector, "verify", _ok)
    async with _client() as c:
        r = await c.post(f"/connectors/{cfg_id}/sync", headers=_auth(token))

    assert "tested=1" in r.headers["location"]
    async with session_scope() as s:
        cfg = await s.get(ConnectorConfig, cfg_id)
        assert cfg.status == "configured"
        assert cfg.error_message is None
        assert cfg.last_sync is not None
        # Even on success: a verify is not a capture.
        assert cfg.objects_discovered == 0
        assert cfg.evidence_produced == 0


# --- the scan button ----------------------------------------------------------


async def _system(org_id: int, name: str = "Federal") -> int:
    from ccf.models import System  # noqa: PLC0415

    async with session_scope() as s:
        system = System(organization_id=org_id, name=name)
        s.add(system)
        await s.flush()
        return system.id


@pytest.mark.asyncio
async def test_a_scan_runs_the_connectors_checks_and_records_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scanning was CLI and JSON API only, so a deployment could configure a
    connector, see the development sync's counts, and reasonably conclude a
    scan had run when none ever had -- control_tests stayed empty."""
    org_id, token = await _org_admin(f"Conn Scan {uuid.uuid4().hex[:6]}")
    cfg_id = await _connector(org_id)
    system_id = await _system(org_id)

    async with _client() as c:
        await c.post(f"/connectors/{cfg_id}/credential", data=_MSGRAPH, headers=_auth(token))

    seen: dict = {}

    async def _fake_scan(session, *, system_id, connector_key, actor="scan"):
        seen.update(system_id=system_id, connector_key=connector_key, actor=actor)
        return {"checks_run": 3, "failing_total": 1, "results": []}

    import ccf.posture.scan as scan_module  # noqa: PLC0415

    monkeypatch.setattr(scan_module, "scan_for_system", _fake_scan)
    async with _client() as c:
        r = await c.post(
            f"/connectors/{cfg_id}/scan", data={"system_id": system_id}, headers=_auth(token)
        )

    assert "scanned=3" in r.headers["location"]
    assert "failing=1" in r.headers["location"]
    assert seen["connector_key"] == "msgraph"
    assert seen["system_id"] == system_id


@pytest.mark.asyncio
async def test_a_scan_that_ran_no_checks_does_not_look_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """"Zero checks registered" and "everything passed" are different answers.

    azure_arm and gcp register no posture checks at all, so a scan there is a
    no-op that would otherwise render as a successful, green result.
    """
    org_id, token = await _org_admin(f"Conn Scan Empty {uuid.uuid4().hex[:6]}")
    cfg_id = await _connector(org_id, "azure_arm")
    system_id = await _system(org_id)

    async with _client() as c:
        await c.post(
            f"/connectors/{cfg_id}/credential",
            data={**_MSGRAPH, "subscription_id": "sub-1"},
            headers=_auth(token),
        )

    async def _no_checks(session, *, system_id, connector_key, actor="scan"):
        return {"checks_run": 0, "results": [], "reason": "no checks registered"}

    import ccf.posture.scan as scan_module  # noqa: PLC0415

    monkeypatch.setattr(scan_module, "scan_for_system", _no_checks)
    try:
        async with _client() as c:
            r = await c.post(
                f"/connectors/{cfg_id}/scan",
                data={"system_id": system_id},
                headers=_auth(token),
            )

        from urllib.parse import unquote  # noqa: PLC0415

        location = unquote(r.headers["location"])
        assert "scanned=" not in location
        assert "did nothing" in location
    finally:
        # Remove the stored credential. The scheduled collection path iterates
        # "organizations with a bound credential" and would then attempt a real
        # azure_arm capture against this row, reaching the network -- which the
        # conftest guard fails, in a different module, with no obvious link back
        # to here.
        async with session_scope() as s:
            row = await s.get(ConnectorConfig, cfg_id)
            if row is not None:
                await s.delete(row)


@pytest.mark.asyncio
async def test_a_scan_needs_a_credential_and_an_owned_system() -> None:
    org_id, token = await _org_admin(f"Conn Scan Guard {uuid.uuid4().hex[:6]}")
    cfg_id = await _connector(org_id)
    system_id = await _system(org_id)

    from urllib.parse import unquote  # noqa: PLC0415

    # No credential yet.
    async with _client() as c:
        r = await c.post(
            f"/connectors/{cfg_id}/scan", data={"system_id": system_id}, headers=_auth(token)
        )
    assert "nothing to scan with" in unquote(r.headers["location"])

    # Another organization's system, with a credential in place.
    _other_id, other_token = await _org_admin(f"Conn Scan Other {uuid.uuid4().hex[:6]}")
    outsider_system = await _system(_other_id, "Theirs")
    async with _client() as c:
        await c.post(f"/connectors/{cfg_id}/credential", data=_MSGRAPH, headers=_auth(token))
        r = await c.post(
            f"/connectors/{cfg_id}/scan",
            data={"system_id": outsider_system},
            headers=_auth(token),
        )
    assert r.status_code == 404
    # And the outsider cannot drive this connector at all.
    async with _client() as c:
        r = await c.post(
            f"/connectors/{cfg_id}/scan",
            data={"system_id": outsider_system},
            headers=_auth(other_token),
        )
    assert r.status_code == 404
