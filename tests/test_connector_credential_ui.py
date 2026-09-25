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

    from ccf.connectors.credentials import resolve_credential

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

    from ccf.connectors.msgraph import MsGraphConnector

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

    from ccf.connectors.msgraph import MsGraphConnector

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
