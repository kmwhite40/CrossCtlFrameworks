"""Org-admin connector credential API (IA-05) — production-path HTTP tests.

Covers the functional regression: ``credentials.set_credential`` existed but
no route ever called it, so no organization could bind a connector credential
over HTTP, and ``ssp.py``'s ``/connectors/{key}/verify`` +
``/projects/{id}/autofill`` always resolved ``configured=False`` for every
org. This exercises the real routes end to end: an admin binds a credential
(stored encrypted, response masked), verify/autofill for that org then see it
configured, another org does not, and a non-admin is refused.
"""

from __future__ import annotations

import os

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.connectors.msgraph import MsGraphConnector
from ccf.db import session_scope
from ccf.models import Organization, SSPControlEntry, SSPProject, User

pytestmark = pytest.mark.usefixtures("fresh_engine")

_MSGRAPH_SECRET = {
    "tenant_id": "tenant-1",
    "client_id": "client-1",
    "client_secret": "topsecret1234",
}


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def _master_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CCF_AI_CREDENTIAL_MASTER_KEY", "unit-test-master-key-32-chars-xx")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _auth_enabled() -> None:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _stub_msgraph_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never make a real network call — verify()/capture() are stubbed to
    reflect only whether a credential was actually passed to the connector."""

    async def fake_verify(self: MsGraphConnector) -> dict:
        if not self.is_configured():
            return {"connected": False, "reason": "graph credentials not configured"}
        return {"connected": True, "tenant": self.credential.get("tenant_id")}

    async def fake_capture(self: MsGraphConnector) -> list:
        from ccf.connectors import CapturedParameter  # noqa: PLC0415

        if not self.is_configured():
            return []
        return [
            CapturedParameter(
                odp_key="inactivity_period",
                value="15 minutes",
                nist_id="3.1.10",
                source="mock",
            )
        ]

    monkeypatch.setattr(MsGraphConnector, "verify", fake_verify)
    monkeypatch.setattr(MsGraphConnector, "capture", fake_capture)


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _org_admin(org_name: str, *, role: str = "admin") -> tuple[int, str]:
    async with session_scope() as s:
        org = Organization(name=org_name)
        s.add(org)
        await s.flush()
        user = User(
            email=f"{role}@{org_name.lower().replace(' ', '-')}.test",
            organization_id=org.id,
            role=role,
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(user)
        await s.flush()
        return org.id, user.api_token


async def _ssp_project_with_entry(org_id: int, nist_id: str = "3.1.10") -> int:
    async with session_scope() as s:
        proj = SSPProject(organization_id=org_id, customer_name="Cust", platform="m365")
        s.add(proj)
        await s.flush()
        s.add(
            SSPControlEntry(
                project_id=proj.id, control_id="AC-11", nist_id=nist_id, odp_values={}
            )
        )
        await s.flush()
        return proj.id


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --- bind / list / mask -------------------------------------------------------


@pytest.mark.asyncio
async def test_bind_list_mask_roundtrip() -> None:
    _org_id, token = await _org_admin("ConnSettings Add Org")
    async with _client() as c:
        bound = await c.post(
            "/api/connector-settings/credentials/msgraph",
            json={"secret": _MSGRAPH_SECRET},
            headers=_auth(token),
        )
        assert bound.status_code == 200, bound.text
        body = bound.json()
        assert body["key_last4"] == "…1234"
        assert body["has_credential"] is True
        assert "encrypted_credential" not in body
        assert _MSGRAPH_SECRET["client_secret"] not in bound.text

        listed = await c.get("/api/connector-settings/credentials", headers=_auth(token))
        assert listed.status_code == 200
        rows = listed.json()
        assert len(rows) == 1
        assert rows[0]["connector_type"] == "msgraph"
        assert rows[0]["key_last4"] == "…1234"
        assert _MSGRAPH_SECRET["client_secret"] not in listed.text


@pytest.mark.asyncio
async def test_bind_rejects_unknown_connector_type() -> None:
    _org_id, token = await _org_admin("ConnSettings BadType Org")
    async with _client() as c:
        r = await c.post(
            "/api/connector-settings/credentials/not_a_real_connector",
            json={"secret": {"x": "y"}},
            headers=_auth(token),
        )
        assert r.status_code == 422


# --- org isolation -------------------------------------------------------------


@pytest.mark.asyncio
async def test_org_isolation_list_and_mutation() -> None:
    _org_a, token_a = await _org_admin("ConnSettings Iso Org A")
    org_b, token_b = await _org_admin("ConnSettings Iso Org B")

    async with _client() as c:
        add = await c.post(
            "/api/connector-settings/credentials/msgraph",
            json={"secret": _MSGRAPH_SECRET},
            headers=_auth(token_a),
        )
        assert add.status_code == 200

        listed_b = await c.get("/api/connector-settings/credentials", headers=_auth(token_b))
        assert listed_b.json() == []

        # org_b binding its own credential only affects its own row.
        add_b = await c.post(
            "/api/connector-settings/credentials/msgraph",
            json={"secret": {"tenant_id": "t2", "client_id": "c2", "client_secret": "orgBsecret"}},
            headers=_auth(token_b),
        )
        assert add_b.status_code == 200
        assert add_b.json()["organization_id"] == org_b
        assert add_b.json()["key_last4"] == "…cret"

        listed_a = await c.get("/api/connector-settings/credentials", headers=_auth(token_a))
        assert len(listed_a.json()) == 1
        assert listed_a.json()[0]["key_last4"] == "…1234"


# --- role gating ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_non_admin_refused() -> None:
    _org_id, viewer_token = await _org_admin("ConnSettings Viewer Org", role="viewer")
    async with _client() as c:
        r = await c.get("/api/connector-settings/credentials", headers=_auth(viewer_token))
        assert r.status_code == 403

        r2 = await c.post(
            "/api/connector-settings/credentials/msgraph",
            json={"secret": _MSGRAPH_SECRET},
            headers=_auth(viewer_token),
        )
        assert r2.status_code == 403


@pytest.mark.asyncio
async def test_unauthenticated_refused() -> None:
    async with _client() as c:
        r = await c.get("/api/connector-settings/credentials")
        assert r.status_code == 401


# --- remove --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_remove_clears_credential() -> None:
    _org_id, token = await _org_admin("ConnSettings Remove Org")
    async with _client() as c:
        await c.post(
            "/api/connector-settings/credentials/msgraph",
            json={"secret": _MSGRAPH_SECRET},
            headers=_auth(token),
        )
        removed = await c.delete(
            "/api/connector-settings/credentials/msgraph", headers=_auth(token)
        )
        assert removed.status_code == 200
        assert removed.json()["has_credential"] is False

        listed = await c.get("/api/connector-settings/credentials", headers=_auth(token))
        assert listed.json()[0]["has_credential"] is False


@pytest.mark.asyncio
async def test_remove_without_binding_404s() -> None:
    _org_id, token = await _org_admin("ConnSettings RemoveNone Org")
    async with _client() as c:
        r = await c.delete(
            "/api/connector-settings/credentials/msgraph", headers=_auth(token)
        )
        assert r.status_code == 404


# --- verify / autofill wiring (ssp.py) ------------------------------------------


@pytest.mark.asyncio
async def test_verify_and_autofill_see_configured_after_binding() -> None:
    org_id, token = await _org_admin("ConnSettings Verify Org")
    proj_id = await _ssp_project_with_entry(org_id)

    async with _client() as c:
        # Before binding: not configured.
        v0 = await c.post("/api/ssp/connectors/msgraph/verify", headers=_auth(token))
        assert v0.status_code == 200
        assert v0.json()["configured"] is False

        a0 = await c.post(
            f"/api/ssp/projects/{proj_id}/autofill",
            params={"connector": "msgraph", "apply": "true"},
            headers=_auth(token),
        )
        assert a0.json()["configured"] is False
        assert a0.json()["applied"] == 0

        # Bind the org's own credential over HTTP.
        bound = await c.post(
            "/api/connector-settings/credentials/msgraph",
            json={"secret": _MSGRAPH_SECRET},
            headers=_auth(token),
        )
        assert bound.status_code == 200

        # Now verify sees it configured and connected.
        v1 = await c.post("/api/ssp/connectors/msgraph/verify", headers=_auth(token))
        assert v1.status_code == 200
        assert v1.json()["configured"] is True
        assert v1.json()["connected"] is True
        assert v1.json()["tenant"] == "tenant-1"

        # And autofill actually applies the captured ODP value.
        a1 = await c.post(
            f"/api/ssp/projects/{proj_id}/autofill",
            params={"connector": "msgraph", "apply": "true"},
            headers=_auth(token),
        )
        assert a1.status_code == 200, a1.text
        body = a1.json()
        assert body["configured"] is True
        assert body["applied"] == 1
        assert body["captured"][0]["value"] == "15 minutes"

        got = await c.get(f"/api/ssp/projects/{proj_id}", headers=_auth(token))
        entries = got.json()["entries"]
        entry = next(e for e in entries if e["nist_id"] == "3.1.10")
        assert entry["odp_values"]["inactivity_period"] == "15 minutes"


@pytest.mark.asyncio
async def test_verify_and_autofill_do_not_leak_across_orgs() -> None:
    _org_a, token_a = await _org_admin("ConnSettings Cred Org A")
    org_b, token_b = await _org_admin("ConnSettings Cred Org B")
    proj_b = await _ssp_project_with_entry(org_b)

    async with _client() as c:
        bound = await c.post(
            "/api/connector-settings/credentials/msgraph",
            json={"secret": _MSGRAPH_SECRET},
            headers=_auth(token_a),
        )
        assert bound.status_code == 200

        # org_b never bound its own credential -> still not configured, even
        # though org_a's credential exists in the same connector_configs table.
        v_b = await c.post("/api/ssp/connectors/msgraph/verify", headers=_auth(token_b))
        assert v_b.json()["configured"] is False
        assert v_b.json()["connected"] is False

        a_b = await c.post(
            f"/api/ssp/projects/{proj_b}/autofill",
            params={"connector": "msgraph", "apply": "true"},
            headers=_auth(token_b),
        )
        assert a_b.json()["configured"] is False
        assert a_b.json()["applied"] == 0
