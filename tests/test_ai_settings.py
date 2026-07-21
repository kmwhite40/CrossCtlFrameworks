"""Org-admin AI settings API/UI — role gating, org isolation, credential safety.

The org-scoped AI credential vault + gateway (``ccf.ai.gateway``) already exist;
this covers the admin surface on top of it: an org admin can add/list/test/rotate/
revoke a provider credential, scoped to their own organization, and the raw key is
never present in any response.
"""

from __future__ import annotations

import os

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient

from ccf.ai import gateway
from ccf.ai.providers.base import CredentialValidationResult
from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, User

pytestmark = pytest.mark.usefixtures("fresh_engine")

_KEY_A = "sk-ant-api03-org-a-secret-1234"
_KEY_B = "sk-ant-api03-org-b-secret-5678"


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


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _org_admin(org_name: str, *, role: str = "admin") -> tuple[int, str]:
    """Create an org + a user with the given role; return (org_id, bearer_token)."""
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


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --- add / list / mask -------------------------------------------------------


@pytest.mark.asyncio
async def test_add_list_mask_roundtrip() -> None:
    _org_id, token = await _org_admin("AiSettings Add Org")
    async with _client() as c:
        added = await c.post(
            "/api/ai-settings/providers/anthropic",
            json={"api_key": _KEY_A, "enabled": True, "default_model": "claude-opus-4-8"},
            headers=_auth(token),
        )
        assert added.status_code == 200, added.text
        body = added.json()
        assert body["key_last4"] == "…1234"
        assert body["has_credential"] is True
        assert body["enabled"] is True
        assert "encrypted_credential" not in body
        assert _KEY_A not in added.text

        listed = await c.get("/api/ai-settings/providers", headers=_auth(token))
        assert listed.status_code == 200
        rows = listed.json()
        assert len(rows) == 1
        assert rows[0]["provider"] == "anthropic"
        assert rows[0]["key_last4"] == "…1234"
        assert "encrypted_credential" not in rows[0]
        assert _KEY_A not in listed.text


# --- org isolation -------------------------------------------------------------


@pytest.mark.asyncio
async def test_org_isolation_list_and_mutation() -> None:
    _org_a, token_a = await _org_admin("AiSettings Iso Org A")
    org_b, token_b = await _org_admin("AiSettings Iso Org B")

    async with _client() as c:
        add = await c.post(
            "/api/ai-settings/providers/anthropic",
            json={"api_key": _KEY_A, "enabled": True},
            headers=_auth(token_a),
        )
        assert add.status_code == 200

        # Org B sees nothing of org A's config.
        listed_b = await c.get("/api/ai-settings/providers", headers=_auth(token_b))
        assert listed_b.json() == []

        # Org B "revoking" the same provider name only creates/affects its own row.
        revoke_b = await c.post(
            "/api/ai-settings/providers/anthropic/revoke", headers=_auth(token_b)
        )
        assert revoke_b.status_code == 200
        assert revoke_b.json()["organization_id"] == org_b

        # Org A's config is untouched (still enabled, still has its credential).
        listed_a = await c.get("/api/ai-settings/providers", headers=_auth(token_a))
        rows_a = listed_a.json()
        assert len(rows_a) == 1
        assert rows_a[0]["enabled"] is True
        assert rows_a[0]["has_credential"] is True


# --- role gating ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_non_admin_refused() -> None:
    _org_id, viewer_token = await _org_admin("AiSettings Viewer Org", role="viewer")
    async with _client() as c:
        r = await c.get("/api/ai-settings/providers", headers=_auth(viewer_token))
        assert r.status_code == 403

        r2 = await c.post(
            "/api/ai-settings/providers/anthropic",
            json={"api_key": _KEY_A},
            headers=_auth(viewer_token),
        )
        assert r2.status_code == 403


@pytest.mark.asyncio
async def test_unauthenticated_refused() -> None:
    async with _client() as c:
        r = await c.get("/api/ai-settings/providers")
        assert r.status_code == 401


# --- missing master key --------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_master_key_returns_clear_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CCF_AI_CREDENTIAL_MASTER_KEY", raising=False)
    get_settings.cache_clear()
    _org_id, token = await _org_admin("AiSettings NoKey Org")
    async with _client() as c:
        r = await c.post(
            "/api/ai-settings/providers/anthropic",
            json={"api_key": _KEY_A},
            headers=_auth(token),
        )
        assert r.status_code == 400
        assert "credential storage" in r.json()["detail"].lower()


# --- test-connection (mocked provider, no real network) -----------------------


@pytest.mark.asyncio
async def test_test_connection_uses_mocked_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    _org_id, token = await _org_admin("AiSettings TestConn Org")

    class _StubProvider:
        name = "anthropic"

        async def validate_credential(self):
            return CredentialValidationResult(valid=True, detail="ok")

    monkeypatch.setattr(gateway, "build_provider", lambda *a, **k: _StubProvider())

    async with _client() as c:
        await c.post(
            "/api/ai-settings/providers/anthropic",
            json={"api_key": _KEY_A, "enabled": True},
            headers=_auth(token),
        )
        r = await c.post("/api/ai-settings/providers/anthropic/test", headers=_auth(token))
        assert r.status_code == 200
        assert r.json() == {"provider": "anthropic", "valid": True}

        listed = await c.get("/api/ai-settings/providers", headers=_auth(token))
        assert listed.json()[0]["validated_at"] is not None


@pytest.mark.asyncio
async def test_test_connection_without_credential_errors() -> None:
    _org_id, token = await _org_admin("AiSettings NoCred Org")
    async with _client() as c:
        r = await c.post("/api/ai-settings/providers/anthropic/test", headers=_auth(token))
        assert r.status_code == 400


# --- rotate ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rotate_updates_key_last4() -> None:
    _org_id, token = await _org_admin("AiSettings Rotate Org")
    async with _client() as c:
        await c.post(
            "/api/ai-settings/providers/anthropic",
            json={"api_key": _KEY_A, "enabled": True},
            headers=_auth(token),
        )
        rotated = await c.post(
            "/api/ai-settings/providers/anthropic/rotate",
            json={"api_key": _KEY_B},
            headers=_auth(token),
        )
        assert rotated.status_code == 200
        body = rotated.json()
        assert body["key_last4"] == "…5678"
        assert "encrypted_credential" not in body
        assert _KEY_B not in rotated.text

        # validated_at must be cleared — the new key hasn't been re-validated.
        listed = await c.get("/api/ai-settings/providers", headers=_auth(token))
        assert listed.json()[0]["key_last4"] == "…5678"
        assert listed.json()[0]["validated_at"] is None


@pytest.mark.asyncio
async def test_missing_master_key_blocks_rotate(monkeypatch: pytest.MonkeyPatch) -> None:
    _org_id, token = await _org_admin("AiSettings RotateNoKey Org")
    async with _client() as c:
        await c.post(
            "/api/ai-settings/providers/anthropic",
            json={"api_key": _KEY_A, "enabled": True},
            headers=_auth(token),
        )
    monkeypatch.delenv("CCF_AI_CREDENTIAL_MASTER_KEY", raising=False)
    get_settings.cache_clear()
    async with _client() as c:
        r = await c.post(
            "/api/ai-settings/providers/anthropic/rotate",
            json={"api_key": _KEY_B},
            headers=_auth(token),
        )
        assert r.status_code == 400


# --- revoke / disable ------------------------------------------------------------


@pytest.mark.asyncio
async def test_revoke_disables_config() -> None:
    _org_id, token = await _org_admin("AiSettings Revoke Org")
    async with _client() as c:
        await c.post(
            "/api/ai-settings/providers/anthropic",
            json={"api_key": _KEY_A, "enabled": True},
            headers=_auth(token),
        )
        revoked = await c.post(
            "/api/ai-settings/providers/anthropic/revoke", headers=_auth(token)
        )
        assert revoked.status_code == 200
        assert revoked.json()["enabled"] is False

        listed = await c.get("/api/ai-settings/providers", headers=_auth(token))
        assert listed.json()[0]["enabled"] is False
        # credential itself is left in place (still masked, never returned raw).
        assert listed.json()[0]["has_credential"] is True


# --- admin UI page -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_ui_page_renders_masked_configs_for_admin() -> None:
    _org_id, token = await _org_admin("AiSettings UI Org")
    async with _client() as c:
        await c.post(
            "/api/ai-settings/providers/anthropic",
            json={"api_key": _KEY_A, "enabled": True},
            headers=_auth(token),
        )
        page = await c.get("/admin/ai-settings", headers=_auth(token))
        assert page.status_code == 200
        assert "…1234" in page.text
        assert _KEY_A not in page.text


@pytest.mark.asyncio
async def test_ui_page_refuses_non_admin() -> None:
    _org_id, viewer_token = await _org_admin("AiSettings UI Viewer Org", role="viewer")
    async with _client() as c:
        page = await c.get("/admin/ai-settings", headers=_auth(viewer_token))
        assert page.status_code == 403
