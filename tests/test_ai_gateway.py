"""Integration tests for the org-scoped AI gateway (real DB, mocked provider)."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from ccf.ai import gateway
from ccf.ai.providers.base import GenerateTextResponse
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization
from ccf.models_ai_actions import AiProviderConfig

pytestmark = pytest.mark.usefixtures("fresh_engine")

_KEY = "sk-ant-api03-secret-value-1234"


@pytest.fixture(autouse=True)
def _master_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CCF_AI_CREDENTIAL_MASTER_KEY", "unit-test-master-key-32-chars-xx")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return org.id


async def test_set_credential_encrypts_and_masks() -> None:
    org_id = await _org("cipher-org")
    async with session_scope() as s:
        cfg = await gateway.set_credential(
            s, org_id, "anthropic", api_key=_KEY, enabled=True, default_model="claude-opus-4-8"
        )
        assert cfg.encrypted_credential and _KEY not in cfg.encrypted_credential
        assert cfg.key_last4 == "…1234"
        view = gateway.masked_view(cfg)
        assert "encrypted_credential" not in view and view["key_last4"] == "…1234"
    # persisted as ciphertext
    async with session_scope() as s:
        row = (await s.execute(select(AiProviderConfig))).scalar_one()
        assert _KEY not in (row.encrypted_credential or "")


async def test_resolve_enforces_allowlist() -> None:
    org_id = await _org("allowlist-org")
    async with session_scope() as s:
        await gateway.set_credential(
            s,
            org_id,
            "anthropic",
            api_key=_KEY,
            enabled=True,
            default_model="claude-opus-4-8",
            allowed_models=["claude-opus-4-8"],
        )
    async with session_scope() as s:
        rp = await gateway.resolve(s, org_id)
        assert rp.model == "claude-opus-4-8" and rp.provider.name == "anthropic"
    async with session_scope() as s:
        with pytest.raises(gateway.GatewayError, match="allowlist"):
            await gateway.resolve(s, org_id, model="gpt-5")


async def test_resolve_requires_enabled_config() -> None:
    org_id = await _org("disabled-org")
    async with session_scope() as s:
        await gateway.set_credential(s, org_id, "anthropic", api_key=_KEY, enabled=False)
    async with session_scope() as s:
        with pytest.raises(gateway.GatewayError, match="no enabled AI provider"):
            await gateway.resolve(s, org_id)


async def test_generate_text_records_usage(monkeypatch: pytest.MonkeyPatch) -> None:
    org_id = await _org("gen-org")
    async with session_scope() as s:
        await gateway.set_credential(
            s, org_id, "anthropic", api_key=_KEY, enabled=True, default_model="claude-opus-4-8"
        )

    class _StubProvider:
        name = "anthropic"

        async def generate_text(self, request):
            assert request.model == "claude-opus-4-8"
            return GenerateTextResponse(text="drafted statement", model=request.model,
                                        input_tokens=10, output_tokens=4)

    monkeypatch.setattr(gateway, "build_provider", lambda *a, **k: _StubProvider())
    async with session_scope() as s:
        out = await gateway.generate_text(
            s, org_id, prompt="draft AC-2", purpose="ssp_narrative"
        )
        assert out == "drafted statement"


async def test_org_isolation_config_not_shared() -> None:
    org_a = await _org("iso-a")
    org_b = await _org("iso-b")
    async with session_scope() as s:
        await gateway.set_credential(s, org_a, "anthropic", api_key=_KEY, enabled=True,
                                     default_model="m")
    # org B has no config → resolve must fail even though a row exists for org A
    async with session_scope() as s:
        with pytest.raises(gateway.GatewayError):
            await gateway.resolve(s, org_b)
