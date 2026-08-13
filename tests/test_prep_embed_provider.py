"""Embedding support on the provider interface and the org-scoped gateway."""

from __future__ import annotations

import pytest

from ccf.ai import gateway
from ccf.ai.providers import build_provider
from ccf.ai.providers.base import AIProvider, EmbedRequest, EmbedResponse, ProviderError
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization

pytestmark = pytest.mark.usefixtures("fresh_engine")

_KEY = "sk-test-embedding-key-0001"


@pytest.fixture(autouse=True)
def _master_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CCF_AI_CREDENTIAL_MASTER_KEY", "unit-test-master-key-32-chars-xx")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


class _FakeEmbedProvider(AIProvider):
    """Deterministic adapter — no network, stable vectors."""

    name = "fake"
    supports_embeddings = True

    async def validate_credential(self):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    async def generate_text(self, request):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    async def generate_structured_output(self, request):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    async def list_supported_models(self):  # type: ignore[no-untyped-def]
        return []

    async def embed(self, request: EmbedRequest) -> EmbedResponse:
        return EmbedResponse(
            vectors=[[float(len(text) % 7)] * 1024 for text in request.texts],
            model=request.model,
            input_tokens=sum(len(t) for t in request.texts) // 4,
        )


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return int(org.id)


async def test_anthropic_reports_no_embedding_support() -> None:
    provider = build_provider("anthropic", _KEY)
    assert provider.supports_embeddings is False


async def test_calling_embed_on_an_unsupported_provider_raises_provider_error() -> None:
    provider = build_provider("anthropic", _KEY)
    with pytest.raises(ProviderError) as exc:
        await provider.embed(EmbedRequest(texts=["hello"], model="claude-opus-4-8"))
    assert "embedding" in str(exc.value).lower()


async def test_openai_reports_embedding_support() -> None:
    provider = build_provider("openai", _KEY)
    assert provider.supports_embeddings is True


async def test_gateway_embed_returns_one_vector_per_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = await _org("embed-org")
    async with session_scope() as s:
        await gateway.set_credential(
            s, org_id, "openai", api_key=_KEY, enabled=True,
            default_model="text-embedding-3-small",
        )
    monkeypatch.setattr(gateway, "build_provider", lambda *a, **kw: _FakeEmbedProvider())
    async with session_scope() as s:
        response = await gateway.embed(
            s, org_id, texts=["one", "two", "three"], purpose="prep.classify"
        )
    assert len(response.vectors) == 3
    assert all(len(v) == 1024 for v in response.vectors)


async def test_gateway_embed_rejects_an_empty_batch() -> None:
    org_id = await _org("embed-empty")
    async with session_scope() as s:
        with pytest.raises(gateway.GatewayError):
            await gateway.embed(s, org_id, texts=[], purpose="prep.classify")
