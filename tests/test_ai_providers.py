"""Unit tests for the Anthropic and OpenAI adapters using mocked HTTP (no network)."""

from __future__ import annotations

import json

import httpx
import pytest

from ccf.ai.providers import build_provider
from ccf.ai.providers.base import (
    GenerateTextRequest,
    ProviderError,
    StructuredGenerationRequest,
)

_SCHEMA = {
    "type": "object",
    "required": ["control_id", "statement"],
    "properties": {"control_id": {"type": "string"}, "statement": {"type": "string"}},
}
_JSON_OUT = '{"control_id": "AC-2", "statement": "ok"}'


def _anthropic_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/v1/models":
        if request.headers.get("x-api-key") == "bad":
            return httpx.Response(401, json={"error": "unauthorized"})
        return httpx.Response(
            200, json={"data": [{"id": "claude-opus-4-8", "display_name": "Opus"}]}
        )
    if request.url.path == "/v1/messages":
        body = json.loads(request.content)
        structured = "schema" in (body.get("system") or "")
        text = _JSON_OUT if structured else "Hello from Claude"
        return httpx.Response(
            200,
            json={
                "model": body["model"],
                "content": [{"type": "text", "text": text}],
                "usage": {"input_tokens": 11, "output_tokens": 7},
            },
        )
    return httpx.Response(404)


def _openai_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/v1/models":
        if request.headers.get("authorization") == "Bearer bad":
            return httpx.Response(401, json={"error": "unauthorized"})
        return httpx.Response(200, json={"data": [{"id": "gpt-5"}]})
    if request.url.path == "/v1/chat/completions":
        body = json.loads(request.content)
        structured = body.get("response_format", {}).get("type") == "json_object"
        content = _JSON_OUT if structured else "Hello from GPT"
        return httpx.Response(
            200,
            json={
                "model": body["model"],
                "choices": [{"message": {"content": content}}],
                "usage": {"prompt_tokens": 9, "completion_tokens": 5},
            },
        )
    return httpx.Response(404)


def _provider(name: str, key: str, handler):
    p = build_provider(name, key, base_url="https://mock.local")
    p._transport = httpx.MockTransport(handler)  # inject mock transport
    return p


@pytest.mark.asyncio
async def test_anthropic_validate_generate_structured() -> None:
    p = _provider("anthropic", "good", _anthropic_handler)
    v = await p.validate_credential()
    assert v.valid and "claude-opus-4-8" in v.models
    t = await p.generate_text(GenerateTextRequest(prompt="hi", model="claude-opus-4-8"))
    assert t.text == "Hello from Claude" and t.input_tokens == 11 and t.output_tokens == 7
    s = await p.generate_structured_output(
        StructuredGenerationRequest(prompt="draft", model="claude-opus-4-8", schema=_SCHEMA)
    )
    assert s.data["control_id"] == "AC-2"


@pytest.mark.asyncio
async def test_anthropic_bad_key() -> None:
    p = _provider("anthropic", "bad", _anthropic_handler)
    v = await p.validate_credential()
    assert not v.valid


@pytest.mark.asyncio
async def test_openai_validate_generate_structured() -> None:
    p = _provider("openai", "good", _openai_handler)
    v = await p.validate_credential()
    assert v.valid and "gpt-5" in v.models
    t = await p.generate_text(GenerateTextRequest(prompt="hi", model="gpt-5"))
    assert t.text == "Hello from GPT" and t.input_tokens == 9
    s = await p.generate_structured_output(
        StructuredGenerationRequest(prompt="draft", model="gpt-5", schema=_SCHEMA)
    )
    assert s.data["statement"] == "ok"


@pytest.mark.asyncio
async def test_openai_bad_key() -> None:
    p = _provider("openai", "bad", _openai_handler)
    v = await p.validate_credential()
    assert not v.valid


def test_unknown_provider_rejected() -> None:
    with pytest.raises(ProviderError):
        build_provider("gemini", "k")


@pytest.mark.asyncio
async def test_structured_schema_violation_raises() -> None:
    def bad_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "model": "m",
                "content": [{"type": "text", "text": "{\"wrong\": true}"}],
                "usage": {},
            },
        )

    p = _provider("anthropic", "good", bad_handler)
    with pytest.raises(ProviderError):
        await p.generate_structured_output(
            StructuredGenerationRequest(prompt="x", model="m", schema=_SCHEMA)
        )
