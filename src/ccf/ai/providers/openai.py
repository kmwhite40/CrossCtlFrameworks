"""OpenAI adapter (Chat Completions API)."""

from __future__ import annotations

from typing import Any

import httpx

from . import _structured
from .base import (
    AIProvider,
    CredentialValidationResult,
    EmbedRequest,
    EmbedResponse,
    GenerateTextRequest,
    GenerateTextResponse,
    ModelDescriptor,
    ProviderError,
    StructuredGenerationRequest,
    StructuredGenerationResponse,
)

_DEFAULT_BASE = "https://api.openai.com"


class OpenAIProvider(AIProvider):
    name = "openai"
    supports_embeddings = True

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = 60.0,
    ) -> None:
        self._key = api_key
        self._base = (base_url or _DEFAULT_BASE).rstrip("/")
        self._transport = transport
        self._timeout = timeout

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self._base,
            timeout=self._timeout,
            transport=self._transport,
            headers={
                "authorization": f"Bearer {self._key}",
                "content-type": "application/json",
            },
        )

    async def validate_credential(self) -> CredentialValidationResult:
        try:
            async with self._client() as client:
                resp = await client.get("/v1/models")
            if resp.status_code == 200:
                models = [m.get("id", "") for m in resp.json().get("data", [])]
                return CredentialValidationResult(True, "ok", [m for m in models if m])
            if resp.status_code in (401, 403):
                return CredentialValidationResult(False, "invalid API key")
            return CredentialValidationResult(False, f"unexpected status {resp.status_code}")
        except httpx.HTTPError as exc:
            return CredentialValidationResult(False, f"transport error: {exc}")

    def _messages(self, system: str | None, prompt: str) -> list[dict[str, Any]]:
        msgs: list[dict[str, Any]] = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.append({"role": "user", "content": prompt})
        return msgs

    async def generate_text(self, request: GenerateTextRequest) -> GenerateTextResponse:
        body = {
            "model": request.model,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "messages": self._messages(request.system, request.prompt),
        }
        data = await self._post("/v1/chat/completions", body)
        choice = (data.get("choices") or [{}])[0]
        text = ((choice.get("message") or {}).get("content") or "").strip()
        usage = data.get("usage", {})
        return GenerateTextResponse(
            text=text,
            model=data.get("model", request.model),
            input_tokens=int(usage.get("prompt_tokens", 0)),
            output_tokens=int(usage.get("completion_tokens", 0)),
        )

    async def generate_structured_output(
        self, request: StructuredGenerationRequest
    ) -> StructuredGenerationResponse:
        system = "\n\n".join(
            p for p in (request.system, _structured.schema_instruction(request.schema)) if p
        )
        body = {
            "model": request.model,
            "max_tokens": request.max_tokens,
            "temperature": 0.0,
            "response_format": {"type": "json_object"},
            "messages": self._messages(system, request.prompt),
        }
        data = await self._post("/v1/chat/completions", body)
        choice = (data.get("choices") or [{}])[0]
        text = ((choice.get("message") or {}).get("content") or "").strip()
        usage = data.get("usage", {})
        parsed = _structured.validate(_structured.extract_json(text), request.schema)
        return StructuredGenerationResponse(
            data=parsed,
            model=data.get("model", request.model),
            input_tokens=int(usage.get("prompt_tokens", 0)),
            output_tokens=int(usage.get("completion_tokens", 0)),
        )

    async def list_supported_models(self) -> list[ModelDescriptor]:
        async with self._client() as client:
            resp = await client.get("/v1/models")
        if resp.status_code != 200:
            raise ProviderError(f"could not list models (status {resp.status_code})")
        return [
            ModelDescriptor(m["id"], m.get("id", ""))
            for m in resp.json().get("data", [])
            if m.get("id")
        ]

    async def embed(self, request: EmbedRequest) -> EmbedResponse:
        """Call POST /v1/embeddings and normalise the response.

        The API is not guaranteed to return items in request order, so results are
        sorted by the response's ``index`` field before being handed back — an
        unsorted or truncated batch would silently corrupt the vector store, so both
        the ordering and the count are treated as load-bearing here, not cosmetic.
        """
        payload = {"model": request.model, "input": request.texts}
        data = await self._post("/v1/embeddings", payload)
        rows = data.get("data", [])
        if len(rows) != len(request.texts):
            raise ProviderError(
                f"embedding count mismatch: sent {len(request.texts)}, got {len(rows)}"
            )
        try:
            items = sorted(rows, key=lambda row: int(row["index"]))
            vectors = [[float(x) for x in row["embedding"]] for row in items]
        except (KeyError, TypeError, ValueError) as exc:
            raise ProviderError(f"malformed embedding response: {exc}") from exc
        indices = [int(row["index"]) for row in items]
        if indices != list(range(len(request.texts))):
            raise ProviderError(
                f"embedding response indices {indices} do not match a contiguous "
                f"0..{len(request.texts) - 1} range"
            )
        return EmbedResponse(
            vectors=vectors,
            model=str(data.get("model", request.model)),
            input_tokens=int(data.get("usage", {}).get("prompt_tokens", 0)),
        )

    async def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        try:
            async with self._client() as client:
                resp = await client.post(path, json=body)
        except httpx.HTTPError as exc:
            raise ProviderError(f"transport error: {exc}") from exc
        if resp.status_code != 200:
            raise ProviderError(f"openai error {resp.status_code}: {resp.text[:200]}")
        data: dict[str, Any] = resp.json()
        return data
