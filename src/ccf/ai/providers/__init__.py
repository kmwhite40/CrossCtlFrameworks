"""Provider-neutral AI adapter interface and concrete implementations."""

from __future__ import annotations

from .base import (
    AIProvider,
    CredentialValidationResult,
    GenerateTextRequest,
    GenerateTextResponse,
    ModelDescriptor,
    ProviderError,
    StructuredGenerationRequest,
    StructuredGenerationResponse,
)

__all__ = [
    "AIProvider",
    "CredentialValidationResult",
    "GenerateTextRequest",
    "GenerateTextResponse",
    "ModelDescriptor",
    "ProviderError",
    "StructuredGenerationRequest",
    "StructuredGenerationResponse",
    "build_provider",
]


def build_provider(provider: str, api_key: str, *, base_url: str | None = None) -> AIProvider:
    """Construct a provider adapter by name with a decrypted API key."""
    from .anthropic import AnthropicProvider  # noqa: PLC0415
    from .openai import OpenAIProvider  # noqa: PLC0415

    key = (provider or "").lower()
    if key == "anthropic":
        return AnthropicProvider(api_key, base_url=base_url)
    if key == "openai":
        return OpenAIProvider(api_key, base_url=base_url)
    raise ProviderError(f"unknown AI provider '{provider}'")
