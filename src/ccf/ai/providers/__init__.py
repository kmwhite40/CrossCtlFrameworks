"""Provider-neutral AI adapter interface and concrete implementations."""

from __future__ import annotations

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

__all__ = [
    "SUPPORTED_PROVIDERS",
    "AIProvider",
    "CredentialValidationResult",
    "EmbedRequest",
    "EmbedResponse",
    "GenerateTextRequest",
    "GenerateTextResponse",
    "ModelDescriptor",
    "ProviderError",
    "StructuredGenerationRequest",
    "StructuredGenerationResponse",
    "build_provider",
]


#: Providers this build can actually construct.
#:
#: The single source for both the settings page's options and the check in
#: ``gateway.set_credential``. They were two separate lists that happened to
#: agree: a provider added here and not there was unofferable, and one added
#: there and not here stored an *enabled* credential whose every use raised
#: ``unknown AI provider``.
SUPPORTED_PROVIDERS: tuple[str, ...] = ("anthropic", "openai")


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
