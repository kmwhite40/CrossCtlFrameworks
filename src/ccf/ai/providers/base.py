"""Provider-neutral AI adapter interface.

SSP generation and other consumers depend on this interface, never on a specific
vendor SDK, so the model vendor is a runtime choice per organization. Concrete
adapters (Anthropic, OpenAI) translate these requests to each vendor's HTTP API and
normalize the responses back to these dataclasses.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


class ProviderError(RuntimeError):
    """Adapter-level failure (auth, transport, malformed response)."""


@dataclass(slots=True)
class CredentialValidationResult:
    valid: bool
    detail: str = ""
    models: list[str] = field(default_factory=list)


@dataclass(slots=True)
class GenerateTextRequest:
    prompt: str
    model: str
    system: str | None = None
    max_tokens: int = 1024
    temperature: float = 0.2


@dataclass(slots=True)
class GenerateTextResponse:
    text: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass(slots=True)
class StructuredGenerationRequest:
    prompt: str
    model: str
    schema: dict[str, Any]
    system: str | None = None
    max_tokens: int = 1024


@dataclass(slots=True)
class StructuredGenerationResponse:
    data: dict[str, Any]
    model: str
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass(slots=True)
class ModelDescriptor:
    id: str
    label: str = ""


class AIProvider(ABC):
    """A vendor adapter constructed with an already-decrypted API key."""

    name: str = "base"

    @abstractmethod
    async def validate_credential(self) -> CredentialValidationResult: ...

    @abstractmethod
    async def generate_text(self, request: GenerateTextRequest) -> GenerateTextResponse: ...

    @abstractmethod
    async def generate_structured_output(
        self, request: StructuredGenerationRequest
    ) -> StructuredGenerationResponse: ...

    @abstractmethod
    async def list_supported_models(self) -> list[ModelDescriptor]: ...
