"""Organization-scoped AI gateway.

The single choke point for making an AI call on behalf of an organization: it
resolves the org's enabled provider config, decrypts the credential (only here),
enforces the model allowlist, invokes the adapter, and records usage — without ever
logging or returning the raw key. All other application code calls the gateway, not
a provider adapter directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..logging import get_logger
from ..models_ai_actions import AiProviderConfig
from .cipher import build_cipher, mask
from .providers import build_provider
from .providers.base import (
    AIProvider,
    GenerateTextRequest,
    StructuredGenerationRequest,
)

log = get_logger(__name__)


class GatewayError(RuntimeError):
    """No usable provider/credential/model for the requested organization."""


@dataclass(slots=True)
class ResolvedProvider:
    config: AiProviderConfig
    provider: AIProvider
    model: str


def masked_view(cfg: AiProviderConfig) -> dict[str, Any]:
    """A safe, credential-free serialization for API/UI (never the token)."""
    return {
        "id": cfg.id,
        "organization_id": cfg.organization_id,
        "provider": cfg.provider,
        "enabled": cfg.enabled,
        "default_model": cfg.default_model,
        "allowed_models": cfg.allowed_models or [],
        "key_last4": cfg.key_last4,
        "has_credential": bool(cfg.encrypted_credential),
        "validated_at": cfg.validated_at.isoformat() if cfg.validated_at else None,
        "rotated_at": cfg.rotated_at.isoformat() if cfg.rotated_at else None,
    }


async def _load_config(
    session: AsyncSession, org_id: int, provider: str | None
) -> AiProviderConfig | None:
    stmt = select(AiProviderConfig).where(
        AiProviderConfig.organization_id == org_id,  # defense-in-depth beyond RLS
        AiProviderConfig.enabled.is_(True),
    )
    if provider:
        stmt = stmt.where(AiProviderConfig.provider == provider)
    stmt = stmt.order_by(AiProviderConfig.id)
    return (await session.execute(stmt)).scalars().first()


async def set_credential(
    session: AsyncSession,
    org_id: int,
    provider: str,
    *,
    api_key: str | None = None,
    enabled: bool | None = None,
    default_model: str | None = None,
    allowed_models: list[str] | None = None,
    actor: str | None = None,
) -> AiProviderConfig:
    """Create or update an org's provider config; encrypt the key if supplied.

    The plaintext key is enveloped immediately and never stored or logged; only the
    last-4 identifier is retained for display.
    """
    now = datetime.now(UTC)
    cfg = (
        await session.execute(
            select(AiProviderConfig).where(
                AiProviderConfig.organization_id == org_id,
                AiProviderConfig.provider == provider,
            )
        )
    ).scalar_one_or_none()
    if cfg is None:
        cfg = AiProviderConfig(organization_id=org_id, provider=provider, created_by=actor)
        session.add(cfg)
    if api_key:
        cipher = build_cipher(get_settings())  # raises if credential storage unavailable
        cfg.encrypted_credential = cipher.encrypt(api_key)
        cfg.key_last4 = mask(api_key)
        cfg.rotated_at = now
        cfg.validated_at = None  # must be re-validated after rotation
    if enabled is not None:
        cfg.enabled = enabled
    if default_model is not None:
        cfg.default_model = default_model
    if allowed_models is not None:
        cfg.allowed_models = allowed_models
    await session.flush()
    log.info(
        "ai.gateway.config_saved",
        org_id=org_id,
        provider=provider,
        enabled=cfg.enabled,
        rotated=bool(api_key),
        key_last4=cfg.key_last4,
    )
    return cfg


def _decrypt_key(cfg: AiProviderConfig) -> str:
    if not cfg.encrypted_credential:
        raise GatewayError(f"provider '{cfg.provider}' has no stored credential")
    return build_cipher(get_settings()).decrypt(cfg.encrypted_credential)


async def resolve(
    session: AsyncSession, org_id: int, *, provider: str | None = None, model: str | None = None
) -> ResolvedProvider:
    """Resolve an org to a ready-to-call provider adapter + effective model."""
    cfg = await _load_config(session, org_id, provider)
    if cfg is None:
        raise GatewayError(f"no enabled AI provider configured for organization {org_id}")
    chosen = model or cfg.default_model or get_settings().ai_model
    if not chosen:
        raise GatewayError(f"no model specified and no default set for '{cfg.provider}'")
    allow = cfg.allowed_models or []
    if allow and chosen not in allow:
        raise GatewayError(f"model '{chosen}' is not in the allowlist for '{cfg.provider}'")
    adapter = build_provider(cfg.provider, _decrypt_key(cfg))
    return ResolvedProvider(config=cfg, provider=adapter, model=chosen)


async def validate_credential(session: AsyncSession, org_id: int, provider: str) -> bool:
    """Test-connection: validate the stored key with the vendor; stamp validated_at."""
    cfg = (
        await session.execute(
            select(AiProviderConfig).where(
                AiProviderConfig.organization_id == org_id,
                AiProviderConfig.provider == provider,
            )
        )
    ).scalar_one_or_none()
    if cfg is None or not cfg.encrypted_credential:
        raise GatewayError("no stored credential to validate")
    adapter = build_provider(provider, _decrypt_key(cfg))
    result = await adapter.validate_credential()
    if result.valid:
        cfg.validated_at = datetime.now(UTC)
        await session.flush()
    log.info("ai.gateway.validate", org_id=org_id, provider=provider, valid=result.valid)
    return result.valid


async def generate_text(
    session: AsyncSession,
    org_id: int,
    *,
    prompt: str,
    purpose: str,
    provider: str | None = None,
    model: str | None = None,
    system: str | None = None,
    max_tokens: int = 1024,
    actor: str | None = None,
) -> str:
    """Resolve the org's provider and generate text; records usage, never the key."""
    rp = await resolve(session, org_id, provider=provider, model=model)
    resp = await rp.provider.generate_text(
        GenerateTextRequest(prompt=prompt, model=rp.model, system=system, max_tokens=max_tokens)
    )
    log.info(
        "ai.gateway.generate",
        org_id=org_id,
        provider=rp.config.provider,
        model=rp.model,
        purpose=purpose,
        actor=actor,
        prompt_chars=len(prompt),
        input_tokens=resp.input_tokens,
        output_tokens=resp.output_tokens,
    )
    return resp.text


async def generate_structured(
    session: AsyncSession,
    org_id: int,
    *,
    prompt: str,
    schema: dict[str, Any],
    purpose: str,
    provider: str | None = None,
    model: str | None = None,
    system: str | None = None,
    max_tokens: int = 1024,
    actor: str | None = None,
) -> dict[str, Any]:
    """Resolve the org's provider and generate schema-validated structured output."""
    rp = await resolve(session, org_id, provider=provider, model=model)
    resp = await rp.provider.generate_structured_output(
        StructuredGenerationRequest(
            prompt=prompt, model=rp.model, schema=schema, system=system, max_tokens=max_tokens
        )
    )
    log.info(
        "ai.gateway.generate_structured",
        org_id=org_id,
        provider=rp.config.provider,
        model=rp.model,
        purpose=purpose,
        actor=actor,
        input_tokens=resp.input_tokens,
        output_tokens=resp.output_tokens,
    )
    return resp.data
