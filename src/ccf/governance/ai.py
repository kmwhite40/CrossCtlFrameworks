"""AI-assisted authoring — generate tailored compliance content.

Prefers the organization-scoped AI gateway (``ccf.ai.gateway``) when a DB session and
organization id are supplied — resolving the org's configured provider, model, and
envelope-encrypted credential. Falls back to the legacy global ``CCF_ANTHROPIC_API_KEY``
path when no org context is available, and returns ``None`` when neither is configured
so callers fall back to canned/deterministic content.
"""

from __future__ import annotations

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..logging import get_logger

log = get_logger(__name__)

_SYSTEM = (
    "You are a federal compliance writer for CUI / CMMC / FedRAMP systems. "
    "Write concise, factual, assessor-ready prose. No marketing language. "
    "Prefix any content that needs human review with nothing extra — the caller adds markers."
)


def is_configured() -> bool:
    return bool(get_settings().anthropic_api_key)


async def generate(
    prompt: str,
    *,
    max_tokens: int = 700,
    session: AsyncSession | None = None,
    organization_id: int | None = None,
    purpose: str = "authoring",
) -> str | None:
    """Draft text via the org gateway if org context is given, else the legacy key.

    Returns None (never raises) so callers can fall back to deterministic content.
    """
    # Preferred path: organization-scoped gateway (per-org provider + credential).
    if session is not None and organization_id is not None:
        try:
            from ..ai import gateway  # noqa: PLC0415 — lazy to avoid import cycle

            text = await gateway.generate_text(
                session,
                organization_id,
                prompt=prompt,
                purpose=purpose,
                system=_SYSTEM,
                max_tokens=max_tokens,
            )
            return text or None
        except Exception as e:  # gateway unconfigured/failed → fall back
            log.info("ai.gateway_unavailable", error=str(e)[:200])

    # Legacy fallback: single global Anthropic key (deprecated once orgs are configured).
    s = get_settings()
    if not s.anthropic_api_key:
        return None
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                f"{s.anthropic_base_url}/v1/messages",
                headers={
                    "x-api-key": s.anthropic_api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": s.anthropic_model,
                    "max_tokens": max_tokens,
                    "system": _SYSTEM,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
        resp.raise_for_status()
        blocks = resp.json().get("content", [])
        return "".join(b.get("text", "") for b in blocks if b.get("type") == "text").strip() or None
    except Exception as e:
        log.warning("ai.generate_failed", error=str(e)[:200])
        return None


async def draft_narrative(
    control_id: str,
    requirement: str,
    environment: str,
    services: str,
    *,
    session: AsyncSession | None = None,
    organization_id: int | None = None,
) -> str | None:
    return await generate(
        f"Draft a system security plan implementation statement for control {control_id}.\n"
        f"Requirement: {requirement}\nEnvironment: {environment}\n"
        f"Relevant services: {services}\n"
        "Write 2-4 sentences describing how the organization implements it.",
        session=session,
        organization_id=organization_id,
        purpose="ssp_narrative",
    )


async def draft_remediation_plan(
    weakness: str,
    *,
    session: AsyncSession | None = None,
    organization_id: int | None = None,
) -> str | None:
    return await generate(
        f"Draft a POA&M remediation plan (3-5 milestone bullets with rough sequencing) "
        f"for this weakness:\n{weakness}",
        session=session,
        organization_id=organization_id,
        purpose="poam_remediation",
    )
