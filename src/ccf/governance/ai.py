"""AI-assisted authoring (Anthropic) — generate tailored compliance content.

Config-gated on ``CCF_ANTHROPIC_API_KEY``. Drafts implementation narratives,
POA&M remediation plans, and risk statements from the system's real context.
Returns ``None`` when not configured so callers fall back to canned content.
"""

from __future__ import annotations

import httpx

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


async def generate(prompt: str, *, max_tokens: int = 700) -> str | None:
    """Call the Anthropic Messages API; return text or None if unconfigured/failed."""
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
    control_id: str, requirement: str, environment: str, services: str
) -> str | None:
    return await generate(
        f"Draft a system security plan implementation statement for control {control_id}.\n"
        f"Requirement: {requirement}\nEnvironment: {environment}\n"
        f"Relevant services: {services}\n"
        "Write 2-4 sentences describing how the organization implements it."
    )


async def draft_remediation_plan(weakness: str) -> str | None:
    return await generate(
        f"Draft a POA&M remediation plan (3-5 milestone bullets with rough sequencing) "
        f"for this weakness:\n{weakness}"
    )
