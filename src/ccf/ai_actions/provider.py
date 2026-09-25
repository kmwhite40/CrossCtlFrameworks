"""AI action provider — the organization's own gateway, or a grounded stub.

The stub renders reproducible output from the supplied (tenant-scoped) context
with no external call, so local, dev and tests need no AI provider. When the
organization has a credential bound through ``ccf.ai.gateway``, the same
contract is satisfied by a real model instead.

**The provider is reported, never assumed.** ``generate`` returns the provider
and model that actually produced the output, and ``service.run_action`` records
what it is handed. Before this, ``run.provider`` was set from
``settings.ai_provider`` BEFORE the call while this module ignored its argument
and always returned the stub -- so every run on a deployment with
``CCF_AI_ENABLED=true`` recorded a vendor no model had answered, in the one
audit trail whose job is to say what was machine-generated and by what.
Returning it makes that false claim structurally impossible rather than a rule
somebody has to remember.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..ai import gateway
from ..logging import get_logger
from .registry import ActionDef

if TYPE_CHECKING:  # pragma: no cover - typing only
    from sqlalchemy.ext.asyncio import AsyncSession

log = get_logger(__name__)

#: What a model is asked to return. ``citations`` are INDICES into the sources
#: the caller supplied, never free text: a model cannot cite a document that
#: was not given to it, because there is no way to express one. A fabricated
#: citation in a compliance narrative is the worst output this path can
#: produce, so the format makes it unrepresentable rather than discouraged.
_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["content", "citations"],
    "additionalProperties": False,
    "properties": {
        "content": {"type": "string"},
        "citations": {
            "type": "array",
            "items": {"type": "integer", "minimum": 0},
            "description": "Indices of the supplied sources this content rests on.",
        },
        "payload": {"type": "object"},
    },
}

_SYSTEM = (
    "You draft compliance content for a federal authorization package. Use only "
    "the supplied facts and sources. Cite by source index. If the supplied "
    "material does not support a statement, omit the statement rather than "
    "inferring it -- an unsupported sentence in this document is worse than a "
    "missing one."
)


async def generate(
    action: ActionDef,
    context: dict[str, Any],
    *,
    session: AsyncSession | None = None,
    org_id: int | None = None,
) -> dict[str, Any]:
    """Return ``{content, payload, citations, provider, model}``.

    Falls back to the stub -- and says so in ``provider`` -- whenever a real
    call is not possible or does not succeed. A run that failed over to the
    stub and still recorded a vendor would be the same false attribution this
    function exists to prevent.
    """
    if session is None or org_id is None:
        return {**_stub(action, context), "provider": "stub", "model": None}
    try:
        result = await gateway.generate_structured_resolved(
            session,
            org_id,
            prompt=_prompt(action, context),
            schema=_SCHEMA,
            purpose=f"ai_action:{action.key}",
            system=_SYSTEM,
        )
    except Exception:
        log.info("ai_action.stub_fallback", action=action.key)
        return {**_stub(action, context), "provider": "stub", "model": None}

    data = result.data if isinstance(result.data, dict) else {}
    content = str(data.get("content") or "").strip()
    if not content:
        # An empty answer is not an answer. Falling back keeps the action
        # useful and keeps the record honest about which one produced it.
        return {**_stub(action, context), "provider": "stub", "model": None}

    return {
        "content": content,
        "payload": data.get("payload") if isinstance(data.get("payload"), dict) else {},
        "citations": _resolve_citations(context, data.get("citations")),
        "provider": result.provider,
        "model": result.model,
    }


def _prompt(action: ActionDef, context: dict[str, Any]) -> str:
    """The supplied context, rendered with its sources numbered for citation."""
    facts = context.get("facts") or {}
    sources = context.get("sources") or []
    fact_lines = "\n".join(f"- {k}: {v}" for k, v in facts.items()) or "- none"
    source_lines = (
        "\n".join(
            f"[{i}] {s.get('source_type')} {s.get('source_id')}: {s.get('label') or ''}"
            for i, s in enumerate(sources)
        )
        or "(no sources)"
    )
    label = context.get("label") or f"{context.get('target_type')} {context.get('target_id')}"
    return (
        f"Task: {action.title}. {action.description}\n\n"
        f"Subject: {label}\n\nFacts:\n{fact_lines}\n\nSources:\n{source_lines}"
    )


def _resolve_citations(context: dict[str, Any], raw: Any) -> list[dict[str, Any]]:
    """Map returned indices back to the supplied sources.

    An index outside the supplied range is DROPPED, not rendered. The model
    cannot cite a source it was not given, so a citation that does not resolve
    is a model error and a dropped one is the safe reading -- the action's own
    ``citation_required`` flag then reports the shortfall through the normal
    path, rather than a plausible-looking reference to nothing reaching a
    reviewer.
    """
    sources = context.get("sources") or []
    out: list[dict[str, Any]] = []
    seen: set[int] = set()
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, int) or item in seen or not 0 <= item < len(sources):
            continue
        seen.add(item)
        s = sources[item]
        out.append(
            {
                "source_type": s["source_type"],
                "source_id": str(s.get("source_id") or ""),
                "label": s.get("label"),
            }
        )
    return out


def _stub(action: ActionDef, context: dict[str, Any]) -> dict[str, Any]:
    label = context.get("label") or f"{context.get('target_type')} {context.get('target_id')}"
    facts = context.get("facts") or {}
    sources = context.get("sources") or []
    fact_lines = "; ".join(f"{k}={v}" for k, v in facts.items()) or "no additional facts"

    content = (
        f"[{action.key}] Draft for {label}.\n"
        f"Context: {fact_lines}.\n"
        f"Grounded in {len(sources)} source(s)."
    )

    payload: dict[str, Any] = {"action": action.key, "target": label, "facts": facts}
    # Structured suggestions for the actions that can mutate on approval.
    if action.allowed_mutation == "create_task":
        payload["task"] = {
            "title": f"Remediate: {label}",
            "priority": "high" if str(facts.get("severity")) in ("high", "critical") else "medium",
            "owner": facts.get("owner") or context.get("owner"),
        }
    elif action.allowed_mutation == "set_poam_remediation":
        payload["remediation_plan"] = (
            f"Proposed remediation for {label}: address the weakness, attach evidence, "
            f"and schedule verification. (AI draft — review before use.)"
        )
    elif action.allowed_mutation == "create_control_test":
        payload["control_test"] = {
            "name": f"Test for {facts.get('control_id') or label}",
            "control_id": str(facts.get("control_id") or context.get("target_id")),
            "method": "manual",
            "frequency": "quarterly",
        }
    elif action.allowed_mutation == "set_response_suggestion":
        payload["suggested_answer"] = "yes"
        payload["rationale"] = f"Based on {len(sources)} cited source(s) for {label}."

    citations = [
        {"source_type": s["source_type"], "source_id": str(s.get("source_id") or ""),
         "label": s.get("label")}
        for s in sources
    ]
    return {"content": content, "payload": payload, "citations": citations}
