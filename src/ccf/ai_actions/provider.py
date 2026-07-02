"""AI action provider — a deterministic, citation-first stub (default) + hook.

The stub renders grounded, reproducible output from the supplied (tenant-scoped)
context with no external calls, so local/dev and tests need no AI provider. When
``CCF_AI_ENABLED`` and an Anthropic key are set the real provider could be wired
here; the contract (``generate`` → ``{content, payload, citations}``) is identical.
"""

from __future__ import annotations

from typing import Any

from .registry import ActionDef


def generate(
    action: ActionDef, context: dict[str, Any], *, provider: str = "stub"
) -> dict[str, Any]:
    """Return ``{content, payload, citations}`` for an action + context."""
    # Only the deterministic stub is implemented; a real provider would branch here.
    return _stub(action, context)


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
