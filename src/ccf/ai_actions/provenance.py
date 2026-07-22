"""Derive "was this field AI-written" display signals from ai_actions provenance.

Display/surfacing only (CISO-02): never mutates data, never fabricates a
signal. The one durable, non-fabricated record that a field was set by an AI
action is the ``ai_approved_mutations`` row ``ai_actions.service.approve_run``
writes when it applies an approved run's declared mutation (see
``_apply_mutation`` in ``ai_actions/service.py``).
"""

from __future__ import annotations

from typing import Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models_ai_actions import AiApprovedMutation


class _HasRemediation(Protocol):
    id: int
    remediation_plan: str | None


async def ai_written_poam_ids(
    session: AsyncSession, poams: list[_HasRemediation]
) -> set[int]:
    """POA&M ids whose *current* ``remediation_plan`` still matches the text an
    approved ``set_poam_remediation`` AI action mutation wrote.

    Comparing against the current field value (rather than just "an AI run
    ever touched this POA&M") means a POA&M whose AI-drafted remediation was
    later hand-edited stops showing the AI badge, instead of leaving a stale
    marker on human-reviewed content.
    """
    ids = [p.id for p in poams if getattr(p, "remediation_plan", None)]
    if not ids:
        return set()
    rows = (
        await session.execute(
            select(AiApprovedMutation.target_id, AiApprovedMutation.payload)
            .where(AiApprovedMutation.target_type == "poam")
            .where(AiApprovedMutation.mutation_type == "set_poam_remediation")
            .where(AiApprovedMutation.target_id.in_([str(i) for i in ids]))
            .order_by(AiApprovedMutation.created_at)
        )
    ).all()
    # Later rows win (a POA&M can have more than one approved AI draft over
    # time) — keep the most recently approved mutation's text per target.
    last_ai_text_by_id: dict[str, str] = {}
    for target_id, payload in rows:
        text = (payload or {}).get("remediation_plan")
        if text:
            last_ai_text_by_id[target_id] = text
    current_by_id = {str(p.id): p.remediation_plan for p in poams}
    return {
        int(pid)
        for pid, ai_text in last_ai_text_by_id.items()
        if current_by_id.get(pid) == ai_text
    }
