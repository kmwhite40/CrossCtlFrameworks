"""Record what a pipeline AI call did, without routing it through run_action --
and derive "was this field AI-written" display signals from that provenance.

``ccf.ai_actions.service.run_action`` takes an *entity* and builds its own prompt,
then gates the result behind human approval. The preparation and assessment
pipelines cannot use it: their prompts are deliberately bounded (one passage, or
one objective plus only the passages retrieval returned) and their outputs are
schema-validated with citations checked against those exact candidates -- and that
boundedness is the safety property. Gating each call behind approval is also
unusable at 98 objectives for a single control.

So :func:`record_ai_run` records provenance and nothing else. It writes the same
``ai_action_*`` rows an approval-gated run would, with ``status="recorded"`` to
distinguish them, so one query over one table answers "which model produced this
verdict, from what evidence, and who accepted it". Acceptance fills in the
reviewer half.

Recording must never fail the work it documents: every failure returns ``None``
and is logged, leaving the caller to store a NULL run id and carry on.

:func:`ai_written_poam_ids` is separate, read-only logic (CISO-02) that lives in
this module because it derives from the same ``ai_action_*`` tables: it is
display/surfacing only, never mutates data, and never fabricates a signal. The
one durable, non-fabricated record that a field was set by an AI action is the
``ai_approved_mutations`` row ``ai_actions.service.approve_run`` writes when it
applies an approved run's declared mutation (see ``_apply_mutation`` in
``ai_actions/service.py``).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..logging import get_logger
from ..models_ai_actions import (
    AiActionCitation,
    AiActionInput,
    AiActionOutput,
    AiActionRun,
    AiApprovedMutation,
)

log = get_logger(__name__)

#: Distinguishes a pipeline-recorded run from one awaiting human approval.
PIPELINE_RUN_STATUS = "recorded"

#: Bumped when a pipeline's prompt construction changes materially, so runs
#: recorded under different prompt shapes stay distinguishable.
PROMPT_VERSION = "v1"


@dataclass(slots=True)
class CitationRef:
    """One piece of evidence a model was shown and cited."""

    source_type: str
    source_id: str
    label: str | None = None
    note: str | None = None


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical(payload: dict[str, Any]) -> str:
    """Stable JSON so the same output always hashes the same."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


async def record_ai_run(
    session: AsyncSession,
    *,
    action_key: str,
    entity_type: str,
    entity_id: str,
    organization_id: int,
    provider: str,
    model: str | None,
    prompt: str,
    output: dict[str, Any],
    citations: list[CitationRef],
    actor: str | None = None,
) -> AiActionRun | None:
    """Record one pipeline AI call. Returns ``None`` if recording failed."""
    settings = get_settings()
    input_hash = _sha256(prompt)
    output_hash = _sha256(_canonical(output))

    try:
        run = AiActionRun(
            organization_id=organization_id,
            action_key=action_key,
            entity_type=entity_type,
            entity_id=entity_id,
            status=PIPELINE_RUN_STATUS,
            provider=provider,
            prompt_version=PROMPT_VERSION,
            input_hash=input_hash,
            output_hash=output_hash,
            actor=actor,
            mutation_applied=False,
            summary={"model": model, "citation_count": len(citations)},
        )
        session.add(run)
        await session.flush()

        # IA-10: the hash proves what ran even when the prompt itself is not retained.
        payload: dict[str, Any] = {"prompt_sha256": input_hash, "model": model}
        if settings.ai_store_prompts:
            payload["prompt"] = prompt
        session.add(
            AiActionInput(
                run_id=run.id,
                entity_type=entity_type,
                entity_id=entity_id,
                payload=payload,
                hash=input_hash,
            )
        )
        session.add(
            AiActionOutput(
                run_id=run.id,
                content=_canonical(output),
                uncited=not citations,
                payload=output,
                hash=output_hash,
            )
        )
        for citation in citations:
            session.add(
                AiActionCitation(
                    run_id=run.id,
                    source_type=citation.source_type,
                    source_id=citation.source_id,
                    label=citation.label,
                    note=citation.note,
                )
            )
        await session.flush()
        return run
    except Exception as exc:
        # A failed flush leaves the session's transaction unusable for anything
        # further -- including the caller's own eventual commit -- until it is
        # rolled back. Recording must not raise, but it also must not leave the
        # session broken behind it, or "the stage carries on" would be a lie.
        await session.rollback()
        log.warning(
            "ai.provenance_record_failed",
            action_key=action_key,
            entity_type=entity_type,
            entity_id=entity_id,
            error=str(exc),
        )
        return None


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
