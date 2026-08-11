"""Evaluate one assessment objective against retrieved evidence.

This is the only place in the engine where a model reasons, and its scope is
bounded three ways: it sees a single objective, only the passages retrieval
surfaced for that objective, and it may cite nothing outside that set. What the
verdict *means* for the control is decided later by application code, and whether
it becomes a finding at all is decided by an assessor.

Retrieval finding nothing is not an error. It yields ``insufficient_evidence``
with an explicit gap, which is the honest answer and the one an assessor needs --
and it skips the model call entirely, since there would be nothing to reason over.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ...ai import gateway
from ...config import get_settings
from ...logging import get_logger
from ...prep import retriever
from ...prep.retriever import RetrievedUnit
from .objectives import Objective

log = get_logger(__name__)

PURPOSE = "assessment.evaluate_objective"

EVALUATION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "verdict": {
            "type": "string",
            "enum": ["satisfied", "not_satisfied", "not_applicable", "insufficient_evidence"],
        },
        "cited_unit_ids": {
            "type": "array",
            "items": {"type": "integer"},
            "description": "Passage ids that support the verdict, from those offered.",
        },
        "gaps": {"type": "array", "items": {"type": "string"}},
        "contradictions": {"type": "array", "items": {"type": "string"}},
        "rationale": {"type": "string"},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
    },
    "required": ["verdict", "cited_unit_ids", "rationale", "confidence"],
    "additionalProperties": False,
}

_SYSTEM_PROMPT = (
    "You evaluate a single NIST SP 800-53A assessment objective against evidence "
    "passages drawn from an organization's own documentation. You are not deciding "
    "whether the control passes and you are not writing an assessment finding -- an "
    "assessor does that, later, using your analysis. Judge only whether the passages "
    "you are shown demonstrate that this one objective is met. Cite only the passage "
    "ids you were given. If the evidence does not settle the question, say "
    "insufficient_evidence rather than guessing."
)


@dataclass(slots=True)
class ObjectiveEvaluation:
    """One objective's verdict, with everything needed to review it."""

    verdict: str
    rationale: str
    confidence: float
    cited_unit_ids: list[int] = field(default_factory=list)
    retrieved_unit_ids: list[int] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)
    model_name: str | None = None


def build_prompt(objective_text: str, units: list[RetrievedUnit]) -> str:
    """Build the evaluation prompt for one objective and its retrieved passages."""
    passages = "\n\n".join(
        f"[{u.unit_id}] (page {', '.join(str(p) for p in u.page_numbers) or 'n/a'}"
        f"{f', {u.section_path}' if u.section_path else ''})\n{u.content}"
        for u in units
    )
    return (
        f"Assessment objective:\n{objective_text}\n\n"
        f"Evidence passages:\n{passages}\n\n"
        "Decide whether these passages demonstrate that the objective is met. "
        "Cite the passage ids that support your verdict. List any gap that keeps "
        "the objective from being fully demonstrated, and any passage that "
        "contradicts another. This is analysis for an assessor, not a finding."
    )


async def evaluate_objective(
    session: AsyncSession,
    *,
    org_id: int,
    control_identifier: str,
    objective: Objective,
    system_id: int | None,
) -> ObjectiveEvaluation:
    """Retrieve evidence for one objective and evaluate it."""
    settings = get_settings()
    units = await retriever.retrieve(
        session,
        org_id=org_id,
        control_identifier=control_identifier,
        query_text=objective.text,
        system_id=system_id,
        limit=settings.assessment_engine_retrieval_limit,
    )
    retrieved_ids = [u.unit_id for u in units]

    if not units:
        log.info(
            "assessment.objective_no_evidence",
            control_identifier=control_identifier,
            label=objective.label,
        )
        return ObjectiveEvaluation(
            verdict="insufficient_evidence",
            rationale="No prepared evidence was retrieved for this objective.",
            confidence=0.0,
            retrieved_unit_ids=[],
            gaps=["No evidence retrieved -- nothing in the prepared corpus matched."],
        )

    data = await gateway.generate_structured(
        session,
        org_id,
        prompt=build_prompt(objective.text, units),
        schema=EVALUATION_SCHEMA,
        purpose=PURPOSE,
        system=_SYSTEM_PROMPT,
    )

    # A model may only cite passages it was actually shown. A malformed id is
    # dropped like any out-of-set id rather than crashing the evaluation --
    # this module owns that guarantee and does not rely on schema validation
    # happening to enforce it two layers away in a provider adapter. Repeats
    # collapse to one entry, first-seen order, so the persisted citation list
    # doesn't misrepresent the weight of evidence.
    offered = set(retrieved_ids)
    cited: list[int] = []
    seen_citations: set[int] = set()
    for raw in data.get("cited_unit_ids", []):
        try:
            unit_id = int(raw)
        except (TypeError, ValueError):
            log.warning("assessment.malformed_citation_id", value=repr(raw))
            continue
        if unit_id in offered and unit_id not in seen_citations:
            cited.append(unit_id)
            seen_citations.add(unit_id)

    return ObjectiveEvaluation(
        verdict=str(data["verdict"]),
        rationale=str(data.get("rationale", "")),
        confidence=float(data.get("confidence", 0.0)),
        cited_unit_ids=cited,
        retrieved_unit_ids=retrieved_ids,
        gaps=[str(g) for g in data.get("gaps", [])],
        contradictions=[str(c) for c in data.get("contradictions", [])],
    )
