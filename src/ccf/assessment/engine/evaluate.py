"""Evaluate one assessment objective against retrieved evidence.

This is the only place in the engine where a model reasons, and its scope is
bounded three ways: it sees a single objective, only the passages retrieval
surfaced for that objective, and it may cite nothing outside that set. What the
verdict *means* for the control is decided later by application code, and whether
it becomes a finding at all is decided by an assessor.

Retrieval finding nothing is not an error. It yields ``insufficient_evidence``
with an explicit gap, which is the honest answer and the one an assessor needs --
and it skips the model call entirely, since there would be nothing to reason over.

Every evaluation -- including the no-model-call path above -- is recorded with
``ccf.ai_actions.provenance.record_ai_run``, citing only the units the model
actually relied on (``cited_unit_ids``), not everything retrieval offered. An
accepted verdict here can become a Security Assessment Report finding and
auto-create a POA&M, so this is the record that answers "which model decided
this, and from what evidence."
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ...ai import gateway
from ...ai_actions.provenance import CitationRef, record_ai_run
from ...config import get_settings
from ...logging import get_logger
from ...prep import retriever
from ...prep.retriever import RetrievedUnit
from .objectives import Objective

log = get_logger(__name__)

PURPOSE = "assessment.evaluate_objective"
ACTION_KEY = "evaluate_assessment_objective"

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
    ai_action_run_id: int | None = None


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


def _citation_label(unit: RetrievedUnit) -> str:
    """Page numbers plus section path, so a citation reads without a join --
    e.g. ``"p. 3, 4 — Access Control > Account Management"``.
    """
    pages = ", ".join(str(p) for p in unit.page_numbers)
    page_part = f"p. {pages}" if pages else "p. n/a"
    return f"{page_part} — {unit.section_path}" if unit.section_path else page_part


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
        rationale = "No prepared evidence was retrieved for this objective."
        gaps = ["No evidence retrieved -- nothing in the prepared corpus matched."]
        # insufficient_evidence-with-no-model-call is still an auditable
        # outcome -- an assessor asking "why is this objective unresolved?"
        # deserves an answer even though no model ran. There is no provider or
        # model to report: record_ai_run's ``provider`` column is NOT NULL, so
        # "none" stands in for "no model call was made" rather than inventing a
        # provider that never ran; ``model=None`` says the same for the
        # nullable model column. The "prompt" passed here was never sent
        # anywhere -- it documents what retrieval was attempted, so the hash
        # (and, if ai_store_prompts is on, the text itself) still answers what
        # this run was for. Zero citations makes AiActionOutput.uncited True,
        # same as any other run that couldn't ground its output in evidence.
        ai_run = await record_ai_run(
            session,
            action_key=ACTION_KEY,
            entity_type="assessment_objective",
            entity_id=objective.label,
            organization_id=org_id,
            provider="none",
            model=None,
            prompt=f"No evidence retrieved for objective {objective.label}: {objective.text}",
            output={"verdict": "insufficient_evidence", "rationale": rationale, "gaps": gaps},
            citations=[],
        )
        return ObjectiveEvaluation(
            verdict="insufficient_evidence",
            rationale=rationale,
            confidence=0.0,
            retrieved_unit_ids=[],
            gaps=gaps,
            ai_action_run_id=ai_run.id if ai_run is not None else None,
        )

    # generate_structured_resolved, not the plain generate_structured: this is
    # the one call site in the app whose output is persisted with provenance
    # weight (an AssessmentObjectiveProposal a FedRAMP citation traces back
    # to), so it needs the resolved model name back, not just the data.
    prompt = build_prompt(objective.text, units)
    result = await gateway.generate_structured_resolved(
        session,
        org_id,
        prompt=prompt,
        schema=EVALUATION_SCHEMA,
        purpose=PURPOSE,
        system=_SYSTEM_PROMPT,
    )
    data = result.data

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

    # One CitationRef per *cited* unit, not one per retrieved unit -- the
    # model may have been shown N passages and relied on only M of them, and
    # the audit record should reflect what it actually used, not everything
    # it was offered.
    units_by_id = {u.unit_id: u for u in units}
    citations = [
        CitationRef(
            source_type="prep_unit",
            source_id=str(unit_id),
            label=_citation_label(units_by_id[unit_id]),
        )
        for unit_id in cited
    ]
    ai_run = await record_ai_run(
        session,
        action_key=ACTION_KEY,
        entity_type="assessment_objective",
        entity_id=objective.label,
        organization_id=org_id,
        provider=result.provider,
        model=result.model,
        prompt=prompt,
        output=data,
        citations=citations,
    )

    return ObjectiveEvaluation(
        verdict=str(data["verdict"]),
        rationale=str(data.get("rationale", "")),
        confidence=float(data.get("confidence", 0.0)),
        cited_unit_ids=cited,
        retrieved_unit_ids=retrieved_ids,
        gaps=[str(g) for g in data.get("gaps", [])],
        contradictions=[str(c) for c in data.get("contradictions", [])],
        model_name=result.model,
        ai_action_run_id=ai_run.id if ai_run is not None else None,
    )
