"""Typed AI action registry — declares each action's contract.

Each :class:`ActionDef` states its allowed input entity types, whether a citation
is required, whether human approval is required, and which authoritative mutation
(if any) approval may apply. The registry is seeded into ``ai_action_definitions``
so it is inspectable via the API, but the source of truth is this module.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models_ai_actions import AiActionDefinition


@dataclass(frozen=True)
class ActionDef:
    key: str
    title: str
    description: str
    input_entity_types: tuple[str, ...]
    requires_approval: bool = True
    citation_required: bool = True
    allowed_mutation: str | None = None  # set_poam_remediation|create_task|create_control_test|…
    output_kind: str = "text"
    guardrails: tuple[str, ...] = field(default_factory=tuple)


_DEFS: list[ActionDef] = [
    ActionDef("draft_questionnaire_answer", "Draft questionnaire answer",
              "Suggest an answer for a vendor questionnaire question from evidence + policies.",
              ("questionnaire_response",), True, True, "set_response_suggestion"),
    ActionDef("find_evidence_for_control", "Find evidence for a control",
              "Recommend existing evidence (and gaps) for a control on a system.",
              ("control", "system"), False, True, None),
    ActionDef("explain_failed_ksi", "Explain a failed KSI",
              "Explain why a KSI is failing and what would remediate it.",
              ("ksi", "system"), False, False, None),
    ActionDef("draft_poam_remediation", "Draft POA&M remediation",
              "Draft a remediation plan for a POA&M.",
              ("poam",), True, False, "set_poam_remediation"),
    ActionDef("prepare_authorization_delta", "Prepare authorization delta",
              "Summarize what changed in a system's authorization posture.",
              ("system",), False, False, None),
    ActionDef("summarize_regulatory_impact", "Summarize regulatory impact",
              "Draft the control/policy/system impact of a regulatory change.",
              ("regulatory_update",), False, False, None),
    ActionDef("map_vendor_gap_to_controls", "Map vendor gap to controls",
              "Map a vendor's security gaps to affected controls.",
              ("vendor",), False, True, None),
    ActionDef("generate_assessor_brief", "Generate assessor brief",
              "Produce an assessor-facing brief for a system.",
              ("system",), False, False, None),
    ActionDef("propose_control_test", "Propose a control test",
              "Propose a repeatable test definition for a control.",
              ("control", "system"), True, False, "create_control_test"),
    ActionDef("classify_evidence_strength", "Classify evidence strength",
              "Explain an evidence object's confidence and how to strengthen it.",
              ("evidence_object",), False, False, None),
    ActionDef("build_trust_package", "Build trust package",
              "Assemble a Trust Center package from approved artifacts.",
              ("system", "organization"), True, True, None,
              guardrails=("no_provenance",)),
    ActionDef("open_task_with_owner_due_date", "Open task with owner + due date",
              "Open a remediation task with a suggested owner and due date.",
              ("poam", "risk", "system", "control", "vendor"), True, False, "create_task"),
    ActionDef("summarize_package_diff", "Summarize package diff",
              "Summarize the difference between two authorization packages.",
              ("system",), False, False, None),
    ActionDef("recommend_evidence_replacement", "Recommend evidence replacement",
              "Recommend replacements for weak/stale evidence.",
              ("evidence_object", "system"), False, True, None),
    ActionDef("generate_control_owner_brief", "Generate control-owner brief",
              "Produce a brief for a control owner.",
              ("control", "system"), False, False, None),
    ActionDef("draft_policy_exception_review", "Draft policy exception review",
              "Draft a review of a policy exception.",
              ("policy",), True, False, None),
    ActionDef("draft_vendor_remediation_plan", "Draft vendor remediation plan",
              "Draft a remediation plan for a vendor's findings.",
              ("vendor",), True, False, None),
    ActionDef("draft_ai_agent_risk_review", "Draft AI agent risk review",
              "Draft a risk review for an AI agent.",
              ("ai_agent",), True, False, None),
    ActionDef("classify_evidence_unit", "Classify an evidence unit",
              "Classify a prepared evidence passage by control, artifact type, and strength.",
              ("evidence_object", "system"), False, True, None),
    ActionDef("evaluate_assessment_objective", "Evaluate an assessment objective",
              "Judge one NIST SP 800-53A assessment objective against retrieved evidence "
              "passages. Recorded, not dispatched: ccf.assessment.engine.evaluate calls the "
              "model itself and calls record_ai_run directly, so this entry describes the "
              "action for the registry -- nothing routes its execution through run_action.",
              ("assessment_objective",), False, True, None),
]

ACTIONS: dict[str, ActionDef] = {d.key: d for d in _DEFS}


def get_action(key: str) -> ActionDef | None:
    return ACTIONS.get(key)


async def seed_definitions(session: AsyncSession) -> int:
    """Upsert the registry into ``ai_action_definitions`` (idempotent)."""
    existing = {
        d.action_key
        for d in (await session.execute(select(AiActionDefinition))).scalars().all()
    }
    added = 0
    for d in _DEFS:
        if d.key in existing:
            continue
        session.add(
            AiActionDefinition(
                action_key=d.key, title=d.title, description=d.description,
                input_entity_types=list(d.input_entity_types),
                requires_approval=d.requires_approval, citation_required=d.citation_required,
                allowed_mutation=d.allowed_mutation, output_kind=d.output_kind,
            )
        )
        added += 1
    await session.flush()
    return added
