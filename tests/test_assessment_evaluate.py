"""Per-objective evaluation — bounded scope, validated citations, honest gaps."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import select

from ccf.ai import gateway
from ccf.assessment.engine.evaluate import (
    EVALUATION_SCHEMA,
    build_prompt,
    evaluate_objective,
)
from ccf.assessment.engine.objectives import Objective, objective_sha256
from ccf.db import session_scope
from ccf.models import Organization
from ccf.models_ai_actions import AiActionCitation, AiActionOutput, AiActionRun
from ccf.prep import retriever
from ccf.prep.retriever import RetrievedUnit

pytestmark = pytest.mark.usefixtures("fresh_engine")


def _objective(text: str = "multifactor authentication is implemented;") -> Objective:
    return Objective(label="IA-2a", text=text, text_sha256=objective_sha256(text), sort_order=0)


def _unit(
    unit_id: int,
    content: str,
    page_numbers: list[int] | None = None,
    section_path: str | None = "Access Control",
) -> RetrievedUnit:
    return RetrievedUnit(
        unit_id=unit_id, content=content, score=0.5, page_numbers=page_numbers or [3],
        section_path=section_path, table_coordinates=None, source_kind="evidence_version",
        control_identifiers=["IA-2"], evidence_strength="strong",
        lexical_rank=1, vector_rank=1,
    )


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return int(org.id)


def _resolved(
    data: dict[str, Any],
    model: str = "fake-eval-model",
    provider: str = "fake-provider",
) -> gateway.StructuredResult:
    """Wrap a fake structured-generation payload the way the real gateway's
    generate_structured_resolved does -- see I2: evaluate_objective calls that
    function specifically (not the plain generate_structured) so it gets the
    resolved model name back, not just the data.
    """
    return gateway.StructuredResult(data=data, model=model, provider=provider)


def test_schema_constrains_the_verdict_vocabulary() -> None:
    assert EVALUATION_SCHEMA["properties"]["verdict"]["enum"] == [
        "satisfied", "not_satisfied", "not_applicable", "insufficient_evidence",
    ]


def test_prompt_contains_the_objective_and_numbered_passages() -> None:
    prompt = build_prompt("MFA is implemented;", [_unit(7, "Admins use MFA."), _unit(9, "x")])
    assert "MFA is implemented;" in prompt
    assert "[7]" in prompt and "[9]" in prompt


def test_prompt_states_the_model_is_not_deciding_the_finding() -> None:
    prompt = build_prompt("MFA is implemented;", [_unit(7, "Admins use MFA.")])
    lowered = prompt.lower()
    assert "assessor" in lowered
    assert "not" in lowered


async def test_a_citation_outside_the_retrieved_set_is_dropped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A model may not cite a passage it was never shown."""
    org_id = await _org("ae-eval-citation")

    async def _fake_retrieve(*args: Any, **kwargs: Any) -> list[RetrievedUnit]:
        return [_unit(7, "Administrators authenticate with MFA.")]

    async def _fake_structured(*args: Any, **kwargs: Any) -> gateway.StructuredResult:
        return _resolved({
            "verdict": "satisfied",
            "cited_unit_ids": [7, 999],
            "gaps": [],
            "contradictions": [],
            "rationale": "Section 2 requires MFA.",
            "confidence": 0.9,
        })

    monkeypatch.setattr(retriever, "retrieve", _fake_retrieve)
    monkeypatch.setattr(gateway, "generate_structured_resolved", _fake_structured)
    async with session_scope() as s:
        result = await evaluate_objective(
            s, org_id=org_id, control_identifier="IA-2",
            objective=_objective(), system_id=None,
        )
    assert result.cited_unit_ids == [7]
    assert result.retrieved_unit_ids == [7]


async def test_no_retrieved_evidence_yields_insufficient_without_a_model_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retrieval finding nothing is an honest answer, not an error -- and not
    worth a model call whose input would be empty."""
    org_id = await _org("ae-eval-empty")

    async def _fake_retrieve(*args: Any, **kwargs: Any) -> list[RetrievedUnit]:
        return []

    monkeypatch.setattr(retriever, "retrieve", _fake_retrieve)
    # No gateway patch: any model call would raise.
    async with session_scope() as s:
        result = await evaluate_objective(
            s, org_id=org_id, control_identifier="IA-2",
            objective=_objective(), system_id=None,
        )
    assert result.verdict == "insufficient_evidence"
    assert result.cited_unit_ids == []
    assert any("no evidence" in g.lower() for g in result.gaps)


async def test_objective_text_is_passed_to_retrieval_as_the_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The objective text is a far better query than a bare control id."""
    org_id = await _org("ae-eval-query")
    seen: dict[str, Any] = {}

    async def _fake_retrieve(session: Any, **kwargs: Any) -> list[RetrievedUnit]:
        seen.update(kwargs)
        return [_unit(7, "Admins use MFA.")]

    async def _fake_structured(*args: Any, **kwargs: Any) -> gateway.StructuredResult:
        return _resolved({"verdict": "satisfied", "cited_unit_ids": [7], "gaps": [],
                           "contradictions": [], "rationale": "ok", "confidence": 0.8})

    monkeypatch.setattr(retriever, "retrieve", _fake_retrieve)
    monkeypatch.setattr(gateway, "generate_structured_resolved", _fake_structured)
    async with session_scope() as s:
        await evaluate_objective(
            s, org_id=org_id, control_identifier="IA-2",
            objective=_objective("multifactor authentication is implemented;"),
            system_id=None,
        )
    assert seen["query_text"] == "multifactor authentication is implemented;"
    assert seen["control_identifier"] == "IA-2"


async def test_a_malformed_citation_id_is_dropped_not_raised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A citation id the model produced that isn't coercible to int should be
    dropped like any other invalid citation, not crash the evaluation."""
    org_id = await _org("ae-eval-malformed")

    async def _fake_retrieve(*args: Any, **kwargs: Any) -> list[RetrievedUnit]:
        return [_unit(7, "Administrators authenticate with MFA.")]

    async def _fake_structured(*args: Any, **kwargs: Any) -> gateway.StructuredResult:
        return _resolved({
            "verdict": "satisfied",
            "cited_unit_ids": [7, "not-an-id"],
            "gaps": [],
            "contradictions": [],
            "rationale": "Section 2 requires MFA.",
            "confidence": 0.9,
        })

    monkeypatch.setattr(retriever, "retrieve", _fake_retrieve)
    monkeypatch.setattr(gateway, "generate_structured_resolved", _fake_structured)
    async with session_scope() as s:
        result = await evaluate_objective(
            s, org_id=org_id, control_identifier="IA-2",
            objective=_objective(), system_id=None,
        )
    assert result.cited_unit_ids == [7]


async def test_duplicate_citations_collapse_to_one_in_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Citing the same passage repeatedly must not inflate the weight of
    evidence in the persisted citation list."""
    org_id = await _org("ae-eval-dupe")

    async def _fake_retrieve(*args: Any, **kwargs: Any) -> list[RetrievedUnit]:
        return [_unit(7, "x"), _unit(9, "y")]

    async def _fake_structured(*args: Any, **kwargs: Any) -> gateway.StructuredResult:
        return _resolved({
            "verdict": "satisfied",
            "cited_unit_ids": [9, 7, 9, 7, 7],
            "gaps": [],
            "contradictions": [],
            "rationale": "ok",
            "confidence": 0.9,
        })

    monkeypatch.setattr(retriever, "retrieve", _fake_retrieve)
    monkeypatch.setattr(gateway, "generate_structured_resolved", _fake_structured)
    async with session_scope() as s:
        result = await evaluate_objective(
            s, org_id=org_id, control_identifier="IA-2",
            objective=_objective(), system_id=None,
        )
    assert result.cited_unit_ids == [9, 7]


async def test_the_resolved_model_name_is_recorded_on_the_evaluation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """I2: gateway.generate_structured previously discarded the resolved model
    name, so no ObjectiveEvaluation -- and downstream, no persisted
    AssessmentObjectiveProposal -- ever carried any record of which model
    produced a verdict. evaluate_objective must call
    generate_structured_resolved and thread ``.model`` through to
    ObjectiveEvaluation.model_name.
    """
    org_id = await _org("ae-eval-model-name")

    async def _fake_retrieve(*args: Any, **kwargs: Any) -> list[RetrievedUnit]:
        return [_unit(7, "Administrators authenticate with MFA.")]

    async def _fake_structured(*args: Any, **kwargs: Any) -> gateway.StructuredResult:
        return _resolved(
            {
                "verdict": "satisfied",
                "cited_unit_ids": [7],
                "gaps": [],
                "contradictions": [],
                "rationale": "ok",
                "confidence": 0.9,
            },
            model="claude-real-model-under-test",
        )

    monkeypatch.setattr(retriever, "retrieve", _fake_retrieve)
    monkeypatch.setattr(gateway, "generate_structured_resolved", _fake_structured)
    async with session_scope() as s:
        result = await evaluate_objective(
            s, org_id=org_id, control_identifier="IA-2",
            objective=_objective(), system_id=None,
        )
    assert result.model_name == "claude-real-model-under-test"


async def test_evaluation_records_a_run_with_one_citation_per_cited_unit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two cited units -> two AiActionCitation rows, labels carrying page and section."""
    org_id = await _org("ae-eval-provenance-citations")

    async def _fake_retrieve(*args: Any, **kwargs: Any) -> list[RetrievedUnit]:
        return [
            _unit(
                7, "Admins use MFA.",
                page_numbers=[3, 4], section_path="Access Control > Account Management",
            ),
            _unit(
                9, "MFA is enforced at login.",
                page_numbers=[11], section_path="Identification and Authentication",
            ),
        ]

    async def _fake_structured(*args: Any, **kwargs: Any) -> gateway.StructuredResult:
        return _resolved(
            {
                "verdict": "satisfied",
                "cited_unit_ids": [7, 9],
                "gaps": [],
                "contradictions": [],
                "rationale": "Both passages demonstrate MFA is enforced.",
                "confidence": 0.85,
            },
            model="claude-eval-model",
            provider="anthropic",
        )

    monkeypatch.setattr(retriever, "retrieve", _fake_retrieve)
    monkeypatch.setattr(gateway, "generate_structured_resolved", _fake_structured)
    async with session_scope() as s:
        result = await evaluate_objective(
            s, org_id=org_id, control_identifier="IA-2",
            objective=_objective(), system_id=None,
        )
        assert result.ai_action_run_id is not None

        ai_run = (
            await s.execute(select(AiActionRun).where(AiActionRun.id == result.ai_action_run_id))
        ).scalar_one()
        assert ai_run.action_key == "evaluate_assessment_objective"
        assert ai_run.entity_type == "assessment_objective"
        assert ai_run.entity_id == "IA-2a"
        assert ai_run.provider == "anthropic"
        assert ai_run.summary["model"] == "claude-eval-model"

        citations = (
            await s.execute(
                select(AiActionCitation).where(AiActionCitation.run_id == result.ai_action_run_id)
            )
        ).scalars().all()

    by_source_id = {c.source_id: c for c in citations}
    assert set(by_source_id) == {"7", "9"}
    assert all(c.source_type == "prep_unit" for c in citations)
    assert by_source_id["7"].label == "p. 3, 4 — Access Control > Account Management"
    assert by_source_id["9"].label == "p. 11 — Identification and Authentication"


async def test_only_cited_units_are_recorded_as_citations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retrieved-but-uncited unit must not appear as a citation."""
    org_id = await _org("ae-eval-provenance-uncited")

    async def _fake_retrieve(*args: Any, **kwargs: Any) -> list[RetrievedUnit]:
        return [
            _unit(7, "Admins use MFA."),
            _unit(9, "Unrelated passage the model did not rely on."),
        ]

    async def _fake_structured(*args: Any, **kwargs: Any) -> gateway.StructuredResult:
        return _resolved(
            {
                "verdict": "satisfied",
                "cited_unit_ids": [7],
                "gaps": [],
                "contradictions": [],
                "rationale": "Only passage 7 demonstrates MFA.",
                "confidence": 0.8,
            },
            provider="anthropic",
        )

    monkeypatch.setattr(retriever, "retrieve", _fake_retrieve)
    monkeypatch.setattr(gateway, "generate_structured_resolved", _fake_structured)
    async with session_scope() as s:
        result = await evaluate_objective(
            s, org_id=org_id, control_identifier="IA-2",
            objective=_objective(), system_id=None,
        )
        assert result.retrieved_unit_ids == [7, 9]
        assert result.cited_unit_ids == [7]

        citations = (
            await s.execute(
                select(AiActionCitation).where(AiActionCitation.run_id == result.ai_action_run_id)
            )
        ).scalars().all()

    assert [c.source_id for c in citations] == ["7"]


async def test_no_evidence_still_records_a_run_marked_uncited(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """insufficient_evidence is a real outcome and must be auditable too."""
    org_id = await _org("ae-eval-provenance-no-evidence")

    async def _fake_retrieve(*args: Any, **kwargs: Any) -> list[RetrievedUnit]:
        return []

    monkeypatch.setattr(retriever, "retrieve", _fake_retrieve)
    # No gateway patch: a model call would raise, proving this path never calls one.
    async with session_scope() as s:
        result = await evaluate_objective(
            s, org_id=org_id, control_identifier="IA-2",
            objective=_objective(), system_id=None,
        )
        assert result.verdict == "insufficient_evidence"
        assert result.ai_action_run_id is not None

        ai_run = (
            await s.execute(select(AiActionRun).where(AiActionRun.id == result.ai_action_run_id))
        ).scalar_one()
        assert ai_run.action_key == "evaluate_assessment_objective"
        assert ai_run.entity_type == "assessment_objective"
        assert ai_run.entity_id == "IA-2a"

        citations = (
            await s.execute(
                select(AiActionCitation).where(AiActionCitation.run_id == result.ai_action_run_id)
            )
        ).scalars().all()
        output = (
            await s.execute(
                select(AiActionOutput).where(AiActionOutput.run_id == result.ai_action_run_id)
            )
        ).scalar_one()

    assert citations == []
    assert output.uncited is True
