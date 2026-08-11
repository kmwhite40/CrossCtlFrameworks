"""Per-objective evaluation — bounded scope, validated citations, honest gaps."""

from __future__ import annotations

from typing import Any

import pytest

from ccf.ai import gateway
from ccf.assessment.engine.evaluate import (
    EVALUATION_SCHEMA,
    build_prompt,
    evaluate_objective,
)
from ccf.assessment.engine.objectives import Objective, objective_sha256
from ccf.db import session_scope
from ccf.models import Organization
from ccf.prep import retriever
from ccf.prep.retriever import RetrievedUnit

pytestmark = pytest.mark.usefixtures("fresh_engine")


def _objective(text: str = "multifactor authentication is implemented;") -> Objective:
    return Objective(label="IA-2a", text=text, text_sha256=objective_sha256(text), sort_order=0)


def _unit(unit_id: int, content: str) -> RetrievedUnit:
    return RetrievedUnit(
        unit_id=unit_id, content=content, score=0.5, page_numbers=[3],
        section_path="Access Control", table_coordinates=None, source_kind="evidence_version",
        control_identifiers=["IA-2"], evidence_strength="strong",
        lexical_rank=1, vector_rank=1,
    )


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return int(org.id)


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

    async def _fake_structured(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "verdict": "satisfied",
            "cited_unit_ids": [7, 999],
            "gaps": [],
            "contradictions": [],
            "rationale": "Section 2 requires MFA.",
            "confidence": 0.9,
        }

    monkeypatch.setattr(retriever, "retrieve", _fake_retrieve)
    monkeypatch.setattr(gateway, "generate_structured", _fake_structured)
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

    async def _fake_structured(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {"verdict": "satisfied", "cited_unit_ids": [7], "gaps": [],
                "contradictions": [], "rationale": "ok", "confidence": 0.8}

    monkeypatch.setattr(retriever, "retrieve", _fake_retrieve)
    monkeypatch.setattr(gateway, "generate_structured", _fake_structured)
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

    async def _fake_structured(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "verdict": "satisfied",
            "cited_unit_ids": [7, "not-an-id"],
            "gaps": [],
            "contradictions": [],
            "rationale": "Section 2 requires MFA.",
            "confidence": 0.9,
        }

    monkeypatch.setattr(retriever, "retrieve", _fake_retrieve)
    monkeypatch.setattr(gateway, "generate_structured", _fake_structured)
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

    async def _fake_structured(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "verdict": "satisfied",
            "cited_unit_ids": [9, 7, 9, 7, 7],
            "gaps": [],
            "contradictions": [],
            "rationale": "ok",
            "confidence": 0.9,
        }

    monkeypatch.setattr(retriever, "retrieve", _fake_retrieve)
    monkeypatch.setattr(gateway, "generate_structured", _fake_structured)
    async with session_scope() as s:
        result = await evaluate_objective(
            s, org_id=org_id, control_identifier="IA-2",
            objective=_objective(), system_id=None,
        )
    assert result.cited_unit_ids == [9, 7]
