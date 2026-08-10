"""Classification stage — schema, prompt bounding, and persistence."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import select

from ccf.ai import gateway
from ccf.ai_actions.registry import get_action
from ccf.db import session_scope
from ccf.models import Organization
from ccf.models_prep import PrepClassification, PrepLine, PrepScreen, PrepUnit
from ccf.prep import pipeline
from ccf.prep.classify import (
    ARTIFACT_TYPES,
    CLASSIFICATION_SCHEMA,
    build_prompt,
    run_stage_classify,
)

pytestmark = pytest.mark.usefixtures("fresh_engine")


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return int(org.id)


def test_action_is_registered_and_requires_citation() -> None:
    action = get_action("classify_evidence_unit")
    assert action is not None
    assert action.citation_required is True
    # Classification writes only to prep tables — it must never mutate an
    # authoritative record.
    assert action.allowed_mutation is None


def test_schema_constrains_artifact_type_to_the_known_vocabulary() -> None:
    enum = CLASSIFICATION_SCHEMA["properties"]["artifact_type"]["enum"]
    assert tuple(enum) == ARTIFACT_TYPES


def test_prompt_includes_the_unit_and_bounds_the_candidate_controls() -> None:
    prompt = build_prompt("Accounts are reviewed quarterly.", ["AC-2", "AC-2(1)"])
    assert "Accounts are reviewed quarterly." in prompt
    assert "AC-2(1)" in prompt


def test_prompt_states_that_the_model_does_not_decide_compliance() -> None:
    """The model classifies; application code and assessors decide."""
    prompt = build_prompt("Some evidence.", ["AC-2"])
    assert "not" in prompt.lower() and "determination" in prompt.lower()


async def test_classify_stage_persists_one_classification_per_unit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = await _org("prep-classify")

    async def _fake_structured(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "control_identifiers": ["AC-2"],
            "artifact_type": "procedure",
            "evidence_strength": "moderate",
            "explanation": "Describes a recurring account review.",
            "confidence": 0.72,
        }

    monkeypatch.setattr(gateway, "generate_structured", _fake_structured)

    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        run.stage_parse = run.stage_screen = run.stage_expand = "complete"
        line = PrepLine(run_id=run.id, organization_id=org_id, line_number=1,
                        content="Accounts are reviewed quarterly.")
        s.add(line)
        await s.flush()
        s.add(PrepScreen(line_id=line.id, run_id=run.id, organization_id=org_id,
                         relevance_score=0.5, candidate_controls=["AC-2"], above_threshold=True))
        s.add(PrepUnit(run_id=run.id, organization_id=org_id, trigger_line_id=line.id,
                       source_line_ids=[line.id], content="Accounts are reviewed quarterly.",
                       token_count=6))
        await s.flush()

        count = await run_stage_classify(s, run)
        assert count == 1
        assert run.units_classified == 1
        assert run.stage_classify == "complete"

        row = (
            await s.execute(select(PrepClassification).where(PrepClassification.run_id == run.id))
        ).scalar_one()
        assert row.control_identifiers == ["AC-2"]
        assert row.artifact_type == "procedure"
        assert row.evidence_strength == "moderate"
        assert row.model_confidence == pytest.approx(0.72)


async def test_classify_stage_is_idempotent_on_rerun(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = await _org("prep-classify-rerun")

    async def _fake_structured(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "control_identifiers": ["AC-2"], "artifact_type": "policy",
            "evidence_strength": "weak", "explanation": "x", "confidence": 0.4,
        }

    monkeypatch.setattr(gateway, "generate_structured", _fake_structured)
    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        run.stage_parse = run.stage_screen = run.stage_expand = "complete"
        line = PrepLine(run_id=run.id, organization_id=org_id, line_number=1, content="Text.")
        s.add(line)
        await s.flush()
        s.add(PrepUnit(run_id=run.id, organization_id=org_id, trigger_line_id=line.id,
                       source_line_ids=[line.id], content="Text.", token_count=2))
        await s.flush()
        await run_stage_classify(s, run)
        await run_stage_classify(s, run)
        rows = (
            await s.execute(select(PrepClassification).where(PrepClassification.run_id == run.id))
        ).scalars().all()
        assert len(rows) == 1


async def test_provider_failure_leaves_the_run_resumable_with_prior_stages_intact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = await _org("prep-classify-fail")

    async def _boom(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise gateway.GatewayError("provider unavailable")

    monkeypatch.setattr(gateway, "generate_structured", _boom)
    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        run.stage_parse = run.stage_screen = run.stage_expand = "complete"
        line = PrepLine(run_id=run.id, organization_id=org_id, line_number=1, content="Text.")
        s.add(line)
        await s.flush()
        s.add(PrepUnit(run_id=run.id, organization_id=org_id, trigger_line_id=line.id,
                       source_line_ids=[line.id], content="Text.", token_count=2))
        await s.flush()
        await run_stage_classify(s, run)

    assert run.status == "failed"
    assert run.error_stage == "classify"
    assert run.stage_parse == "complete", "a classify failure must not undo parsing"
    assert pipeline.next_stage(run) == "classify"


async def test_partial_classification_failure_leaves_no_rows_and_zeroed_counter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failure after some units succeed must not leave persisted rows that
    disagree with ``units_classified`` — the bug class that bit Task 8's parse
    stage when counters and rows fell out of sync after an outcome change."""
    org_id = await _org("prep-classify-partial-fail")

    calls = 0

    async def _fail_on_second(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return {
                "control_identifiers": ["AC-2"], "artifact_type": "policy",
                "evidence_strength": "weak", "explanation": "x", "confidence": 0.4,
            }
        raise gateway.GatewayError("provider unavailable")

    monkeypatch.setattr(gateway, "generate_structured", _fail_on_second)
    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        run.stage_parse = run.stage_screen = run.stage_expand = "complete"
        line1 = PrepLine(run_id=run.id, organization_id=org_id, line_number=1, content="Text 1.")
        line2 = PrepLine(run_id=run.id, organization_id=org_id, line_number=2, content="Text 2.")
        s.add_all([line1, line2])
        await s.flush()
        s.add_all([
            PrepUnit(run_id=run.id, organization_id=org_id, trigger_line_id=line1.id,
                     source_line_ids=[line1.id], content="Text 1.", token_count=2),
            PrepUnit(run_id=run.id, organization_id=org_id, trigger_line_id=line2.id,
                     source_line_ids=[line2.id], content="Text 2.", token_count=2),
        ])
        await s.flush()

        await run_stage_classify(s, run)

        rows = (
            await s.execute(select(PrepClassification).where(PrepClassification.run_id == run.id))
        ).scalars().all()
        assert len(rows) == 0
        assert run.units_classified == 0
        assert run.status == "failed"


async def test_model_output_outside_candidates_is_dropped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The model must never widen its own scope beyond what screening surfaced,
    even when it returns a syntactically valid identifier that just wasn't
    offered as a candidate."""
    org_id = await _org("prep-classify-scope-nonempty")

    async def _fake_structured(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "control_identifiers": ["AC-2", "AU-6"],  # AU-6 was never a candidate
            "artifact_type": "procedure",
            "evidence_strength": "moderate",
            "explanation": "x",
            "confidence": 0.6,
        }

    monkeypatch.setattr(gateway, "generate_structured", _fake_structured)
    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        run.stage_parse = run.stage_screen = run.stage_expand = "complete"
        line = PrepLine(run_id=run.id, organization_id=org_id, line_number=1, content="Text.")
        s.add(line)
        await s.flush()
        s.add(PrepScreen(line_id=line.id, run_id=run.id, organization_id=org_id,
                         relevance_score=0.5, candidate_controls=["AC-2"], above_threshold=True))
        s.add(PrepUnit(run_id=run.id, organization_id=org_id, trigger_line_id=line.id,
                       source_line_ids=[line.id], content="Text.", token_count=2))
        await s.flush()

        await run_stage_classify(s, run)

        row = (
            await s.execute(select(PrepClassification).where(PrepClassification.run_id == run.id))
        ).scalar_one()
        assert row.control_identifiers == ["AC-2"]


async def test_model_output_with_no_surfaced_candidates_is_dropped_entirely(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An empty candidate set must not be treated as 'unbounded' — a model that
    invents a control identifier when screening surfaced none must have it
    dropped, not persisted."""
    org_id = await _org("prep-classify-scope-empty")

    async def _fake_structured(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "control_identifiers": ["MADE-UP-CONTROL"],
            "artifact_type": "other",
            "evidence_strength": "weak",
            "explanation": "x",
            "confidence": 0.3,
        }

    monkeypatch.setattr(gateway, "generate_structured", _fake_structured)
    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        run.stage_parse = run.stage_screen = run.stage_expand = "complete"
        # No PrepScreen row for this line at all, so _candidates_for returns [].
        line = PrepLine(run_id=run.id, organization_id=org_id, line_number=1, content="Text.")
        s.add(line)
        await s.flush()
        s.add(PrepUnit(run_id=run.id, organization_id=org_id, trigger_line_id=line.id,
                       source_line_ids=[line.id], content="Text.", token_count=2))
        await s.flush()

        await run_stage_classify(s, run)

        row = (
            await s.execute(select(PrepClassification).where(PrepClassification.run_id == run.id))
        ).scalar_one()
        assert row.control_identifiers == []
