"""Classification stage — schema, prompt bounding, and persistence."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import select

from ccf.ai import gateway
from ccf.ai_actions.registry import get_action
from ccf.db import session_scope
from ccf.models import Organization
from ccf.models_ai_actions import AiActionCitation, AiActionRun
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

    async def _fake_structured(*args: Any, **kwargs: Any) -> gateway.StructuredResult:
        return gateway.StructuredResult(
            data={
                "control_identifiers": ["AC-2"],
                "artifact_type": "procedure",
                "evidence_strength": "moderate",
                "explanation": "Describes a recurring account review.",
                "confidence": 0.72,
            },
            model="fake-model",
            provider="fake-provider",
        )

    monkeypatch.setattr(gateway, "generate_structured_resolved", _fake_structured)

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

    async def _fake_structured(*args: Any, **kwargs: Any) -> gateway.StructuredResult:
        return gateway.StructuredResult(
            data={
                "control_identifiers": ["AC-2"], "artifact_type": "policy",
                "evidence_strength": "weak", "explanation": "x", "confidence": 0.4,
            },
            model="fake-model",
            provider="fake-provider",
        )

    monkeypatch.setattr(gateway, "generate_structured_resolved", _fake_structured)
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

    async def _boom(*args: Any, **kwargs: Any) -> gateway.StructuredResult:
        raise gateway.GatewayError("provider unavailable")

    monkeypatch.setattr(gateway, "generate_structured_resolved", _boom)
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

    async def _fail_on_second(*args: Any, **kwargs: Any) -> gateway.StructuredResult:
        nonlocal calls
        calls += 1
        if calls == 1:
            return gateway.StructuredResult(
                data={
                    "control_identifiers": ["AC-2"], "artifact_type": "policy",
                    "evidence_strength": "weak", "explanation": "x", "confidence": 0.4,
                },
                model="fake-model",
                provider="fake-provider",
            )
        raise gateway.GatewayError("provider unavailable")

    monkeypatch.setattr(gateway, "generate_structured_resolved", _fail_on_second)
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

    async def _fake_structured(*args: Any, **kwargs: Any) -> gateway.StructuredResult:
        return gateway.StructuredResult(
            data={
                "control_identifiers": ["AC-2", "AU-6"],  # AU-6 was never a candidate
                "artifact_type": "procedure",
                "evidence_strength": "moderate",
                "explanation": "x",
                "confidence": 0.6,
            },
            model="fake-model",
            provider="fake-provider",
        )

    monkeypatch.setattr(gateway, "generate_structured_resolved", _fake_structured)
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

    async def _fake_structured(*args: Any, **kwargs: Any) -> gateway.StructuredResult:
        return gateway.StructuredResult(
            data={
                "control_identifiers": ["MADE-UP-CONTROL"],
                "artifact_type": "other",
                "evidence_strength": "weak",
                "explanation": "x",
                "confidence": 0.3,
            },
            model="fake-model",
            provider="fake-provider",
        )

    monkeypatch.setattr(gateway, "generate_structured_resolved", _fake_structured)
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


async def test_classification_records_an_ai_action_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """action_key, entity ref, provider and model are recorded; the FK is set."""
    org_id = await _org("prep-classify-provenance")

    async def _fake_structured(*args: Any, **kwargs: Any) -> gateway.StructuredResult:
        return gateway.StructuredResult(
            data={
                "control_identifiers": ["AC-2"],
                "artifact_type": "procedure",
                "evidence_strength": "moderate",
                "explanation": "Describes a recurring account review.",
                "confidence": 0.72,
            },
            model="fake-model-v1",
            provider="fake-provider",
        )

    monkeypatch.setattr(gateway, "generate_structured_resolved", _fake_structured)

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
        unit = PrepUnit(run_id=run.id, organization_id=org_id, trigger_line_id=line.id,
                        source_line_ids=[line.id], content="Text.", token_count=2)
        s.add(unit)
        await s.flush()
        unit_id = unit.id

        await run_stage_classify(s, run)

        classification = (
            await s.execute(select(PrepClassification).where(PrepClassification.run_id == run.id))
        ).scalar_one()
        assert classification.ai_action_run_id is not None

        ai_run = (
            await s.execute(
                select(AiActionRun).where(AiActionRun.id == classification.ai_action_run_id)
            )
        ).scalar_one()
        assert ai_run.action_key == "classify_evidence_unit"
        assert ai_run.entity_type == "prep_unit"
        assert ai_run.entity_id == str(unit_id)
        assert ai_run.status == "recorded"
        assert ai_run.provider == "fake-provider"
        assert ai_run.summary["model"] == "fake-model-v1"


async def test_classification_records_a_citation_for_the_unit_itself(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A classification's evidence is the passage itself: record_ai_run must be
    given exactly one CitationRef pointing back at this unit, and that must
    land as a real AiActionCitation row, not just an in-memory argument."""
    org_id = await _org("prep-classify-citation")

    async def _fake_structured(*args: Any, **kwargs: Any) -> gateway.StructuredResult:
        return gateway.StructuredResult(
            data={
                "control_identifiers": ["AC-2"],
                "artifact_type": "procedure",
                "evidence_strength": "moderate",
                "explanation": "Describes a recurring account review.",
                "confidence": 0.72,
            },
            model="fake-model-v1",
            provider="fake-provider",
        )

    monkeypatch.setattr(gateway, "generate_structured_resolved", _fake_structured)

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
        unit = PrepUnit(run_id=run.id, organization_id=org_id, trigger_line_id=line.id,
                        source_line_ids=[line.id], content="Text.", token_count=2)
        s.add(unit)
        await s.flush()
        unit_id = unit.id

        await run_stage_classify(s, run)

        classification = (
            await s.execute(select(PrepClassification).where(PrepClassification.run_id == run.id))
        ).scalar_one()
        assert classification.ai_action_run_id is not None

        citations = (
            await s.execute(
                select(AiActionCitation).where(
                    AiActionCitation.run_id == classification.ai_action_run_id
                )
            )
        ).scalars().all()
        assert len(citations) == 1
        assert citations[0].source_type == "prep_unit"
        assert citations[0].source_id == str(unit_id)


async def test_a_provenance_failure_does_not_fail_the_classification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A provenance write that fails must cost that one unit its
    ai_action_run_id, not its classification, and must not touch any other
    unit's already-persisted classification from the same run.

    The failure is real, not simulated by replacing ``record_ai_run``: the
    fake gateway hands back a provider string longer than
    ``ai_action_runs.provider``'s ``VARCHAR(24)``, which the real
    ``record_ai_run``'s own INSERT hits and fails on, inside its own
    ``begin_nested()`` savepoint -- for the second unit only. That exercises
    record_ai_run's actual failure path, so a regression that swapped its
    savepoint for a bare ``session.rollback()`` -- which unwinds to the
    outermost transaction, not just this write -- would take the first unit's
    already-flushed classification down with it. This test is built to catch
    exactly that.
    """
    org_id = await _org("prep-classify-provenance-fail")

    calls = 0

    async def _fake_structured(*args: Any, **kwargs: Any) -> gateway.StructuredResult:
        nonlocal calls
        calls += 1
        data = {
            "control_identifiers": ["AC-2"],
            "artifact_type": "procedure",
            "evidence_strength": "moderate",
            "explanation": "x",
            "confidence": 0.5,
        }
        # ai_action_runs.provider is VARCHAR(24); this overflows it on
        # purpose so record_ai_run's own insert fails for the second unit.
        provider = "way-too-long-a-provider-name" if calls == 2 else "fake-provider"
        return gateway.StructuredResult(data=data, model="fake-model", provider=provider)

    monkeypatch.setattr(gateway, "generate_structured_resolved", _fake_structured)

    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        run.stage_parse = run.stage_screen = run.stage_expand = "complete"
        line1 = PrepLine(run_id=run.id, organization_id=org_id, line_number=1, content="Text 1.")
        line2 = PrepLine(run_id=run.id, organization_id=org_id, line_number=2, content="Text 2.")
        s.add_all([line1, line2])
        await s.flush()
        unit1 = PrepUnit(run_id=run.id, organization_id=org_id, trigger_line_id=line1.id,
                         source_line_ids=[line1.id], content="Text 1.", token_count=2)
        unit2 = PrepUnit(run_id=run.id, organization_id=org_id, trigger_line_id=line2.id,
                         source_line_ids=[line2.id], content="Text 2.", token_count=2)
        s.add_all([unit1, unit2])
        await s.flush()
        unit1_id, unit2_id = unit1.id, unit2.id

        count = await run_stage_classify(s, run)
        assert count == 2
        assert run.stage_classify == "complete"

    # Re-query from a fresh session: proves both classifications are actually
    # committed, not merely pending in the session that wrote them.
    async with session_scope() as s:
        rows = (
            await s.execute(
                select(PrepClassification).where(
                    PrepClassification.unit_id.in_([unit1_id, unit2_id])
                )
            )
        ).scalars().all()

    assert len(rows) == 2, "the failing unit's classification must survive too"
    run_ids = {row.ai_action_run_id for row in rows}
    assert None in run_ids, "the provenance failure must show up as a NULL FK"
    assert len(run_ids - {None}) == 1, "the other unit's provenance must still be recorded"
