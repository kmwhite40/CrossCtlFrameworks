"""Provenance recording for pipeline AI calls.

These runs are recorded, not approval-gated: they document what a model produced
so an assessor's later acceptance can be attributed. See
src/ccf/ai_actions/provenance.py for why they do not go through run_action.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from ccf.ai_actions.provenance import PIPELINE_RUN_STATUS, CitationRef, record_ai_run
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization
from ccf.models_ai_actions import (
    AiActionCitation,
    AiActionInput,
    AiActionOutput,
    AiActionRun,
)
from ccf.models_assessment_engine import AssessmentObjectiveProposal

pytestmark = pytest.mark.usefixtures("fresh_engine")


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return int(org.id)


async def _record(org_id: int, **overrides: object) -> int:
    kwargs: dict[str, object] = {
        "action_key": "classify_evidence_unit",
        "entity_type": "prep_unit",
        "entity_id": "42",
        "organization_id": org_id,
        "provider": "openai",
        "model": "gpt-test",
        "prompt": "Classify this passage.",
        "output": {"verdict": "satisfied", "confidence": 0.8},
        "citations": [
            CitationRef(source_type="prep_unit", source_id="42", label="p. 3, Access Control")
        ],
        "actor": None,
    }
    kwargs.update(overrides)
    async with session_scope() as s:
        run = await record_ai_run(s, **kwargs)  # type: ignore[arg-type]
        assert run is not None
        await s.flush()
        return int(run.id)


async def test_records_a_run_with_model_and_provider() -> None:
    org_id = await _org("prov-basic")
    run_id = await _record(org_id)
    async with session_scope() as s:
        run = (await s.execute(select(AiActionRun).where(AiActionRun.id == run_id))).scalar_one()
        assert run.action_key == "classify_evidence_unit"
        assert run.entity_type == "prep_unit"
        assert run.entity_id == "42"
        assert run.organization_id == org_id
        assert run.provider == "openai"
        assert run.summary.get("model") == "gpt-test"


async def test_pipeline_runs_are_recorded_not_pending_review() -> None:
    """A distinct status, so an operator can tell these from approval-gated runs."""
    org_id = await _org("prov-status")
    run_id = await _record(org_id)
    async with session_scope() as s:
        run = (await s.execute(select(AiActionRun).where(AiActionRun.id == run_id))).scalar_one()
        assert run.status == PIPELINE_RUN_STATUS == "recorded"
        assert run.mutation_applied is False
        assert run.reviewer is None
        assert run.decided_at is None


async def test_input_and_output_hashes_are_recorded() -> None:
    org_id = await _org("prov-hashes")
    run_id = await _record(org_id)
    async with session_scope() as s:
        run = (await s.execute(select(AiActionRun).where(AiActionRun.id == run_id))).scalar_one()
        assert run.input_hash and len(run.input_hash) == 64
        assert run.output_hash and len(run.output_hash) == 64


async def test_the_same_prompt_and_output_hash_identically() -> None:
    org_id = await _org("prov-stable")
    first = await _record(org_id)
    second = await _record(org_id)
    async with session_scope() as s:
        runs = (
            await s.execute(
                select(AiActionRun).where(AiActionRun.id.in_([first, second]))
            )
        ).scalars().all()
    assert runs[0].input_hash == runs[1].input_hash
    assert runs[0].output_hash == runs[1].output_hash


async def test_a_different_prompt_hashes_differently() -> None:
    org_id = await _org("prov-differs")
    first = await _record(org_id)
    second = await _record(org_id, prompt="A different prompt entirely.")
    async with session_scope() as s:
        runs = {
            r.id: r
            for r in (
                await s.execute(
                    select(AiActionRun).where(AiActionRun.id.in_([first, second]))
                )
            ).scalars().all()
        }
    assert runs[first].input_hash != runs[second].input_hash


async def test_one_citation_row_per_reference_with_its_label() -> None:
    org_id = await _org("prov-citations")
    run_id = await _record(
        org_id,
        citations=[
            CitationRef(source_type="prep_unit", source_id="7", label="p. 3, Access Control"),
            CitationRef(source_type="prep_unit", source_id="9", label="p. 4, Audit"),
        ],
    )
    async with session_scope() as s:
        rows = (
            await s.execute(
                select(AiActionCitation).where(AiActionCitation.run_id == run_id)
            )
        ).scalars().all()
    assert sorted(r.source_id for r in rows) == ["7", "9"]
    assert all(r.source_type == "prep_unit" for r in rows)
    assert any("Access Control" in (r.label or "") for r in rows)


async def test_the_output_payload_is_stored() -> None:
    org_id = await _org("prov-output")
    run_id = await _record(org_id)
    async with session_scope() as s:
        out = (
            await s.execute(select(AiActionOutput).where(AiActionOutput.run_id == run_id))
        ).scalar_one()
    assert out.payload.get("verdict") == "satisfied"


async def test_the_prompt_body_is_withheld_when_ai_store_prompts_is_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """IA-10: the hash still proves what ran, without retaining the prompt text."""
    monkeypatch.setenv("CCF_AI_STORE_PROMPTS", "false")
    get_settings.cache_clear()
    try:
        org_id = await _org("prov-noprompt")
        run_id = await _record(org_id, prompt="Sensitive customer policy text.")
        async with session_scope() as s:
            inp = (
                await s.execute(select(AiActionInput).where(AiActionInput.run_id == run_id))
            ).scalar_one()
            run = (
                await s.execute(select(AiActionRun).where(AiActionRun.id == run_id))
            ).scalar_one()
        assert "Sensitive customer policy text." not in str(inp.payload)
        assert inp.hash and len(inp.hash) == 64
        assert run.input_hash == inp.hash
    finally:
        get_settings.cache_clear()


async def test_the_prompt_body_is_stored_when_ai_store_prompts_is_true(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CCF_AI_STORE_PROMPTS", "true")
    get_settings.cache_clear()
    try:
        org_id = await _org("prov-prompt")
        run_id = await _record(org_id, prompt="Classify this passage.")
        async with session_scope() as s:
            inp = (
                await s.execute(select(AiActionInput).where(AiActionInput.run_id == run_id))
            ).scalar_one()
        assert "Classify this passage." in str(inp.payload)
    finally:
        get_settings.cache_clear()


async def test_a_recording_failure_returns_none_rather_than_raising() -> None:
    """Losing an audit row must never fail the stage that produced real work."""
    async with session_scope() as s:
        run = await record_ai_run(
            s,
            action_key="classify_evidence_unit",
            entity_type="prep_unit",
            entity_id="1",
            organization_id=987654321,  # no such organization -> FK violation
            provider="openai",
            model="gpt-test",
            prompt="x",
            output={},
            citations=[],
        )
    assert run is None


async def test_the_objective_proposal_carries_an_ai_action_run_fk() -> None:
    """The column Task 3 populates must exist and be nullable."""
    column = AssessmentObjectiveProposal.__table__.c.ai_action_run_id
    assert column.nullable is True
