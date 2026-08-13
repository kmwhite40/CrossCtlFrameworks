"""Embed stage — batching, dimension validation, and model recording."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import select

from ccf.ai import gateway
from ccf.ai.providers.base import EmbedResponse
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization
from ccf.models_prep import PrepEmbedding, PrepLine, PrepUnit
from ccf.prep import pipeline
from ccf.prep.embed import run_stage_embed

pytestmark = pytest.mark.usefixtures("fresh_engine")


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return int(org.id)


async def _run_with_units(org_id: int, count: int) -> int:
    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        run.stage_parse = run.stage_screen = "complete"
        run.stage_expand = run.stage_classify = "complete"
        for n in range(count):
            line = PrepLine(run_id=run.id, organization_id=org_id, line_number=n + 1,
                            content=f"Statement {n}.")
            s.add(line)
            await s.flush()
            s.add(PrepUnit(run_id=run.id, organization_id=org_id, trigger_line_id=line.id,
                           source_line_ids=[line.id], content=f"Statement {n}.", token_count=3))
        await s.flush()
        return int(run.id)


def _fake_embed(dim: int = 1024):
    async def _embed(session: Any, org_id: int, *, texts: list[str], **kw: Any) -> EmbedResponse:
        return EmbedResponse(
            vectors=[[0.01] * dim for _ in texts],
            model="text-embedding-3-small",
            input_tokens=len(texts),
        )

    return _embed


async def test_embed_stage_writes_one_vector_per_unit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = await _org("prep-embed")
    run_id = await _run_with_units(org_id, 3)
    monkeypatch.setattr(gateway, "embed", _fake_embed())
    async with session_scope() as s:
        run = await pipeline.load_run(s, run_id)
        assert run is not None
        count = await run_stage_embed(s, run)
        assert count == 3
        assert run.units_embedded == 3
        assert run.stage_embed == "complete"
        rows = (
            await s.execute(select(PrepEmbedding).where(PrepEmbedding.run_id == run_id))
        ).scalars().all()
        assert len(rows) == 3
        assert all(r.model_name == "text-embedding-3-small" for r in rows)


async def test_dimension_mismatch_fails_the_stage_rather_than_writing_bad_vectors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = await _org("prep-embed-dim")
    run_id = await _run_with_units(org_id, 1)
    monkeypatch.setattr(gateway, "embed", _fake_embed(dim=512))
    async with session_scope() as s:
        run = await pipeline.load_run(s, run_id)
        assert run is not None
        await run_stage_embed(s, run)
        assert run.status == "failed"
        assert run.error_stage == "embed"
        assert "512" in (run.error or "")
        rows = (
            await s.execute(select(PrepEmbedding).where(PrepEmbedding.run_id == run_id))
        ).scalars().all()
        assert rows == []


async def test_embed_stage_is_idempotent_on_rerun(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = await _org("prep-embed-rerun")
    run_id = await _run_with_units(org_id, 2)
    monkeypatch.setattr(gateway, "embed", _fake_embed())
    async with session_scope() as s:
        run = await pipeline.load_run(s, run_id)
        assert run is not None
        await run_stage_embed(s, run)
        await run_stage_embed(s, run)
        rows = (
            await s.execute(select(PrepEmbedding).where(PrepEmbedding.run_id == run_id))
        ).scalars().all()
        assert len(rows) == 2


async def test_a_run_with_no_units_completes_without_calling_the_provider() -> None:
    org_id = await _org("prep-embed-empty")
    run_id = await _run_with_units(org_id, 0)
    async with session_scope() as s:
        run = await pipeline.load_run(s, run_id)
        assert run is not None
        # No monkeypatch: a provider call here would raise, proving none is made.
        assert await run_stage_embed(s, run) == 0
        assert run.stage_embed == "complete"


async def test_advance_drives_a_run_to_complete(monkeypatch: pytest.MonkeyPatch) -> None:
    """`advance()` resolves `next_stage()`, dispatches to the embed runner (the
    only stage this run has left, since `_run_with_units` pre-marks parse,
    screen, expand, and classify complete), and flips `status` to `complete`
    once it finishes. This proves stage dispatch and completion work with all
    five stages registered — it does NOT prove the four-stage handoff chain
    (that expand's units are consumable by classify, that classify's output
    shape is what embed expects, that screen's candidates reach classify
    intact), because the earlier stages never actually run here. See
    `tests/test_prep_pipeline_e2e.py::test_advance_drives_a_full_run_through_all_five_stages`
    for a run that starts every stage at `pending` and drives a real source
    document through all five.
    """
    org_id = await _org("prep-advance")
    run_id = await _run_with_units(org_id, 1)
    monkeypatch.setattr(gateway, "embed", _fake_embed())
    async with session_scope() as s:
        run = await pipeline.load_run(s, run_id)
        assert run is not None
        await pipeline.advance(s, run)
        assert run.status == "complete"
        assert pipeline.next_stage(run) is None


async def test_partial_batch_failure_leaves_zero_rows_and_zero_counter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A provider failure partway through a multi-batch run must discard the
    embeddings written by earlier, successful batches in the same attempt —
    not just the failing batch — because a half-embedded corpus ranks worse
    than an unembedded one (absence is at least detectable).

    This pins the fix for the ordering bug found in Task 12's classify stage:
    the session factory runs with autoflush=False (src/ccf/db.py:88), so a
    cleanup DELETE issued before flushing pending inserts matches nothing,
    and a trailing flush() then persists exactly the partial vectors the
    handler meant to discard.
    """
    org_id = await _org("prep-embed-partial")
    # Two units, batch size 1 (see monkeypatch below): batch 1 succeeds and is
    # `session.add()`-ed (but not flushed, since autoflush=False); batch 2 then
    # raises, so the failure handler must see and remove batch 1's pending row.
    run_id = await _run_with_units(org_id, 2)

    monkeypatch.setattr(get_settings(), "prep_worker_batch_size", 1)

    calls = 0

    async def _flaky_embed(
        session: Any, org_id: int, *, texts: list[str], **kw: Any
    ) -> EmbedResponse:
        nonlocal calls
        calls += 1
        if calls == 1:
            return EmbedResponse(
                vectors=[[0.01] * 1024 for _ in texts],
                model="text-embedding-3-small",
                input_tokens=len(texts),
            )
        raise RuntimeError("provider outage on second batch")

    monkeypatch.setattr(gateway, "embed", _flaky_embed)

    async with session_scope() as s:
        run = await pipeline.load_run(s, run_id)
        assert run is not None
        # Earlier stages' output (the two units) must survive untouched.
        units_before = (
            await s.execute(select(PrepUnit).where(PrepUnit.run_id == run_id))
        ).scalars().all()
        assert len(units_before) == 2

        count = await run_stage_embed(s, run)

        assert count == 0
        assert run.units_embedded == 0
        assert run.status == "failed"
        assert run.error_stage == "embed"

        rows = (
            await s.execute(select(PrepEmbedding).where(PrepEmbedding.run_id == run_id))
        ).scalars().all()
        assert rows == []

        units_after = (
            await s.execute(select(PrepUnit).where(PrepUnit.run_id == run_id))
        ).scalars().all()
        assert len(units_after) == 2
