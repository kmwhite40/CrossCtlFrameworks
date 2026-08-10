"""Job queue — claiming, reaping, retry accounting, and worker cycles."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import delete, select

from ccf.ai import gateway
from ccf.ai.providers.base import EmbedResponse
from ccf.db import session_scope
from ccf.models import Organization
from ccf.models_prep import PrepJob, PrepRun
from ccf.prep import jobs

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(autouse=True)
async def _clean_job_queue() -> AsyncIterator[None]:
    """``prep_jobs``/``prep_runs`` are a genuinely global queue — ``claim()`` has
    no organization filter, by design, since one worker drains jobs for every
    org. The session-scoped ``clean_migrated_db`` fixture resets the schema only
    once per pytest session, not per test, so without this fixture a test that
    asserts an exact count (``claim(..., limit=5) == []``, ``select(PrepJob)
    ...scalars().one()``) sees leftover rows from earlier tests in this module
    and fails on order, not on behavior. Scoped to this module's own
    ``jobs-*``-named organizations so it never touches another test module's
    data — matching the delete-before/after pattern other prep test modules use
    for their own rows (see test_prep_pipeline_e2e.py's ``seeded_control``).
    """

    async def _wipe() -> None:
        async with session_scope() as s:
            org_ids = (
                (await s.execute(select(Organization.id).where(Organization.name.like("jobs-%"))))
                .scalars()
                .all()
            )
            if org_ids:
                # ON DELETE CASCADE on PrepJob.run_id -> PrepRun.id removes the
                # dependent jobs (and any other run-scoped rows) too.
                await s.execute(delete(PrepRun).where(PrepRun.organization_id.in_(org_ids)))

    await _wipe()
    yield
    await _wipe()


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return int(org.id)


async def test_enqueue_creates_a_run_and_a_pending_job() -> None:
    org_id = await _org("jobs-enqueue")
    async with session_scope() as s:
        job = await jobs.enqueue(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        assert job.status == "pending"
        assert job.next_stage == "parse"
        run = (await s.execute(select(PrepRun).where(PrepRun.id == job.run_id))).scalar_one()
        assert run.organization_id == org_id


async def test_claim_marks_jobs_and_records_the_worker() -> None:
    org_id = await _org("jobs-claim")
    async with session_scope() as s:
        for n in range(3):
            await jobs.enqueue(s, organization_id=org_id, source_kind="policy_version", source_id=n)
    async with session_scope() as s:
        claimed = await jobs.claim(s, worker="worker-a", limit=2)
        assert len(claimed) == 2
        assert all(j.status == "claimed" for j in claimed)
        assert all(j.claimed_by == "worker-a" for j in claimed)


async def test_a_claimed_job_is_not_claimed_twice() -> None:
    org_id = await _org("jobs-exclusive")
    async with session_scope() as s:
        await jobs.enqueue(s, organization_id=org_id, source_kind="policy_version", source_id=1)
    async with session_scope() as s:
        assert len(await jobs.claim(s, worker="worker-a", limit=5)) == 1
    async with session_scope() as s:
        assert await jobs.claim(s, worker="worker-b", limit=5) == []


async def test_reap_returns_stale_claimed_jobs_to_pending() -> None:
    """A crashed container must not strand work forever."""
    org_id = await _org("jobs-reap")
    async with session_scope() as s:
        job = await jobs.enqueue(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        job.status = "claimed"
        job.claimed_by = "dead-worker"
        job.claimed_at = datetime.now(UTC) - timedelta(hours=3)
        await s.flush()
        job_id = int(job.id)

    async with session_scope() as s:
        assert await jobs.reap_stale(s, older_than_minutes=60) == 1
        reaped = (await s.execute(select(PrepJob).where(PrepJob.id == job_id))).scalar_one()
        assert reaped.status == "pending"
        assert reaped.claimed_by is None


async def test_reap_leaves_a_freshly_claimed_job_alone() -> None:
    org_id = await _org("jobs-reap-fresh")
    async with session_scope() as s:
        job = await jobs.enqueue(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        job.status = "claimed"
        job.claimed_at = datetime.now(UTC)
        await s.flush()
    async with session_scope() as s:
        assert await jobs.reap_stale(s, older_than_minutes=60) == 0


async def test_reap_dead_letters_a_job_that_exhausted_its_retries() -> None:
    """A worker that crashes on the same job every time must not cycle forever.

    ``attempts`` is bumped at claim time (not after the stage runs) so it
    survives a worker being killed mid-stage. Once a stale job is at or past
    ``max_attempts``, reap_stale must dead-letter it (``status="failed"`` with
    ``last_error`` explaining why) instead of handing it back to ``pending`` —
    otherwise it would claim/crash/reap forever, burning a full stage's worth of
    parsing and model calls on every cycle with no operator visibility.
    """
    org_id = await _org("jobs-reap-exhausted")
    async with session_scope() as s:
        job = await jobs.enqueue(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        job.status = "claimed"
        job.claimed_by = "dead-worker"
        job.claimed_at = datetime.now(UTC) - timedelta(hours=3)
        job.attempts = 5
        await s.flush()
        job_id = int(job.id)

    async with session_scope() as s:
        assert await jobs.reap_stale(s, older_than_minutes=60, max_attempts=5) == 1
        reaped = (await s.execute(select(PrepJob).where(PrepJob.id == job_id))).scalar_one()
        assert reaped.status == "failed"
        assert reaped.claimed_by is None
        assert "exceeded max attempts" in (reaped.last_error or "")

    # A second cycle must not touch it again — it is terminal, not requeued.
    async with session_scope() as s:
        assert await jobs.reap_stale(s, older_than_minutes=60, max_attempts=5) == 0


async def test_run_once_drives_a_job_to_done(monkeypatch: pytest.MonkeyPatch) -> None:
    org_id = await _org("jobs-cycle")

    async def _embed(session: Any, org_id_: int, *, texts: list[str], **kw: Any) -> EmbedResponse:
        return EmbedResponse(vectors=[[0.01] * 1024 for _ in texts], model="m")

    monkeypatch.setattr(gateway, "embed", _embed)
    async with session_scope() as s:
        # A policy_version source that does not exist resolves to orphaned, which
        # is a terminal state — the job must still close rather than spin.
        await jobs.enqueue(s, organization_id=org_id, source_kind="policy_version", source_id=1)
    async with session_scope() as s:
        stats = await jobs.run_once(s, worker="w1", limit=5)
        assert stats["claimed"] == 1
        assert stats["finished"] == 1
    async with session_scope() as s:
        job = (await s.execute(select(PrepJob))).scalars().one()
        assert job.status == "done"


async def test_a_failing_job_records_its_error_and_increments_attempts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id = await _org("jobs-failure")

    async def _boom(session: Any, run: Any) -> Any:
        raise RuntimeError("stage exploded")

    monkeypatch.setattr(jobs.pipeline, "advance", _boom)
    async with session_scope() as s:
        await jobs.enqueue(s, organization_id=org_id, source_kind="policy_version", source_id=1)
    async with session_scope() as s:
        await jobs.run_once(s, worker="w1", limit=5)
    async with session_scope() as s:
        job = (await s.execute(select(PrepJob))).scalars().one()
        assert job.status == "failed"
        assert job.attempts == 1
        assert "stage exploded" in (job.last_error or "")


async def test_claim_is_committed_before_stage_work_begins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The claim (and its ``attempts`` bump) must be durable before any stage
    work runs — not merely flushed into ``run_once``'s own uncommitted
    transaction — otherwise a worker crash during the stage work would silently
    roll the claim back too, and reap_stale would never see the job as stale.
    """
    org_id = await _org("jobs-durable-claim")
    async with session_scope() as s:
        job = await jobs.enqueue(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        job_id = int(job.id)

    seen: dict[str, Any] = {}

    async def _check_from_another_session(session: Any, run: Any) -> Any:
        # A separate session/connection — not the one run_once is using — must
        # already see the claim, proving it doesn't depend on run_once's own
        # eventual commit.
        async with session_scope() as s2:
            row = (await s2.execute(select(PrepJob).where(PrepJob.id == job_id))).scalar_one()
            seen["status"] = row.status
            seen["attempts"] = row.attempts
        raise RuntimeError("stop before real stage work runs")

    monkeypatch.setattr(jobs.pipeline, "advance", _check_from_another_session)
    async with session_scope() as s:
        await jobs.run_once(s, worker="w1", limit=5)

    assert seen["status"] == "claimed"
    assert seen["attempts"] == 1


async def test_a_crash_mid_batch_does_not_roll_back_earlier_committed_jobs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One job's crash must not discard already-committed work from earlier jobs
    processed in the same run_once cycle — each job commits independently, so a
    worker killed on job 2 of a batch does not also undo job 1.

    Simulates a real crash — not a caught exception — with
    ``asyncio.CancelledError``, a ``BaseException`` that ``_drive_one``'s
    ``except Exception`` deliberately does not catch, so it propagates out of
    ``run_once`` uncaught the way a real process kill would.
    """
    org_id = await _org("jobs-crash-mid-batch")
    async with session_scope() as s:
        job_ok = await jobs.enqueue(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        job_crash = await jobs.enqueue(
            s, organization_id=org_id, source_kind="policy_version", source_id=2
        )
        ok_run_id, crash_run_id = int(job_ok.run_id), int(job_crash.run_id)
        ok_id, crash_id = int(job_ok.id), int(job_crash.id)

    real_advance = jobs.pipeline.advance

    async def _advance(session: Any, run: Any) -> Any:
        if int(run.id) == ok_run_id:
            return await real_advance(session, run)  # genuinely completes (orphaned)
        assert int(run.id) == crash_run_id
        raise asyncio.CancelledError("simulated worker kill")

    monkeypatch.setattr(jobs.pipeline, "advance", _advance)
    # pytest.raises must wrap the whole session_scope() block, not sit inside
    # it — session_scope's own try/except only commits on a clean `yield`
    # return. If the exception were caught *inside* the block instead, control
    # would return to session_scope normally and it would commit regardless of
    # which code is under test, defeating the crash simulation entirely.
    with pytest.raises(asyncio.CancelledError):
        async with session_scope() as s:
            await jobs.run_once(s, worker="w1", limit=5)

    async with session_scope() as s:
        ok = (await s.execute(select(PrepJob).where(PrepJob.id == ok_id))).scalar_one()
        crashed = (await s.execute(select(PrepJob).where(PrepJob.id == crash_id))).scalar_one()
    # job_ok's outcome survived the later crash — committed independently.
    assert ok.status == "done"
    # job_crash was abandoned mid-processing: still durably claimed, not rolled
    # back to pending and not silently lost.
    assert crashed.status == "claimed"


async def test_a_job_abandoned_mid_processing_stays_claimed_for_reap_to_dead_letter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: a job whose worker crashes mid-advance() stays durably
    ``claimed`` (not silently reverted to pending by a transaction rollback) so
    reap_stale's timeout branch can actually find it later — and, once it is at
    the retry cap, dead-letters it instead of handing it back for another
    doomed cycle. Without per-job commits, the claim itself would be rolled
    back by the crash and reap_stale would never see this job as stale at all.
    """
    org_id = await _org("jobs-abandoned")
    async with session_scope() as s:
        job = await jobs.enqueue(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        job_id = int(job.id)

    async def _crash(session: Any, run: Any) -> Any:
        raise asyncio.CancelledError("simulated worker kill")

    monkeypatch.setattr(jobs.pipeline, "advance", _crash)
    # See the comment in test_a_crash_mid_batch_does_not_roll_back_earlier_committed_jobs
    # — pytest.raises must wrap the whole session_scope() block.
    with pytest.raises(asyncio.CancelledError):
        async with session_scope() as s:
            await jobs.run_once(s, worker="w1", limit=5)

    async with session_scope() as s:
        row = (await s.execute(select(PrepJob).where(PrepJob.id == job_id))).scalar_one()
        assert row.status == "claimed"
        assert row.attempts == 1

    # Age it past the staleness window, at the cap: reap_stale must dead-letter
    # it rather than hand it back for yet another doomed cycle.
    async with session_scope() as s:
        row = (await s.execute(select(PrepJob).where(PrepJob.id == job_id))).scalar_one()
        row.claimed_at = datetime.now(UTC) - timedelta(hours=3)
        row.attempts = 5
        await s.flush()

    async with session_scope() as s:
        assert await jobs.reap_stale(s, older_than_minutes=60, max_attempts=5) == 1
        row = (await s.execute(select(PrepJob).where(PrepJob.id == job_id))).scalar_one()
        assert row.status == "failed"
        assert "exceeded max attempts" in (row.last_error or "")
