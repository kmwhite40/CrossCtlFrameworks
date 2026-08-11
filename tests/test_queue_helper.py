"""Shared job-queue helper (``ccf.queue``) — claim, reap, dead-letter.

Exercised against ``PrepJob``, an existing table, so this proves the helper is
genuinely generic (not merely copy-pasted with a rename) before a second queue
(``AssessmentJob``) is put on it. Do not add a new table for this module.
"""

from __future__ import annotations

import asyncio
import itertools
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete, select

from ccf.db import get_session_factory, session_scope, set_session_tenant
from ccf.models import Organization
from ccf.models_prep import PrepJob, PrepRun
from ccf.queue import DEAD_LETTER_REASON, claim_jobs, reap_stale_jobs

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(autouse=True)
async def _clean_job_queue() -> AsyncIterator[None]:
    """``prep_jobs`` is the same genuinely-global queue table
    ``tests/test_prep_jobs.py`` exercises, and the schema resets only once per
    pytest session (see ``clean_migrated_db`` in ``tests/conftest.py``) — not
    per test. Without this, a test here that asserts an exact claimed/reaped
    count would see leftover rows from an earlier test and fail on ordering,
    not on behavior. Scoped to this module's own ``queue-helper-*``-named
    organizations (a different prefix than ``test_prep_jobs.py``'s
    ``jobs-*``) so the two modules' cleanups never race each other's data.
    """

    async def _wipe() -> None:
        async with session_scope() as s:
            org_ids = (
                (
                    await s.execute(
                        select(Organization.id).where(Organization.name.like("queue-helper-%"))
                    )
                )
                .scalars()
                .all()
            )
            if org_ids:
                # ON DELETE CASCADE on PrepJob.run_id -> PrepRun.id removes the
                # dependent jobs too.
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


_source_id_seq = itertools.count(1)


async def _make_job(org_id: int, **overrides: object) -> int:
    """Create a ``PrepRun`` + ``PrepJob`` pair and return the job id.

    The helper under test only cares about the columns it's generic over
    (``id, organization_id, status, attempts, claimed_at, claimed_by,
    last_error, created_at``) — none of ``pipeline``/``sources`` machinery is
    needed, so this writes rows directly rather than going through
    ``ccf.prep.jobs.enqueue``. ``PrepRun.source_id`` has no FK (it's a
    polymorphic ref resolved at prepare time, not queue time), so a fresh
    fake id per call is enough to keep runs distinct.
    """
    async with session_scope() as s:
        run = PrepRun(
            organization_id=org_id,
            source_kind="policy_version",
            source_id=next(_source_id_seq),
        )
        s.add(run)
        await s.flush()
        job = PrepJob(run_id=run.id, organization_id=org_id, status="pending", next_stage="parse")
        for key, value in overrides.items():
            setattr(job, key, value)
        s.add(job)
        await s.flush()
        return int(job.id)


async def test_claim_marks_jobs_and_records_the_worker() -> None:
    org_id = await _org("queue-helper-claim")
    for _ in range(3):
        await _make_job(org_id)
    async with session_scope() as s:
        claimed = await claim_jobs(s, PrepJob, worker="worker-a", limit=2)
        assert len(claimed) == 2
        assert all(j.status == "claimed" for j in claimed)
        assert all(j.claimed_by == "worker-a" for j in claimed)
        assert all(j.claimed_at is not None for j in claimed)


async def test_a_claimed_job_is_not_claimed_twice() -> None:
    org_id = await _org("queue-helper-exclusive")
    await _make_job(org_id)
    async with session_scope() as s:
        assert len(await claim_jobs(s, PrepJob, worker="worker-a", limit=5)) == 1
    async with session_scope() as s:
        assert await claim_jobs(s, PrepJob, worker="worker-b", limit=5) == []


async def test_claim_increments_attempts_atomically() -> None:
    """``attempts`` must increment the existing count, not merely be set to 1
    -- otherwise a job reaped and reclaimed a second time would look
    indistinguishable from one claimed for the first time, and
    ``reap_stale_jobs``'s retry cap could never engage.
    """
    org_id = await _org("queue-helper-attempts")
    job_id = await _make_job(org_id, attempts=3)
    async with session_scope() as s:
        claimed = await claim_jobs(s, PrepJob, worker="worker-a", limit=5)
        assert len(claimed) == 1
        assert claimed[0].id == job_id
        assert claimed[0].attempts == 4
    async with session_scope() as s:
        row = (await s.execute(select(PrepJob).where(PrepJob.id == job_id))).scalar_one()
        assert row.attempts == 4


async def test_reap_returns_stale_claimed_jobs_to_pending() -> None:
    org_id = await _org("queue-helper-reap")
    job_id = await _make_job(
        org_id,
        status="claimed",
        claimed_by="dead-worker",
        claimed_at=datetime.now(UTC) - timedelta(hours=3),
        attempts=1,
    )
    async with session_scope() as s:
        result = await reap_stale_jobs(s, PrepJob, older_than_minutes=60, max_attempts=5)
        assert result == {"requeued": 1, "dead_lettered": 0}
        row = (await s.execute(select(PrepJob).where(PrepJob.id == job_id))).scalar_one()
        assert row.status == "pending"
        assert row.claimed_by is None
        assert row.claimed_at is None


async def test_reap_leaves_a_freshly_claimed_job_alone() -> None:
    org_id = await _org("queue-helper-reap-fresh")
    job_id = await _make_job(
        org_id, status="claimed", claimed_by="worker-a", claimed_at=datetime.now(UTC), attempts=1
    )
    async with session_scope() as s:
        result = await reap_stale_jobs(s, PrepJob, older_than_minutes=60, max_attempts=5)
        assert result == {"requeued": 0, "dead_lettered": 0}
        row = (await s.execute(select(PrepJob).where(PrepJob.id == job_id))).scalar_one()
        assert row.status == "claimed"


async def test_reap_dead_letters_at_the_attempt_cap_with_a_legible_error() -> None:
    org_id = await _org("queue-helper-dead-letter")
    job_id = await _make_job(
        org_id,
        status="claimed",
        claimed_by="dead-worker",
        claimed_at=datetime.now(UTC) - timedelta(hours=3),
        attempts=5,
    )
    async with session_scope() as s:
        result = await reap_stale_jobs(s, PrepJob, older_than_minutes=60, max_attempts=5)
        assert result == {"requeued": 0, "dead_lettered": 1}
        row = (await s.execute(select(PrepJob).where(PrepJob.id == job_id))).scalar_one()
        assert row.status == "failed"
        assert row.claimed_by is None
        assert row.last_error is not None
        assert DEAD_LETTER_REASON in row.last_error
        assert "5" in row.last_error  # the cap itself is legible, not just "failed"

    # A second cycle must not touch it again -- it is terminal, not requeued.
    async with session_scope() as s:
        result = await reap_stale_jobs(s, PrepJob, older_than_minutes=60, max_attempts=5)
        assert result == {"requeued": 0, "dead_lettered": 0}


async def test_two_concurrent_claimers_never_take_the_same_job() -> None:
    """SKIP LOCKED under real contention: two independent sessions racing over
    the same pending pool must never both claim the same row, and must never
    together leave one behind. A test that runs ``claim_jobs`` sequentially
    (fully committing the first call before starting the second) can't fail
    this way even with SKIP LOCKED deleted entirely -- by the time the second
    call's SELECT runs, the first has already flipped those rows to
    "claimed", so the ordinary ``status == "pending"`` filter alone would
    hide the overlap. Two sessions genuinely open and racing via
    ``asyncio.gather`` is what actually exercises the locking.
    """
    org_id = await _org("queue-helper-concurrent")
    pool_size = 20
    job_ids = {await _make_job(org_id) for _ in range(pool_size)}

    factory = get_session_factory()
    async with factory() as s1, factory() as s2:
        await set_session_tenant(s1, None)
        await set_session_tenant(s2, None)
        claimed1, claimed2 = await asyncio.gather(
            claim_jobs(s1, PrepJob, worker="racer-1", limit=pool_size),
            claim_jobs(s2, PrepJob, worker="racer-2", limit=pool_size),
        )
        await s1.commit()
        await s2.commit()

    ids1 = {j.id for j in claimed1}
    ids2 = {j.id for j in claimed2}

    assert ids1.isdisjoint(ids2), "the same job was claimed by both racers"
    assert ids1 | ids2 == job_ids, "every job must be claimed by exactly one racer"
    assert len(claimed1) + len(claimed2) == pool_size
