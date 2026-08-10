"""Database-backed job queue for preparation runs.

Preparation is too slow for a request cycle — a large PDF is minutes of parsing
and model calls — so runs are queued and drained by a worker process. The queue
lives in Postgres rather than Redis because Concord ships as a single image
against a single database, and ``SELECT ... FOR UPDATE SKIP LOCKED`` gives
exactly-once claiming across concurrent workers without another stateful service.

Crashes are expected: a container killed mid-run leaves its job ``claimed``
forever, so :func:`reap_stale` returns anything held past a deadline to
``pending``. This is safe precisely because every stage is idempotent — the
reaped job resumes at its first incomplete stage and rewrites only that stage's
output.

**Retry cap.** A job that fails *gracefully* — :func:`pipeline.advance` raises,
or a stage runs to completion but leaves ``run.status == "failed"`` — is left
``status="failed"`` immediately and is never reclaimed again (:func:`claim`
only selects ``pending`` jobs), so those already stop after one attempt with no
cap needed.

The gap is the *crash* path: a job whose worker dies mid-stage every time (an
OOM-inducing document, a pathological input that hangs a parser) is reaped back
to ``pending`` by :func:`reap_stale`, reclaimed, crashes its next worker too,
and repeats forever — burning a full stage's worth of parsing/model calls on
every cycle with no operator visibility. ``attempts`` is incremented in
:func:`claim`, not after the stage work — but incrementing it is only durable
if it is *committed* before stage work begins. :func:`run_once` therefore
commits the claim (and its ``attempts`` bump) immediately, then commits after
each job it drives, rather than leaving the whole batch as one transaction that
a mid-batch crash would silently discard in its entirety — including the
already-finished output of jobs processed earlier in the same cycle.
:func:`reap_stale` dead-letters (leaves ``status="failed"`` with ``last_error``
explaining why, instead of requeuing) any stale job at or past
``Settings.prep_job_max_attempts``, so a poisoned job stops burning cycles and
is visible the same way any other failed job is — through ``status``,
``last_error``, and ``attempts`` on ``PrepJob``. That cap can only ever engage
because the claim durably records ``status="claimed"`` before stage work starts
— otherwise a crash would roll the job back to ``pending`` immediately, and it
would never sit ``claimed`` long enough for :func:`reap_stale`'s timeout to see
it at all.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..logging import get_logger
from ..models_prep import PrepJob
from . import pipeline

log = get_logger(__name__)

#: Terminal run states — a job on such a run is finished, not retryable.
_TERMINAL = ("complete", "unsupported", "orphaned")


async def enqueue(
    session: AsyncSession, *, organization_id: int, source_kind: str, source_id: int
) -> PrepJob:
    """Open a run and queue it for the worker."""
    run = await pipeline.create_run(
        session, organization_id=organization_id, source_kind=source_kind, source_id=source_id
    )
    job = PrepJob(
        run_id=run.id, organization_id=organization_id, status="pending", next_stage="parse"
    )
    session.add(job)
    await session.flush()
    log.info("prep.job_enqueued", job_id=job.id, run_id=run.id, source_kind=source_kind)
    return job


async def claim(session: AsyncSession, *, worker: str, limit: int) -> list[PrepJob]:
    """Atomically claim up to ``limit`` pending jobs for this worker.

    Bumps ``attempts`` here, at claim time, rather than once stage work starts —
    the session driving :func:`pipeline.advance` may never commit if the worker
    is killed mid-stage, and undercounting attempts for exactly those jobs would
    defeat the retry cap in :func:`reap_stale`.
    """
    candidates = (
        (
            await session.execute(
                select(PrepJob.id)
                .where(PrepJob.status == "pending")
                .order_by(PrepJob.created_at)
                .limit(limit)
                .with_for_update(skip_locked=True)
            )
        )
        .scalars()
        .all()
    )
    if not candidates:
        return []
    await session.execute(
        update(PrepJob)
        .where(PrepJob.id.in_(candidates))
        .values(
            status="claimed",
            claimed_by=worker,
            claimed_at=datetime.now(UTC),
            attempts=PrepJob.attempts + 1,
        )
    )
    await session.flush()
    claimed = (
        (await session.execute(select(PrepJob).where(PrepJob.id.in_(candidates)))).scalars().all()
    )
    log.info("prep.jobs_claimed", worker=worker, count=len(claimed))
    return list(claimed)


async def reap_stale(
    session: AsyncSession, *, older_than_minutes: int, max_attempts: int | None = None
) -> int:
    """Return stale ``claimed`` jobs to ``pending``; dead-letter the exhausted ones.

    A job held ``claimed`` past ``older_than_minutes`` is presumed to belong to a
    crashed worker. Below ``max_attempts`` it goes back to ``pending`` for the
    next cycle. At or above ``max_attempts`` it is instead left ``status="failed"``
    with ``last_error`` explaining why, so a poisoned job stops cycling through
    claim/crash/reap and becomes visible instead. Returns the total number of
    jobs acted on (requeued + dead-lettered).
    """
    cap = max_attempts if max_attempts is not None else get_settings().prep_job_max_attempts
    threshold = datetime.now(UTC) - timedelta(minutes=max(1, older_than_minutes))

    requeued = await session.execute(
        update(PrepJob)
        .where(
            PrepJob.status == "claimed",
            PrepJob.claimed_at <= threshold,
            PrepJob.attempts < cap,
        )
        .values(status="pending", claimed_by=None, claimed_at=None)
    )
    dead_lettered = await session.execute(
        update(PrepJob)
        .where(
            PrepJob.status == "claimed",
            PrepJob.claimed_at <= threshold,
            PrepJob.attempts >= cap,
        )
        .values(
            status="failed",
            claimed_by=None,
            claimed_at=None,
            last_error=f"exceeded max attempts ({cap}) via repeated stale reclaim",
        )
    )
    requeued_count = int(getattr(requeued, "rowcount", 0) or 0)
    dead_letter_count = int(getattr(dead_lettered, "rowcount", 0) or 0)
    if requeued_count:
        log.info("prep.jobs_reaped", count=requeued_count, older_than_minutes=older_than_minutes)
    if dead_letter_count:
        log.warning("prep.jobs_dead_lettered", count=dead_letter_count, max_attempts=cap)
    return requeued_count + dead_letter_count


async def _drive_one(session: AsyncSession, job: PrepJob) -> str:
    """Advance one already-claimed job's run and update the job to match.

    Does not commit — the caller (:func:`run_once`) commits immediately after
    this returns, so this job's outcome (or the fact that it is still
    ``claimed`` if this raises) is durable before the next job in the batch
    starts. Returns ``"done"`` or ``"failed"`` for the caller's counters; a job
    left ``pending`` for the next cycle counts as neither.
    """
    run = await pipeline.load_run(session, job.run_id)
    if run is None:
        job.status = "failed"
        job.last_error = f"run {job.run_id} no longer exists"
        return "failed"
    try:
        await pipeline.advance(session, run)
    except Exception as exc:  # a worker must survive any one job
        job.status = "failed"
        job.last_error = str(exc)
        log.warning("prep.job_failed", job_id=job.id, run_id=run.id, error=str(exc))
        return "failed"

    if run.status in _TERMINAL:
        job.status = "done"
        return "done"
    if run.status == "failed":
        job.status = "failed"
        job.last_error = run.error
        return "failed"
    # Progress made but stages remain — return it for the next cycle.
    job.status = "pending"
    job.next_stage = pipeline.next_stage(run) or "parse"
    job.claimed_by = None
    job.claimed_at = None
    return "pending"


async def run_once(session: AsyncSession, *, worker: str, limit: int) -> dict[str, int]:
    """Claim and drive a batch of jobs, each committed independently.

    Every job in the batch shares this one ``session``/connection, but not one
    transaction: the claim is committed before any stage work runs, and each
    job's outcome is committed before the next job starts. A worker killed
    partway through the batch therefore loses at most the one job it was
    mid-stage on — not the whole batch, and not the durable ``claimed`` record
    (with its ``attempts`` bump) that lets :func:`reap_stale` find that job
    again later. A single shared ``session`` — rather than a fresh one per job —
    keeps the public signature exactly as documented in the interface and
    matches how :func:`claim` and :func:`reap_stale` are already tested and
    called; durability here comes from committing this session's transaction
    boundary explicitly at each point, not from any particular Session object.
    """
    claimed = await claim(session, worker=worker, limit=limit)
    await session.commit()

    finished = 0
    failed = 0
    for job in claimed:
        outcome = await _drive_one(session, job)
        await session.commit()
        if outcome == "done":
            finished += 1
        elif outcome == "failed":
            failed += 1
    return {"claimed": len(claimed), "finished": finished, "failed": failed}
