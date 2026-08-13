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

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db import set_session_tenant
from ..logging import get_logger
from ..models_prep import PrepJob
from ..queue import claim_jobs, reap_stale_jobs
from . import pipeline
from .sources import SourceMissing, SourceOwnershipMismatch, resolve_source_organization_id

log = get_logger(__name__)

#: Terminal run states — a job on such a run is finished, not retryable.
_TERMINAL = ("complete", "unsupported", "orphaned")


async def enqueue(
    session: AsyncSession, *, organization_id: int, source_kind: str, source_id: int
) -> PrepJob:
    """Open a run and queue it for the worker.

    Refuses to enqueue when ``organization_id`` does not actually own
    ``(source_kind, source_id)`` — checked via a metadata-only lookup (no
    storage fetch) *before* any row is written. Without this, a caller could
    name a real ``source_id`` belonging to a different organization and have
    the worker (which runs unscoped, bypassing RLS) fetch and prepare that
    organization's real evidence bytes under the caller's own
    ``organization_id`` — laundering a cross-tenant read into rows the caller
    can legitimately retrieve afterward. A ``source_id`` that does not resolve
    at all is refused identically (:class:`SourceOwnershipMismatch` subclasses
    :class:`SourceMissing`), so a caller cannot use this endpoint to probe
    which ids exist for another organization.
    """
    try:
        true_org = await resolve_source_organization_id(session, source_kind, source_id)
    except SourceMissing as exc:
        # resolve_source_organization_id only ever raises the plain SourceMissing
        # (never the ownership-mismatch subclass) -- re-raise as the mismatch
        # type so every "refused" path out of this function is one exception.
        raise SourceOwnershipMismatch(str(exc)) from exc
    if true_org != organization_id:
        raise SourceOwnershipMismatch(
            f"organization {organization_id} does not own {source_kind} {source_id}"
        )
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

    Delegates to :func:`ccf.queue.claim_jobs`, the shared claiming primitive
    both job queues use, so this queue's semantics can never silently drift
    from the other's — see ``ccf.queue``'s module docstring.
    """
    return await claim_jobs(session, PrepJob, worker=worker, limit=limit)


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

    Delegates to :func:`ccf.queue.reap_stale_jobs`, the shared reap/dead-letter
    primitive both job queues use. That helper takes ``max_attempts`` as a
    required keyword and returns ``{"requeued": n, "dead_lettered": n}`` — this
    wrapper is what keeps ``prep.jobs.reap_stale``'s own public contract (an
    optional ``max_attempts`` that falls back to ``Settings.prep_job_max_attempts``,
    and a single summed ``int``) unchanged for every existing caller and test.
    """
    cap = max_attempts if max_attempts is not None else get_settings().prep_job_max_attempts
    result = await reap_stale_jobs(
        session, PrepJob, older_than_minutes=older_than_minutes, max_attempts=cap
    )
    return result["requeued"] + result["dead_lettered"]


#: ``last_error`` is unbounded (``Text``), but a raw DBAPI error's ``str()``
#: can embed the entire failing statement and its parameters -- for the
#: oversized-line failure mode this fixes (see the ``except`` branch below),
#: that literally includes the pathological line's own content, easily
#: hundreds of KB. Capped so one bad job can't bloat the jobs table with its
#: own poison input.
_MAX_LAST_ERROR_CHARS = 4_000


async def _drive_one(session: AsyncSession, job: PrepJob) -> str:
    """Advance one already-claimed job's run and update the job to match.

    Does not commit, and does not manage the tenant GUC or catch a DB-level
    failure -- :func:`run_once` sets the tenant to this job's
    ``organization_id``, wraps this call in ``session.begin_nested()``,
    records any failure, commits, and clears the tenant, all *around* this
    function. See :func:`run_once`'s docstring for why the savepoint
    boundary sits there rather than here. Returns ``"done"`` or ``"failed"``
    for the caller's counters; a job left ``pending`` for the next cycle
    counts as neither.
    """
    run = await pipeline.load_run(session, job.run_id)
    if run is None:
        job.status = "failed"
        job.last_error = f"run {job.run_id} no longer exists"
        return "failed"

    await pipeline.advance(session, run)

    # pipeline.advance() reconciles run.organization_id to the source's true
    # org before every stage (see pipeline._reconcile_organization) -- sync
    # the job row to match. Nothing reads PrepJob.organization_id for
    # authorization (claim() has no org filter, by design), but leaving it
    # stale after a reparent would mean "every prep_* row for a run shares
    # one organization" is no longer literally true of this table too.
    job.organization_id = run.organization_id

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
    """Claim and drive a batch of jobs, each committed independently and
    scoped to its own organization while it processes.

    Every job in the batch shares this one ``session``/connection, but not
    one transaction: the claim is committed before any stage work runs, and
    each job's outcome is committed before the next job starts. A worker
    killed partway through the batch therefore loses at most the one job it
    was mid-stage on — not the whole batch, and not the durable ``claimed``
    record (with its ``attempts`` bump) that lets :func:`reap_stale` find
    that job again later.

    **Tenant scoping (2026-08-12 worker-tenant-scoping design).** ``claim()``
    stays unscoped — it reads only ``id``\\ s and writes only claim
    bookkeeping, never evidence content, so a leak there discloses that some
    organization has a queued job, not its contents. Once a job is claimed,
    though, its own processing reads and writes across every one of the
    eleven RLS'd tables (``pipeline.advance`` touches passages,
    classifications, embeddings...) — exactly what migration ``0060``'s
    policy exists to contain — so the tenant GUC is set to *that job's own*
    ``organization_id`` (:func:`ccf.db.set_session_tenant`) immediately
    before :func:`_drive_one` runs, and cleared again, explicitly, right
    after that job's outcome commits. The reset never waits for the next
    job's own assignment to overwrite it: a job that fails before it manages
    to set anything must not inherit its predecessor's scope, and
    :func:`reap_stale` (called by the CLI drain loop, `cli.py`'s
    `_drain_loop`, on its own session immediately after a batch) must see a
    clean, unscoped session regardless of which organization's job ran last.

    The tenant is set *before* entering ``session.begin_nested()``, not
    inside it, matching ``governance.scheduler._run_per_tenant_cycle``'s
    exact ordering. A plain (non-``LOCAL``) ``SET ROLE``/``set_config``
    issued inside a transaction is itself undone by any rollback of that
    transaction — savepoint or full — so setting the tenant *inside* the
    savepoint would mean a failed job's ``ROLLBACK TO SAVEPOINT`` also undoes
    its own tenant scoping, right before the ``except`` branch below needs it
    to record that same job's failure. Setting it outside means the
    savepoint's rollback undoes only the failed job's own writes and clears
    any DB-level ABORTED state (see the scheduler's own docstring for the
    full trap this guards against), while leaving the tenant untouched
    underneath it.

    This is also why :func:`_drive_one` no longer catches or rolls back its
    own DB-level failures the way an earlier version did, directly, with a
    full ``session.rollback()``: that was safe before tenant scoping existed,
    because nothing else was pending in the transaction at that point, but a
    full rollback issued *after* the tenant was set for this job would undo
    that ``SET`` too, same as above. A failure now propagates out of
    ``_drive_one`` to this loop's own ``except``, which records it via a
    direct ``UPDATE`` (not an ORM mutation — ``session.rollback()``/
    ``ROLLBACK TO SAVEPOINT`` expires every ORM object already in the
    session, so ``job``'s in-memory attributes can no longer be trusted to
    still reflect anything set on it before the rollback).
    """
    claimed = await claim(session, worker=worker, limit=limit)
    await session.commit()
    job_ids = [int(j.id) for j in claimed]

    finished = 0
    failed = 0
    for job_id in job_ids:
        job = await session.get(PrepJob, job_id)
        if job is None:  # pragma: no cover - not deletable via any current API
            continue
        job_run_id = int(job.run_id)
        organization_id = int(job.organization_id)
        await set_session_tenant(session, organization_id)
        try:
            async with session.begin_nested():
                outcome = await _drive_one(session, job)
        except Exception as exc:  # a worker must survive any one job
            last_error = str(exc)[:_MAX_LAST_ERROR_CHARS]
            await session.execute(
                update(PrepJob)
                .where(PrepJob.id == job_id)
                .values(status="failed", last_error=last_error)
            )
            log.warning("prep.job_failed", job_id=job_id, run_id=job_run_id, error=last_error)
            outcome = "failed"
        await session.commit()
        await set_session_tenant(session, None)
        if outcome == "done":
            finished += 1
        elif outcome == "failed":
            failed += 1
    return {"claimed": len(claimed), "finished": finished, "failed": failed}
