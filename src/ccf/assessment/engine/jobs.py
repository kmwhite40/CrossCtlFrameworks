"""Database-backed job queue driving objective-level control evaluation.

Evaluating one control means retrieving evidence and calling a model for every
one of its objectives (:func:`service.evaluate_control_proposal`) -- too slow
for a request cycle, so it is queued and drained by a worker the same way
``ccf.prep.jobs`` queues document preparation. This module is the second
consumer of ``ccf.queue``'s shared claim/reap primitives (the first,
``PrepJob``, is what those primitives were extracted and hardened against);
see that module's docstring for the fuller crash-recovery narrative behind
``FOR UPDATE SKIP LOCKED`` claiming and the requeue/dead-letter split.

What is specific to *this* queue, not shared, is the same hard-won transaction
shape ``ccf.prep.jobs.run_once`` uses, reproduced here rather than merely
imitated because getting it wrong loses data silently, not loudly:

* :func:`claim_jobs`'s claim (and the ``attempts`` bump inside it) is
  committed immediately, *before* any evaluation begins. A job's ``attempts``
  increment sharing a transaction with the evaluation work it is about to do
  would be rolled back by the same crash that increment exists to survive --
  and the job would never spend enough time durably ``claimed`` for
  :func:`ccf.queue.reap_stale_jobs` to ever find it stale.
* Each job's outcome is committed independently, right after
  :func:`_drive_one` returns, so one job crashing partway through cannot roll
  back another job's already-finished work from earlier in the same batch.
* A job that raises is recorded ``failed`` only after ``session.rollback()``.
  ``evaluate_control_proposal`` can raise after leaving the session's
  underlying DB transaction aborted (a raw DBAPI error, not merely a Python
  exception an ORM mutation can shrug off) -- committing straight into that
  poisoned transaction raises instead of persisting, losing ``last_error``
  and the failure both.
"""

from __future__ import annotations

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ...config import get_settings
from ...logging import get_logger
from ...models_assessment_engine import AssessmentControlProposal, AssessmentJob
from ...queue import claim_jobs, reap_stale_jobs
from .service import evaluate_control_proposal, open_control_proposal

log = get_logger(__name__)

#: See ``ccf.prep.jobs``'s identically-named constant: ``last_error`` is
#: unbounded (``Text``), but a raw DBAPI error's ``str()`` can embed the
#: entire failing statement and its parameters. Capped so one poisoned job
#: can't bloat the jobs table with its own failure text.
_MAX_LAST_ERROR_CHARS = 4_000


#: Job states :func:`enqueue_control` treats as "already going to run" -- see
#: that function's docstring.
_OUTSTANDING_JOB_STATUSES = ("pending", "claimed")


async def enqueue_control(
    session: AsyncSession, *, assessment_id: int, control_identifier: str
) -> AssessmentJob:
    """Open (or reuse) a control proposal and queue its evaluation.

    Delegates the proposal's existence and org derivation entirely to
    :func:`open_control_proposal` -- idempotent on ``(assessment_id,
    control_identifier)`` -- rather than re-deriving the organization here, so
    there is exactly one place that trusts an assessment's own system for
    that, not two that could drift.

    The proposal is idempotent; a job queued to evaluate it is not -- nothing
    stopped a repeated call (three POSTs to the API's create-proposal
    endpoint for the same control, most plausibly a client retrying a slow
    request) from queuing three full evaluations of the same control, each
    spending one model call per objective, and from letting two workers claim
    two of those jobs concurrently for the one proposal, colliding on
    ``uq_objective_proposal_label`` when both try to write the same labels.
    So: if a ``pending`` or ``claimed`` job already exists for this proposal,
    that job is still going to run (or is running) and is returned instead of
    queuing a second one. A job in a terminal state (``done`` or ``failed``)
    does not count -- a caller re-enqueuing after either of those wants a
    fresh evaluation, not the stale result of the last one.
    """
    proposal = await open_control_proposal(
        session, assessment_id=assessment_id, control_identifier=control_identifier
    )
    existing = (
        await session.execute(
            select(AssessmentJob)
            .where(
                AssessmentJob.control_proposal_id == proposal.id,
                AssessmentJob.status.in_(_OUTSTANDING_JOB_STATUSES),
            )
            .order_by(AssessmentJob.id.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if existing is not None:
        log.info(
            "assessment.job_enqueue_reused",
            job_id=existing.id,
            control_proposal_id=proposal.id,
            control_identifier=proposal.control_identifier,
            status=existing.status,
        )
        return existing

    job = AssessmentJob(
        organization_id=proposal.organization_id,
        control_proposal_id=proposal.id,
        status="pending",
    )
    session.add(job)
    await session.flush()
    log.info(
        "assessment.job_enqueued",
        job_id=job.id,
        control_proposal_id=proposal.id,
        control_identifier=proposal.control_identifier,
    )
    return job


async def _drive_one(session: AsyncSession, job: AssessmentJob) -> str:
    """Evaluate one already-claimed job's control proposal.

    Does not commit -- the caller (:func:`run_once`) commits immediately after
    this returns, so this job's outcome (or the fact that it is still
    ``claimed`` if this raises) is durable before the next job in the batch
    starts. Returns ``"done"`` or ``"failed"`` for the caller's counters.
    """
    # Captured before any DB work below, for use only in the except branch:
    # once session.rollback() runs there every ORM object already in this
    # session (job included) is expired, and touching an expired attribute
    # triggers an implicit refresh that requires an async-safe context --
    # attempting it from plain attribute access raises MissingGreenlet. Plain
    # ints captured up front sidestep that entirely. See ccf.prep.jobs's
    # _drive_one for the identical reasoning.
    job_id = int(job.id)
    control_proposal_id = int(job.control_proposal_id)

    proposal = (
        await session.execute(
            select(AssessmentControlProposal).where(
                AssessmentControlProposal.id == control_proposal_id
            )
        )
    ).scalar_one_or_none()
    if proposal is None:
        job.status = "failed"
        job.last_error = f"control proposal {control_proposal_id} no longer exists"
        return "failed"

    try:
        await evaluate_control_proposal(session, proposal)
    except Exception as exc:  # a worker must survive any one job
        # See the module docstring: evaluate_control_proposal can raise after
        # leaving the session's DB transaction aborted, not just a plain
        # Python error the ORM can shrug off. Rolling back first makes the
        # transaction usable again; a direct UPDATE (rather than continuing to
        # mutate `job` as an ORM object) records the failure because
        # rollback() expires every object already in the session, so `job`'s
        # in-memory attributes can no longer be trusted to still reflect
        # anything set on it before the rollback.
        await session.rollback()
        last_error = str(exc)[:_MAX_LAST_ERROR_CHARS]
        await session.execute(
            update(AssessmentJob)
            .where(AssessmentJob.id == job_id)
            .values(status="failed", last_error=last_error)
        )
        # evaluate_control_proposal sets proposal.state = "draft" as its very
        # first act, but that assignment lives only in this now-rolled-back
        # transaction -- session.rollback() above discards it along with
        # everything else this attempt did, so without this the DB row is
        # left at whatever state it already had (most commonly still
        # "draft", indistinguishable from "queued but never started") with no
        # record of what went wrong at all. A direct UPDATE, not an ORM
        # mutation, for the same expired-object reason the job update above
        # already is -- see this function's comment on job_id/
        # control_proposal_id being captured as plain ints up front.
        await session.execute(
            update(AssessmentControlProposal)
            .where(AssessmentControlProposal.id == control_proposal_id)
            .values(state="failed", error=last_error)
        )
        log.warning(
            "assessment.job_failed",
            job_id=job_id,
            control_proposal_id=control_proposal_id,
            error=last_error,
        )
        return "failed"

    job.status = "done"
    return "done"


async def run_once(session: AsyncSession, *, worker: str, limit: int) -> dict[str, int]:
    """Claim and drive a batch of jobs, each committed independently.

    See the module docstring for why the claim is committed before any
    evaluation runs, and why each job's outcome is committed before the next
    job starts. Mirrors ``ccf.prep.jobs.run_once`` exactly -- the same
    session/connection drives every job in the batch, but not one shared
    transaction.
    """
    claimed = await claim_jobs(session, AssessmentJob, worker=worker, limit=limit)
    await session.commit()
    # Captured as plain ids, not held as ORM objects across the loop below:
    # a mid-batch DBAPI error's session.rollback() (see _drive_one's except
    # branch) expires every object already in this session -- every job
    # claimed this cycle, not just the one that failed. Re-fetching by id
    # each iteration via session.get() is what lets job 3..N still get driven
    # after job 2 explodes.
    job_ids = [int(j.id) for j in claimed]

    finished = 0
    failed = 0
    for job_id in job_ids:
        job = await session.get(AssessmentJob, job_id)
        if job is None:  # pragma: no cover - not deletable via any current API
            continue
        outcome = await _drive_one(session, job)
        await session.commit()
        if outcome == "done":
            finished += 1
        elif outcome == "failed":
            failed += 1
    return {"claimed": len(claimed), "finished": finished, "failed": failed}


async def reap(session: AsyncSession) -> dict[str, int]:
    """Requeue or dead-letter stale ``claimed`` assessment jobs.

    A thin wrapper over :func:`ccf.queue.reap_stale_jobs` bound to
    ``AssessmentJob`` and this queue's own settings -- see that function for
    the requeue/dead-letter split.
    """
    settings = get_settings()
    return await reap_stale_jobs(
        session,
        AssessmentJob,
        older_than_minutes=settings.assessment_job_stale_after_minutes,
        max_attempts=settings.assessment_job_max_attempts,
    )
