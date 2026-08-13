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
* A job that raises is now recorded ``failed`` without a full
  ``session.rollback()`` -- :func:`_drive_one` runs inside
  ``session.begin_nested()``, whose ``ROLLBACK TO SAVEPOINT`` clears the same
  DB-level aborted-transaction state a raw DBAPI error can leave behind (the
  reason a rollback of some kind is needed at all -- ``evaluate_control_proposal``
  can raise after leaving the session's underlying DB transaction aborted, not
  merely a Python exception an ORM mutation can shrug off) without undoing the
  tenant GUC :func:`run_once` sets for this job just before entering that
  savepoint (2026-08-12 worker-tenant-scoping design; see that function's
  docstring for the full reasoning, mirrored from ``ccf.prep.jobs.run_once``).
"""

from __future__ import annotations

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ...config import get_settings
from ...db import set_session_tenant
from ...logging import get_logger
from ...models import Assessment, AssessmentControlResult, System
from ...models_assessment_engine import AssessmentControlProposal, AssessmentJob
from ...queue import claim_jobs, reap_stale_jobs
from .service import evaluate_control_proposal, open_control_proposal, open_reevaluation_proposal

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


async def enqueue_reevaluation(
    session: AsyncSession, *, poam_id: int, source_ref: str, organization_id: int
) -> AssessmentJob | None:
    """Enqueue a re-evaluation of the control an assessment-sourced POA&M remediated.

    A no-op -- enqueues nothing, returns ``None`` -- for any ``source_ref``
    that does not match the ``assessment_control_result:{id}`` convention
    Task 2's bridge writes: a scan-sourced or profile-gap POA&M has no
    objective-level proposal to re-derive, and enqueueing one would run the
    engine against a control nobody assessed through it.

    ``organization_id`` is the POA&M's own organization -- resolved by the
    caller from its ``system_id``, never trusted from anywhere else -- and
    is reconciled here against the organization the named result's
    assessment actually belongs to *before* anything is written. A mismatch
    means the POA&M's source_ref, however that happened, names a finding in
    another tenant; nothing is enqueued and no proposal row is created for
    it, matching the fail-closed-before-any-write shape
    ``open_reevaluation_proposal`` itself cannot enforce on its own (it only
    ever sees the organization derived from the result, not the caller's).

    Idempotent via :func:`open_reevaluation_proposal`'s own
    ``source_poam_id`` key, plus reuse of any outstanding (``pending`` /
    ``claimed``) job already queued against that one proposal -- closing the
    same POA&M twice enqueues exactly one job.
    """
    if not source_ref.startswith("assessment_control_result:"):
        return None
    try:
        result_id = int(source_ref.split(":", 1)[1])
    except ValueError:
        return None

    result = (
        await session.execute(
            select(AssessmentControlResult).where(AssessmentControlResult.id == result_id)
        )
    ).scalar_one_or_none()
    if result is None:
        return None

    result_org_id = (
        await session.execute(
            select(System.organization_id)
            .join(Assessment, Assessment.system_id == System.id)
            .where(Assessment.id == result.assessment_id)
        )
    ).scalar_one_or_none()
    if result_org_id is None or int(result_org_id) != organization_id:
        log.warning(
            "assessment.reevaluation_org_mismatch",
            poam_id=poam_id,
            result_id=result_id,
            poam_organization_id=organization_id,
        )
        return None

    proposal = await open_reevaluation_proposal(session, result=result, source_poam_id=poam_id)

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
        return existing

    job = AssessmentJob(
        organization_id=proposal.organization_id,
        control_proposal_id=proposal.id,
        status="pending",
    )
    session.add(job)
    await session.flush()
    log.info(
        "assessment.reevaluation_job_enqueued",
        job_id=job.id,
        control_proposal_id=proposal.id,
        source_poam_id=poam_id,
    )
    return job


async def _drive_one(session: AsyncSession, job: AssessmentJob) -> str:
    """Evaluate one already-claimed job's control proposal.

    Does not commit, and does not manage the tenant GUC or catch a DB-level
    failure -- :func:`run_once` sets the tenant to this job's
    ``organization_id``, wraps this call in ``session.begin_nested()``,
    records any failure (on both the job and its proposal), commits, and
    clears the tenant, all *around* this function. See :func:`run_once`'s
    docstring, and ``ccf.prep.jobs.run_once``'s identical reasoning, for why
    the savepoint boundary sits there rather than here. Returns ``"done"``
    or ``"failed"`` for the caller's counters.
    """
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

    await evaluate_control_proposal(session, proposal)

    job.status = "done"
    return "done"


async def run_once(session: AsyncSession, *, worker: str, limit: int) -> dict[str, int]:
    """Claim and drive a batch of jobs, each committed independently and
    scoped to its own organization while it processes.

    Mirrors ``ccf.prep.jobs.run_once`` -- see that function's docstring for
    the full reasoning behind the claim/commit boundaries and, especially,
    the tenant-scoping ordering (2026-08-12 worker-tenant-scoping design):
    the tenant is set to the claimed job's own ``organization_id`` *before*
    ``session.begin_nested()`` opens, not inside it, and cleared explicitly
    after that job's outcome commits -- never left for the next job's own
    assignment to overwrite. ``claim_jobs`` itself stays unscoped (it reads
    only ``id``\\ s and writes only claim bookkeeping); processing does not,
    since :func:`evaluate_control_proposal` reads and writes across the
    RLS'd proposal/objective tables.

    Unlike the prep queue, one job's failure here writes to *two* tables --
    ``AssessmentJob`` and its ``AssessmentControlProposal`` -- both inside
    the same direct-``UPDATE`` recovery below, for the same
    expired-object/ORM-mutation-is-unsafe reason ``ccf.prep.jobs`` documents.
    """
    claimed = await claim_jobs(session, AssessmentJob, worker=worker, limit=limit)
    await session.commit()
    job_ids = [int(j.id) for j in claimed]

    finished = 0
    failed = 0
    for job_id in job_ids:
        job = await session.get(AssessmentJob, job_id)
        if job is None:  # pragma: no cover - not deletable via any current API
            continue
        control_proposal_id = int(job.control_proposal_id)
        organization_id = int(job.organization_id)
        await set_session_tenant(session, organization_id)
        try:
            async with session.begin_nested():
                outcome = await _drive_one(session, job)
        except Exception as exc:  # a worker must survive any one job
            last_error = str(exc)[:_MAX_LAST_ERROR_CHARS]
            await session.execute(
                update(AssessmentJob)
                .where(AssessmentJob.id == job_id)
                .values(status="failed", last_error=last_error)
            )
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
            outcome = "failed"
        await session.commit()
        await set_session_tenant(session, None)
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
