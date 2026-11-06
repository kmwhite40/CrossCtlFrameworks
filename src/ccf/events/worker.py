"""The outbox worker: claim and merge, run under the scope's tenant, then settle.

:func:`drain_once` is one pass. It claims up to ``limit`` jobs, one per
``(consumer, scope_key)``, in a single short transaction, and commits that
before any consumer runs. Each claimed job then runs in its own session and
transaction, so one job's failure never costs another's work.

**Claim and merge** (spec 5.2). A job is eligible when it is ``pending``, its
``next_attempt_at`` has passed (the settle delay and the backoff), its consumer
is registered in this process (ruling R3: a job for a consumer registered
elsewhere, or not yet, is left untouched), and no job for the same
``(consumer, scope_key)`` is ``claimed``. Claiming one marks every other
pending job for that pair ``merged`` into it, in the same transaction: the run
reads current records after the claim commits, so it covers every change
queued before the claim. A change committed during the run leaves a new
pending job, which the running-scope exclusion holds back until the run ends.

Claim transactions are serialized by a transaction-scoped advisory lock. The
running-scope exclusion reads committed ``claimed`` rows only, so without the
lock two workers claiming at the same instant could each take a job for one
scope (two runs at once), and their merge updates could deadlock. The lock is
held for the claim and merge only, never during a run.

**Webhook jobs never merge.** Every webhook subscribed to one event shares
``(webhook, event:N)``; merging them would drop all but one delivery. They are
still held back while a delivery of the same event runs.

**Tenant** (spec 6.3, ruling R6). ``scope_org`` decides it: ``system:N`` and
``org:N`` run under the scope entity's organization, whatever the job was filed
under; a gone scope finishes ``done`` with ``{"skipped": "scope gone"}``. An
``event:N`` job runs under its own ``organization_id``, and is the only kind
that may run unscoped (an organization-less event delivered to a global
webhook). Any other scope ``scope_org`` cannot place, including a malformed
one, fails at once with no retry: retrying cannot make it resolvable, and
running it unscoped would bypass RLS.

**Outcome** (spec 5.5). Success is ``done`` with the run's dict merged into
``result``. A failure below the job's own ``max_attempts`` goes back to
``pending`` at ``now + base * 2**(attempts - 1)`` (base 90 s for webhooks, 60 s
otherwise) with a truncated ``last_error``; at the cap it stays ``failed``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import ColumnElement, exists, func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from ..db import get_session_factory, set_session_tenant
from ..logging import get_logger
from ..models import Event
from ..models_outbox import OutboxJob
from ..queue import _truncate_last_error, claim_jobs, reap_stale_jobs
from . import consumers
from .outbox import CURRENT_CONSUMER, CURRENT_DEPTH, MAX_DEPTH, WEBHOOK_CONSUMER

log = get_logger(__name__)

#: Backoff bases, seconds: attempt n waits base * 2**(n-1).
BACKOFF_SECONDS = 60
WEBHOOK_BACKOFF_SECONDS = 90

_CLAIM_LOCK = "SELECT pg_advisory_xact_lock(hashtext('ccf.outbox.claim'))"

_OUTCOMES = ("done", "merged", "retried", "failed", "skipped")


def _eligible(now: datetime) -> ColumnElement[bool]:
    running = aliased(OutboxJob)
    return (
        (OutboxJob.next_attempt_at <= now)
        & OutboxJob.consumer.in_(list(consumers.REGISTRY))
        & ~exists().where(
            running.consumer == OutboxJob.consumer,
            running.scope_key == OutboxJob.scope_key,
            running.status == "claimed",
        )
    )


async def _claim(*, worker: str, limit: int, now: datetime) -> tuple[list[int], int]:
    """Claim up to ``limit`` jobs, one per scope, merging each scope's other
    pending jobs into it. One transaction, committed before anything runs."""
    claimed: list[int] = []
    merged = 0
    async with get_session_factory()() as session:
        await set_session_tenant(session, None)
        await session.execute(text(_CLAIM_LOCK))
        for _ in range(max(0, limit)):
            # One at a time: the exclusion then sees this transaction's own
            # claim, so a batch never takes two jobs of one scope.
            jobs = await claim_jobs(
                session,
                OutboxJob,
                worker=worker,
                limit=1,
                eligible=_eligible(now),
                order_by=OutboxJob.next_attempt_at,
            )
            if not jobs:
                break
            job = jobs[0]
            claimed.append(job.id)
            if job.consumer == WEBHOOK_CONSUMER:
                continue
            res = await session.execute(
                update(OutboxJob)
                .where(
                    OutboxJob.consumer == job.consumer,
                    OutboxJob.scope_key == job.scope_key,
                    OutboxJob.status == "pending",
                    OutboxJob.id != job.id,
                )
                .values(status="merged", merged_into=job.id, finished_at=func.now())
            )
            n = int(getattr(res, "rowcount", 0) or 0)
            if n:
                await session.execute(
                    update(OutboxJob).where(OutboxJob.id == job.id).values(absorbed=n)
                )
                merged += n
        await session.commit()
    return claimed, merged


def _depth(payload: Any) -> int:
    """The chain depth a run gets: its trigger event's ``_depth`` plus one.

    ``_depth`` is trusted only as an int in ``1..MAX_DEPTH``; anything else
    (absent on a request-path event, or a caller-supplied value of the wrong
    type or range) counts as 0. ``emit`` does not strip ``_depth`` from a
    request's payload, so a caller can still pass one, but a forged value can
    only shorten a chain (an event at ``MAX_DEPTH`` queues nothing), never
    lengthen it.
    """
    raw = payload.get("_depth") if isinstance(payload, dict) else None
    trusted = raw if type(raw) is int and 1 <= raw <= MAX_DEPTH else 0
    return trusted + 1


def _backoff(consumer: str, attempts: int) -> timedelta:
    base = WEBHOOK_BACKOFF_SECONDS if consumer == WEBHOOK_CONSUMER else BACKOFF_SECONDS
    return timedelta(seconds=base * 2 ** max(0, attempts - 1))


async def _settle(
    session: AsyncSession,
    job_id: int,
    *,
    consumer: str,
    attempts: int,
    max_attempts: int,
    now: datetime | None,
    error: BaseException | str | None = None,
    result: dict[str, Any] | None = None,
    retry: bool = True,
) -> str:
    """Write a claimed job's outcome (unscoped, by primary key) and name it."""
    await set_session_tenant(session, None)
    values: dict[str, Any] = {"claimed_by": None, "claimed_at": None}
    if error is None:
        outcome = "done"
        values.update(status="done", finished_at=func.now())
        if result is not None:
            values["result"] = result
    else:
        msg = error if isinstance(error, str) else f"{type(error).__name__}: {error}"
        values["last_error"] = _truncate_last_error(msg)
        if retry and attempts < max_attempts:
            outcome = "retried"
            # Backoff counts from the failure, not the drain's start: with a
            # batch of slow runs, a start-based time is already past by the
            # time a late job fails, and its first backoff collapses to zero.
            base = now if now is not None else datetime.now(UTC)
            values.update(status="pending", next_attempt_at=base + _backoff(consumer, attempts))
        else:
            outcome = "failed"
            values.update(status="failed", finished_at=func.now())
    await session.execute(update(OutboxJob).where(OutboxJob.id == job_id).values(**values))
    await session.commit()
    return outcome


async def _run_one(job_id: int, now: datetime | None) -> str:
    async with get_session_factory()() as session:
        await set_session_tenant(session, None)
        job = await session.get(OutboxJob, job_id)
        if job is None:  # pragma: no cover - deleted between claim and run
            return "skipped"
        name, key = job.consumer, job.scope_key
        settle: dict[str, Any] = {
            "consumer": name,
            "attempts": job.attempts,
            "max_attempts": job.max_attempts,
            "now": now,
        }
        prior = dict(job.result or {})
        consumer = consumers.REGISTRY.get(name)
        if consumer is None:  # claimed only when registered; unregistered since
            return await _settle(session, job_id, error=f"no consumer registered: {name}", **settle)

        org: int | str | None
        try:
            org = await consumers.scope_org(session, key)
        except ValueError:
            org = None
        if org == "gone":
            await _settle(session, job_id, result={**prior, "skipped": "scope gone"}, **settle)
            return "skipped"
        if org is None:
            if not key.startswith("event:"):
                return await _settle(
                    session, job_id, error=f"unresolvable scope: {key}", retry=False, **settle
                )
            org = job.organization_id  # None only for a platform-only delivery
        tenant = org if isinstance(org, int) else None

        payload = (
            await session.execute(select(Event.payload).where(Event.id == job.trigger_event_id))
        ).scalar()

        # The tenant is set before the savepoint: a rollback of the savepoint
        # must not also undo it (see ccf.prep.jobs.run_once).
        await set_session_tenant(session, tenant)
        c_tok = CURRENT_CONSUMER.set(name)
        d_tok = CURRENT_DEPTH.set(_depth(payload))
        failure: Exception | None = None
        out: Any = None
        try:
            async with session.begin_nested():
                out = await consumer.run(session, key, job)
        except Exception as e:
            failure = e
        finally:
            CURRENT_DEPTH.reset(d_tok)
            CURRENT_CONSUMER.reset(c_tok)

        if failure is not None:
            log.warning(
                "event_worker.job_failed",
                job_id=job_id,
                consumer=name,
                attempts=settle["attempts"],
                error=f"{type(failure).__name__}: {str(failure)[:200]}",
            )
            return await _settle(session, job_id, error=failure, **settle)
        merged = {**prior, **(out if isinstance(out, dict) else {})}
        return await _settle(session, job_id, result=merged, **settle)


async def _record_crash(job_id: int, now: datetime | None, error: BaseException) -> str:
    """A failure outside ``run`` (e.g. its commit) still costs only an attempt."""
    async with get_session_factory()() as session:
        await set_session_tenant(session, None)
        job = await session.get(OutboxJob, job_id)
        if job is None:  # pragma: no cover
            return "skipped"
        return await _settle(
            session,
            job_id,
            consumer=job.consumer,
            attempts=job.attempts,
            max_attempts=job.max_attempts,
            now=now,
            error=error,
        )


async def drain_once(
    *, worker: str, limit: int = 10, now: datetime | None = None
) -> dict[str, int]:
    """Claim, merge and run one batch. Returns counts per outcome.

    ``merged`` counts jobs absorbed by this pass's claims; ``skipped`` counts
    jobs whose scope is gone. ``now`` is the clock eligibility and backoff are
    measured against (tests pass a later one instead of sleeping). Without it,
    eligibility uses the drain's start and each backoff counts from the moment
    its job failed.
    """
    counts = dict.fromkeys(_OUTCOMES, 0)
    claimed, counts["merged"] = await _claim(
        worker=worker, limit=limit, now=now or datetime.now(UTC)
    )
    for job_id in claimed:
        try:
            outcome = await _run_one(job_id, now)
        except Exception as e:
            log.warning("event_worker.job_crashed", job_id=job_id, error=type(e).__name__)
            outcome = await _record_crash(job_id, now, e)
        counts[outcome] += 1
    return counts


async def reap(*, older_than: timedelta = timedelta(minutes=15)) -> int:
    """Requeue jobs a dead worker left ``claimed``; dead-letter those at their cap.

    The cap is per row (webhooks 8, derived views 5), so the shared reaper runs
    once per cap present among the stale rows. Returns requeued + dead-lettered.
    """
    minutes = max(1, int(older_than.total_seconds() // 60))
    total = 0
    async with get_session_factory()() as session:
        await set_session_tenant(session, None)
        caps = (
            (
                await session.execute(
                    select(OutboxJob.max_attempts).where(OutboxJob.status == "claimed").distinct()
                )
            )
            .scalars()
            .all()
        )
        for cap in caps:
            r = await reap_stale_jobs(
                session,
                OutboxJob,
                older_than_minutes=minutes,
                max_attempts=cap,
                eligible=OutboxJob.max_attempts == cap,
            )
            total += r["requeued"] + r["dead_lettered"]
        await session.commit()
    return total
