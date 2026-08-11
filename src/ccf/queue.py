"""Shared Postgres job-queue primitives: claim, reap, dead-letter.

Two queues (``ccf.prep.jobs``'s ``PrepJob`` today, an ``AssessmentJob`` queue
soon) need the *exact* same claiming and crash-recovery semantics, and those
semantics were hardened over three fix rounds and an adversarial review before
this extraction existed. Letting a second queue reimplement them "by hand"
means the two copies drift the moment one gets a fix the other doesn't — so
this module is the single place either queue's claim/reap logic lives. See
``ccf.prep.jobs`` module docstring for the fuller crash-recovery narrative;
this docstring records only the properties that must survive being made
generic.

**Exactly-once claiming.** ``SELECT ... FOR UPDATE SKIP LOCKED`` followed by an
atomic ``UPDATE`` is what makes two concurrent workers never claim the same
row: the ``SELECT`` locks its candidate rows and a second, concurrent
``SELECT ... FOR UPDATE SKIP LOCKED`` simply skips them rather than blocking or
double-selecting. A plain ``SELECT`` (no locking) or a ``SELECT`` followed by a
*separate* ``UPDATE ... WHERE id IN (...)`` reopens the race: two workers can
both select the same "pending" row before either one's ``UPDATE`` commits.

**``attempts`` incremented inside that same atomic ``UPDATE``, not afterward in
Python.** A worker can be killed between claiming and doing anything else with
the row; if the increment happened as a separate Python-side step it would be
lost on exactly the crash path the retry cap exists to catch, silently
resetting a poisoned job's attempt count every cycle.

**Requeue below the cap, dead-letter at or above it.** ``attempts < cap`` goes
back to ``pending`` for the next cycle; ``attempts >= cap`` is left
``status="failed"`` with an operator-legible ``last_error`` instead. Without
this split a job whose worker dies on it every time (OOM, a pathological
input) is reclaimed forever, burning a full cycle's work indefinitely with no
operator visibility that anything is wrong.

**``last_error`` is truncated.** Bounded so a queue that composes a longer or
dynamic reason string in the future can't bloat the row the way an
unbounded provider/DBAPI error string can (see ``ccf.prep.jobs``'s own
``_MAX_LAST_ERROR_CHARS`` for the case this guards against in practice).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Protocol

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped

from .logging import get_logger

log = get_logger(__name__)

#: Fixed, operator-legible reason recorded on ``last_error`` when a stale job
#: is dead-lettered rather than requeued. Exposed as a public constant so
#: callers/tests can assert on it without hardcoding the wording twice.
DEAD_LETTER_REASON = "exceeded max attempts via repeated stale reclaim"

#: See the "``last_error`` is truncated" note in the module docstring.
_MAX_LAST_ERROR_CHARS = 4_000


class JobLike(Protocol):
    """Structural shape a model must have to use :func:`claim_jobs` /
    :func:`reap_stale_jobs`.

    A ``Protocol`` (rather than a shared declarative mixin) is used because
    ``PrepJob`` and the coming ``AssessmentJob`` do not otherwise share a base
    class, and forcing one into existence just to satisfy this helper would
    reach further into schema than a queue-semantics extraction needs to.
    Declaring the columns as ``Mapped[...]`` (matching how the real models
    declare them) rather than as plain ``int``/``str`` is what lets mypy treat
    class-level access like ``model.status`` inside this module as a
    SQLAlchemy ``InstrumentedAttribute`` usable in ``.where()``/``.values()``,
    while instance access like ``job.status`` on a claimed row still resolves
    to the plain ``str``.
    """

    id: Mapped[int]
    organization_id: Mapped[int]
    status: Mapped[str]
    attempts: Mapped[int]
    claimed_at: Mapped[datetime | None]
    claimed_by: Mapped[str | None]
    last_error: Mapped[str | None]
    created_at: Mapped[datetime]


async def claim_jobs[J: JobLike](
    session: AsyncSession, model: type[J], *, worker: str, limit: int
) -> list[J]:
    """Atomically claim up to ``limit`` pending rows of ``model`` for ``worker``.

    See the module docstring for why the claiming ``SELECT`` uses
    ``FOR UPDATE SKIP LOCKED``, why the follow-up ``UPDATE`` is one atomic
    statement, and why ``attempts`` is bumped inside it rather than after.
    """
    candidates = (
        (
            await session.execute(
                select(model.id)
                .where(model.status == "pending")
                .order_by(model.created_at)
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
        update(model)
        .where(model.id.in_(candidates))
        .values(
            status="claimed",
            claimed_by=worker,
            claimed_at=datetime.now(UTC),
            attempts=model.attempts + 1,
        )
    )
    await session.flush()
    claimed = (
        (await session.execute(select(model).where(model.id.in_(candidates)))).scalars().all()
    )
    log.info("queue.jobs_claimed", worker=worker, count=len(claimed))
    return list(claimed)


async def reap_stale_jobs[J: JobLike](
    session: AsyncSession,
    model: type[J],
    *,
    older_than_minutes: int,
    max_attempts: int,
) -> dict[str, int]:
    """Return stale ``claimed`` rows of ``model`` to ``pending``; dead-letter
    the ones that have exhausted ``max_attempts``.

    See the module docstring for why the requeue/dead-letter split is on
    ``attempts < max_attempts`` vs ``attempts >= max_attempts``, and why
    ``last_error`` is truncated. Returns ``{"requeued": n, "dead_lettered": n}``.
    """
    threshold = datetime.now(UTC) - timedelta(minutes=max(1, older_than_minutes))

    requeued = await session.execute(
        update(model)
        .where(
            model.status == "claimed",
            model.claimed_at <= threshold,
            model.attempts < max_attempts,
        )
        .values(status="pending", claimed_by=None, claimed_at=None)
    )
    reason = f"{DEAD_LETTER_REASON} (cap={max_attempts})"[:_MAX_LAST_ERROR_CHARS]
    dead_lettered = await session.execute(
        update(model)
        .where(
            model.status == "claimed",
            model.claimed_at <= threshold,
            model.attempts >= max_attempts,
        )
        .values(
            status="failed",
            claimed_by=None,
            claimed_at=None,
            last_error=reason,
        )
    )
    requeued_count = int(getattr(requeued, "rowcount", 0) or 0)
    dead_letter_count = int(getattr(dead_lettered, "rowcount", 0) or 0)
    if requeued_count:
        log.info("queue.jobs_reaped", count=requeued_count, older_than_minutes=older_than_minutes)
    if dead_letter_count:
        log.warning(
            "queue.jobs_dead_lettered", count=dead_letter_count, max_attempts=max_attempts
        )
    return {"requeued": requeued_count, "dead_lettered": dead_letter_count}
