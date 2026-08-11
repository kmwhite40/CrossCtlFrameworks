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
operator visibility that anything is wrong. The exact wording
(:data:`DEAD_LETTER_REASON`) matches ``ccf.prep.jobs.reap_stale`` verbatim —
this extraction exists precisely so two queues never show an operator
different text for the same condition.

**``last_error`` is truncated.** Bounded so a queue that composes a longer or
dynamic reason string in the future can't bloat the row the way an
unbounded provider/DBAPI error string can (see ``ccf.prep.jobs``'s own
``_MAX_LAST_ERROR_CHARS`` for the case this guards against in practice).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, cast

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from .logging import get_logger

log = get_logger(__name__)

#: Fixed, operator-legible reason recorded on ``last_error`` when a stale job
#: is dead-lettered rather than requeued. Verbatim from ``ccf.prep.jobs``'s
#: own ``reap_stale`` -- kept identical (not merely similar) so a future
#: reader can't tell, from the message alone, which queue produced it.
DEAD_LETTER_REASON = "exceeded max attempts ({cap}) via repeated stale reclaim"

#: See the "``last_error`` is truncated" note in the module docstring.
_MAX_LAST_ERROR_CHARS = 4_000


def _truncate_last_error(text: str) -> str:
    """Cap a ``last_error`` value at :data:`_MAX_LAST_ERROR_CHARS`.

    A standalone function (rather than an inline slice at the one call site)
    so the boundary itself -- not just today's short, fixed dead-letter
    message -- is directly testable without needing a DB round trip or an
    input large enough to smuggle past column/type limits elsewhere in the
    query (e.g. ``max_attempts`` is bound into a SQL comparison against an
    ``Integer`` column, so it can't itself be used to manufacture an
    oversized string for a black-box test).
    """
    return text[:_MAX_LAST_ERROR_CHARS]


class JobLike(Protocol):
    """Structural shape a model must have to use :func:`claim_jobs` /
    :func:`reap_stale_jobs`.

    A ``Protocol`` (rather than a shared declarative mixin) is used because
    ``PrepJob`` and the coming ``AssessmentJob`` do not otherwise share a base
    class, and forcing one into existence just to satisfy this helper would
    reach further into schema than a queue-semantics extraction needs to.

    Columns are declared with their plain, unwrapped instance types (``int``,
    ``str``, ...), matching what ``some_job.status`` actually is on a real ORM
    instance -- not ``Mapped[str]``. That distinction matters here: when a
    concrete model like ``PrepJob`` is checked against this bound (e.g. at a
    call site ``claim_jobs(session, PrepJob, ...)``), mypy checks protocol
    conformance the same way it would for an ordinary instance attribute, and
    a real declarative attribute's *instance*-side type is always the
    unwrapped column type -- ``Mapped[T]`` only shows up when the attribute is
    accessed on the *class* itself, via ``Mapped``'s own overloaded
    descriptor. A Protocol typed with ``Mapped[str]`` therefore matches no
    real SQLAlchemy model at all (every candidate's instance-side ``status``
    is ``str``, never ``Mapped[str]``) -- confirmed by adding a call site
    inside ``src/`` and running ``mypy src`` against it; see the Task 7
    review fix for the exact error this produced.

    The corollary is that this Protocol, once correctly bound, can no longer
    describe the *class*-level query-building shape (``model.status`` as an
    ``InstrumentedAttribute`` usable in ``.where()``) -- mypy's descriptor
    overload resolution for ``Mapped[T]`` only fires for a concretely known
    declarative class, not for a generic Protocol-bound type parameter. Both
    functions below therefore alias ``model`` to a locally, explicitly
    ``Any``-typed name before building any SQLAlchemy expressions, and
    ``cast`` the result back to the real ``list[J]`` before returning --
    documented at each use, not left as a silent gap in the public signature.
    """

    id: int
    organization_id: int
    status: str
    attempts: int
    claimed_at: datetime | None
    claimed_by: str | None
    last_error: str | None
    created_at: datetime


async def claim_jobs[J: JobLike](
    session: AsyncSession, model: type[J], *, worker: str, limit: int
) -> list[J]:
    """Atomically claim up to ``limit`` pending rows of ``model`` for ``worker``.

    See the module docstring for why the claiming ``SELECT`` uses
    ``FOR UPDATE SKIP LOCKED``, why the follow-up ``UPDATE`` is one atomic
    statement, and why ``attempts`` is bumped inside it rather than after.
    """
    # See JobLike's docstring: `m` recovers real SQLAlchemy query-building
    # typing (InstrumentedAttribute, ColumnElement, ...) that a Protocol-bound
    # `J` cannot express for class-level access. `model`/`J` stay the real,
    # checked types at the function boundary -- only the statements below,
    # which need class-level column access, use `m`.
    m: Any = model
    candidates = (
        (
            await session.execute(
                select(m.id)
                .where(m.status == "pending")
                .order_by(m.created_at)
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
        update(m)
        .where(m.id.in_(candidates))
        .values(
            status="claimed",
            claimed_by=worker,
            claimed_at=datetime.now(UTC),
            attempts=m.attempts + 1,
        )
    )
    await session.flush()
    claimed = (await session.execute(select(m).where(m.id.in_(candidates)))).scalars().all()
    log.info("queue.jobs_claimed", worker=worker, count=len(claimed))
    return cast(list[J], list(claimed))


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
    # See claim_jobs' comment / JobLike's docstring for why `m` is `Any`.
    m: Any = model
    threshold = datetime.now(UTC) - timedelta(minutes=max(1, older_than_minutes))

    requeued = await session.execute(
        update(m)
        .where(
            m.status == "claimed",
            m.claimed_at <= threshold,
            m.attempts < max_attempts,
        )
        .values(status="pending", claimed_by=None, claimed_at=None)
    )
    reason = _truncate_last_error(DEAD_LETTER_REASON.format(cap=max_attempts))
    dead_lettered = await session.execute(
        update(m)
        .where(
            m.status == "claimed",
            m.claimed_at <= threshold,
            m.attempts >= max_attempts,
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
