"""Bound the growth of per-resource detail without losing the series.

A daily scan of 10,000 users writes 3.65M ``ControlTestResourceResult`` rows a
year, per check. Unbounded growth is not hypothetical.

The rule: **the aggregate is kept forever; the per-resource detail is
windowed.** Every ``ControlTestResult`` survives -- with ``status``,
``evaluated``, ``failing``, ``waived`` and ``expected`` -- so the time series an
authorization package draws on stays complete. It is the resource rows, which
are the volume, that age out.

Two exemptions, both load-bearing:

1. **The latest result per test is never pruned, at any age.** A check that
   last ran eighteen months ago must still be able to say *which* resources
   were failing, or pruning silently turns "3 of 47 failing" into an
   unexplainable number.
2. **A row carrying a ``waiver_id`` is never pruned.** It is the record of
   which specific resource an acceptance covered -- exactly the question a
   waiver exists to answer, so deleting it leaves an acceptance whose
   justification cannot be checked.

Pruning is **explicit**: a function and a CLI command, deliberately not wired
into the scheduler. Automatic deletion of assessment detail should be a
decision an operator makes knowingly, and shipping a timer that deletes before
anyone has seen their own volume is the wrong default.

Two more properties a destructive, deployment-wide delete needs to actually be
defensible in an authorization package:

* **Batched.** One ``DELETE`` over the whole doomed set would be a
  multi-million-row, single transaction the first time this runs against a
  real deployment -- a long lock hold, WAL bloat, and a statement timeout that
  rolls the entire thing back, leaving the operator unable to ever finish.
  Deleting in bounded batches, committing after each, keeps every batch small
  and lets a prune make forward progress even under a timeout.
* **Audited.** Every real (non-dry-run) prune writes a row to the tamper-evident
  audit chain via :func:`ccf.api.audit.record_event` -- never a hand-built
  ``AuditLog``, which would carry no ``prev_hash``/``row_hash`` and silently
  defeat that chain. A structured log line is not a persistent, queryable
  record of who deleted assessment detail, over what window, and how much.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..api.audit import record_event
from ..config import get_settings
from ..logging import get_logger
from ..models_grc import ControlTestResourceResult, ControlTestResult
from .latest import latest_result_ids

log = get_logger(__name__)

#: Rows deleted per transaction. See the module docstring: an unbatched delete
#: over the module's own stated volume (~3.65M rows/year/check) is the kind of
#: single transaction that never finishes on a real deployment.
_BATCH_SIZE = 5_000


async def prune_resource_detail(
    session: AsyncSession,
    *,
    retain_days: int | None = None,
    dry_run: bool = False,
    actor: str = "cli",
) -> dict[str, Any]:
    """Delete per-resource rows older than the window, honouring both exemptions.

    ``retain_days`` defaults to ``CCF_POSTURE_RESOURCE_RETENTION_DAYS``. A
    non-positive window is refused rather than obeyed: ``0`` would delete every
    non-exempt row, and that must be an explicit act rather than a
    fat-fingered flag.

    ``dry_run`` counts what would go, using the same predicate the delete
    applies, without deleting it -- so an operator can see the blast radius
    first.

    A real run reports the sum of each batch delete's own ``rowcount``, not a
    separate ``COUNT`` taken beforehand: under READ COMMITTED a concurrent
    write between a count and a delete can change which rows match, so only
    the delete's own rowcount can be trusted to equal what actually went.
    (A dry run has no delete to count, so it reports the predicate's count --
    the two are expected to agree only in the absence of concurrent writes
    between the two calls.)

    Deletes ``_BATCH_SIZE`` rows at a time, committing after each batch,
    rather than one all-or-nothing transaction -- see the module docstring.
    Each batch re-evaluates ``doomed`` from the current database state, so a
    row that stops being doomed between batches (its result just became
    "latest", say) is naturally left alone.

    Writes one audit record for the whole prune via
    :func:`ccf.api.audit.record_event`, carrying ``actor``, the retention
    window, the cutoff, and the total deleted -- see the module docstring.
    Never for a ``dry_run``, which deletes nothing.

    **Deployment-wide, not per tenant.** There is no ``org_id`` parameter: this
    is an operator maintenance action over every organization, and the reported
    count spans all of them. A test pins that contract, so adding a per-tenant
    prune means changing it deliberately -- a maintenance job whose scope is
    ambiguous is one that eventually deletes the wrong tenant's evidence.
    """
    window = (
        retain_days
        if retain_days is not None
        else get_settings().posture_resource_retention_days
    )
    if window <= 0:
        raise ValueError(
            f"retain_days must be positive, got {window}: "
            "a zero or negative window would delete all non-exempt detail"
        )
    cutoff = datetime.now(UTC) - timedelta(days=window)

    latest = latest_result_ids()
    protected = select(latest.c.result_id)
    # Resource rows whose parent result is older than the cutoff, excluding the
    # latest result per test and anything an acceptance covered.
    doomed = (
        select(ControlTestResourceResult.id)
        .join(
            ControlTestResult,
            ControlTestResult.id == ControlTestResourceResult.result_id,
        )
        .where(
            ControlTestResult.run_at < cutoff,
            ControlTestResourceResult.waiver_id.is_(None),
            ControlTestResult.id.not_in(protected),
        )
    )

    if dry_run:
        count = (
            await session.execute(
                select(func.count()).select_from(doomed.subquery())
            )
        ).scalar_one()
        return {
            "deleted": int(count),
            "retain_days": window,
            "cutoff": cutoff.isoformat(),
            "dry_run": True,
        }

    deleted = 0
    while True:
        batch_ids = (
            await session.execute(
                doomed.order_by(ControlTestResourceResult.id).limit(_BATCH_SIZE)
            )
        ).scalars().all()
        if not batch_ids:
            break
        result = await session.execute(
            delete(ControlTestResourceResult).where(
                ControlTestResourceResult.id.in_(batch_ids)
            )
        )
        deleted += int(getattr(result, "rowcount", 0) or 0)
        await session.commit()

    await record_event(
        session,
        # GENUINELY GLOBAL: this prune takes no org_id and deletes across every
        # organization (see the docstring above) -- the reported count spans all
        # of them. Naming any single org here would be a false statement about
        # whose evidence was pruned. NULL keeps the row visible to every tenant
        # under migration 0044's tenant_isolation policy, which is what a
        # deployment-wide deletion of their detail owes them.
        organization_id=None,
        actor=actor,
        action="delete",
        entity_type="posture_resource_detail",
        entity_id=None,
        diff={
            "retain_days": window,
            "cutoff": cutoff.isoformat(),
            "deleted": deleted,
        },
    )
    await session.commit()
    # Real deletions only: a dry run returns above, because reporting
    # deletions that did not happen would be a lie in a graph.
    from ..api.metrics import POSTURE_DETAIL_PRUNED  # noqa: PLC0415
    from .telemetry import observe  # noqa: PLC0415

    def _count_pruned() -> None:
        POSTURE_DETAIL_PRUNED.inc(deleted)

    observe("detail_pruned", _count_pruned)
    log.info(
        "posture.retention.pruned",
        deleted=deleted,
        retain_days=window,
        cutoff=cutoff.isoformat(),
        actor=actor,
    )
    return {
        "deleted": deleted,
        "retain_days": window,
        "cutoff": cutoff.isoformat(),
        "dry_run": False,
    }
