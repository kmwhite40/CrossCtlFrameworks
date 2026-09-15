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
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..logging import get_logger
from ..models_grc import ControlTestResourceResult, ControlTestResult
from .latest import latest_result_ids

log = get_logger(__name__)


async def prune_resource_detail(
    session: AsyncSession,
    *,
    retain_days: int | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Delete per-resource rows older than the window, honouring both exemptions.

    ``retain_days`` defaults to ``CCF_POSTURE_RESOURCE_RETENTION_DAYS``. A
    non-positive window is refused rather than obeyed: ``0`` would delete every
    non-exempt row, and that must be an explicit act rather than a
    fat-fingered flag.

    ``dry_run`` counts what would go without deleting it, so an operator can
    see the blast radius first. The count is computed by the same predicate the
    delete uses, so the two cannot disagree.
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

    # Counted with the same predicate the delete uses, so a dry run and a real
    # run can never disagree about the blast radius.
    deleted = int(
        (
            await session.execute(select(func.count()).select_from(doomed.subquery()))
        ).scalar_one()
    )
    await session.execute(
        delete(ControlTestResourceResult).where(
            ControlTestResourceResult.id.in_(doomed)
        )
    )
    await session.flush()
    log.info(
        "posture.retention.pruned",
        deleted=deleted,
        retain_days=window,
        cutoff=cutoff.isoformat(),
    )
    return {
        "deleted": deleted,
        "retain_days": window,
        "cutoff": cutoff.isoformat(),
        "dry_run": False,
    }
