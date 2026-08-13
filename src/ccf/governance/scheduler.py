"""In-app automation scheduler.

When ``CCF_SCHEDULER_ENABLED`` is set, a background asyncio loop runs the
continuous jobs on a cadence — catalog drift poll, ConMon scan, alert digest,
and connector collection — so the platform operates as a live program without an
external cron. One cycle is also exposed via ``ccf scheduler --once`` / the API.

Two kinds of job live in one cycle, and they are scoped differently (IA-06):

* GLOBAL — the catalog-currency poll (:mod:`ccf.etl.sources`) and the
  cross-module alert digest (:mod:`ccf.governance.digest`) read/write
  platform-wide records (``CatalogSource``, ATO/POA&M/policy/vendor rollups)
  that are not owned by any one organization. These run once per cycle with
  the session's RLS tenant unscoped (bypass), same as CLI/ETL.
* PER-TENANT — connector collection, the ConMon scan, and connector-backed
  control-test auto-runs all read/write an organization's own rows
  (``CaptureSnapshot``, ``MonitoringRun``, ``ControlTestResult``, tasks,
  notifications, POA&Ms). These run once per organization inside
  :func:`_run_per_tenant_cycle`, each iteration clamped to that org via
  :func:`ccf.db.set_session_tenant` — RLS then backstops the ``org_id``
  filters the called functions already apply, so a bug in the app-layer
  scoping still can't leak org A's job into org B's rows.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db import get_engine, session_scope, set_session_tenant
from ..etl.sources import poll as poll_sources
from ..logging import get_logger
from ..models import Organization
from . import collection, conmon, control_tests, digest

log = get_logger(__name__)

# Postgres advisory-lock key so only ONE replica runs a cycle at a time
# (multi-replica leader election without external coordination). Arbitrary constant.
_SCHEDULER_LOCK_KEY = 809_057_120

_task: asyncio.Task[None] | None = None


async def _active_org_ids(session: AsyncSession) -> list[int]:
    """Every non-deleted organization — the per-tenant loop's fan-out set.

    Run while the session's RLS tenant is unscoped (bypass), so this always
    sees every organization regardless of which org last held the tenant GUC.
    """
    stmt = select(Organization.id).where(Organization.deleted_at.is_(None))
    return sorted((await session.execute(stmt)).scalars().all())


async def _run_per_tenant_cycle(
    session: AsyncSession, org_ids: list[int], *, today: date
) -> dict[str, Any]:
    """Run collection + ConMon + control-test auto-run for every organization.

    Each organization's slice runs under its own ``set_session_tenant`` and
    each step is wrapped in its own SAVEPOINT (``session.begin_nested()``).
    On a DB-level failure the whole *shared* Postgres transaction goes
    ABORTED — a bare ``try/except`` around the step's own call would swallow
    the Python exception but leave that abort in place, so the very next
    statement on this session (even a later org's ``set_session_tenant``)
    would itself raise and blow up the entire cycle. The savepoint contains
    the abort to just that one step: on exception, ``begin_nested()`` issues
    ``ROLLBACK TO SAVEPOINT``, which undoes that step's writes *and* clears
    the abort, leaving the session fully usable for the next step/org.
    """
    collection_results: list[dict[str, Any]] = []
    conmon_results: list[dict[str, Any]] = []
    control_test_results: list[dict[str, Any]] = []
    for org_id in org_ids:
        await set_session_tenant(session, org_id)
        try:
            async with session.begin_nested():
                collection_results.append(await collection.collect_for_org(session, org_id))
        except Exception as e:
            log.warning(
                "scheduler.per_tenant_step_failed",
                org_id=org_id,
                step="collection",
                error=str(e)[:200],
            )
        try:
            async with session.begin_nested():
                result = await conmon.scan(session, today=today, org_id=org_id)
                conmon_results.append({"organization_id": org_id, **result})
        except Exception as e:
            log.warning(
                "scheduler.per_tenant_step_failed",
                org_id=org_id,
                step="conmon",
                error=str(e)[:200],
            )
        try:
            async with session.begin_nested():
                result = await control_tests.run_due(session, today=today, org_id=org_id)
                control_test_results.append({"organization_id": org_id, **result})
        except Exception as e:
            log.warning(
                "scheduler.per_tenant_step_failed",
                org_id=org_id,
                step="control_tests",
                error=str(e)[:200],
            )
    # Back to bypass before any global step (or the advisory unlock) runs.
    # Suppressed: a prior step's failure must not prevent the tenant clamp
    # from being reset — mirrors the advisory-unlock suppress in run_cycle.
    with contextlib.suppress(Exception):
        await set_session_tenant(session, None)
    return {
        "collection": {
            "organizations_processed": [r["organization_id"] for r in collection_results],
            "connectors_run": [
                f"{r['organization_id']}:{k}"
                for r in collection_results
                for k in r["connectors_run"]
            ],
            "captured": sum(r["captured"] for r in collection_results),
            "drift": sum(r["drift"] for r in collection_results),
        },
        "conmon": conmon_results,
        "control_tests": control_test_results,
    }


async def run_cycle() -> dict[str, Any]:
    """Run one full automation cycle. Returns per-job results."""
    today = datetime.now(UTC).date()
    out: dict[str, Any] = {}
    is_pg = get_engine().dialect.name == "postgresql"
    async with session_scope() as session:
        # Multi-replica safety: only the instance that wins the advisory lock runs
        # the cycle; others skip this tick. Session-level lock survives the
        # intermediate commits inside the jobs and is released in ``finally``.
        if is_pg:
            got = (
                await session.execute(
                    text("SELECT pg_try_advisory_lock(:k)"), {"k": _SCHEDULER_LOCK_KEY}
                )
            ).scalar()
            if not got:
                log.info("scheduler.cycle_skipped", reason="another instance holds the lock")
                return {"skipped": "another instance holds the scheduler lock"}
        try:
            # GLOBAL: platform-wide upstream source registry, not org-owned.
            # Wrapped in its own SAVEPOINT for the same reason each per-tenant
            # step is (see ``_run_per_tenant_cycle``'s docstring): a bare
            # ``contextlib.suppress`` swallows the Python exception but, on a
            # DB-level failure, leaves the shared transaction ABORTED — the
            # very next statement on this session (``_active_org_ids`` below)
            # would then raise and kill the whole cycle. ``begin_nested()``
            # issues ``ROLLBACK TO SAVEPOINT`` on exception, which clears the
            # abort and leaves the session usable for the next step.
            try:
                async with session.begin_nested():
                    checks = await poll_sources(session)
                    out["catalog_checks"] = len(checks)
            except Exception as e:
                log.warning("scheduler.global_step_failed", step="poll_sources", error=str(e)[:200])

            # PER-TENANT: collection, ConMon, and control-test auto-run — one
            # pass per organization, each clamped to its own RLS tenant.
            org_ids = await _active_org_ids(session)
            out.update(await _run_per_tenant_cycle(session, org_ids, today=today))

            # GLOBAL: cross-module alert digest (ATO/POA&M/policy/vendor/etc.
            # rollups spanning the whole platform) — intentionally unscoped.
            # Same savepoint containment as above, so a digest failure can't
            # abort the transaction out from under the fedramp20x scan below.
            try:
                async with session.begin_nested():
                    out["digest"] = await digest.run(session, today=today)
            except Exception as e:
                log.warning("scheduler.global_step_failed", step="digest", error=str(e)[:200])
            try:
                async with session.begin_nested():
                    from ..fedramp20x import monitoring  # noqa: PLC0415 — lazy, keeps startup light

                    out["fedramp20x"] = await monitoring.scan(session, today=today)
            except Exception as e:
                log.warning(
                    "scheduler.global_step_failed", step="fedramp20x_monitoring", error=str(e)[:200]
                )
        finally:
            # Always release the tenant clamp before the advisory unlock, even
            # if the per-tenant loop raised past its own suppress (shouldn't,
            # but never leave the session's next use pinned to a stale org).
            await set_session_tenant(session, None)
            if is_pg:
                with contextlib.suppress(Exception):
                    await session.execute(
                        text("SELECT pg_advisory_unlock(:k)"), {"k": _SCHEDULER_LOCK_KEY}
                    )
    log.info("scheduler.cycle", **{k: (v if isinstance(v, int) else "ok") for k, v in out.items()})
    return out


async def _loop(interval_seconds: float) -> None:
    # Small startup delay so the app is fully up before the first cycle.
    await asyncio.sleep(15)
    while True:
        try:
            await run_cycle()
        except Exception as e:
            log.warning("scheduler.cycle_failed", error=str(e)[:200])
        await asyncio.sleep(interval_seconds)


def start() -> None:
    """Start the background scheduler if enabled (idempotent)."""
    global _task  # noqa: PLW0603 — module-level singleton task
    settings = get_settings()
    if not settings.scheduler_enabled or _task is not None:
        return
    interval = max(60.0, settings.scheduler_interval_hours * 3600.0)
    _task = asyncio.create_task(_loop(interval))
    log.info("scheduler.started", interval_hours=settings.scheduler_interval_hours)


async def stop() -> None:
    global _task  # noqa: PLW0603 — module-level singleton task
    if _task is not None:
        _task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await _task
        _task = None
