"""In-app automation scheduler.

When ``CCF_SCHEDULER_ENABLED`` is set, a background asyncio loop runs the
continuous jobs on a cadence — catalog drift poll, ConMon scan, alert digest,
and connector collection — so the platform operates as a live program without an
external cron. One cycle is also exposed via ``ccf scheduler --once`` / the API.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime
from typing import Any

from ..config import get_settings
from ..db import session_scope
from ..etl.sources import poll as poll_sources
from ..logging import get_logger
from . import collection, conmon, digest

log = get_logger(__name__)

_task: asyncio.Task[None] | None = None


async def run_cycle() -> dict[str, Any]:
    """Run one full automation cycle. Returns per-job results."""
    today = datetime.now(UTC).date()
    out: dict[str, Any] = {}
    async with session_scope() as session:
        with contextlib.suppress(Exception):
            checks = await poll_sources(session)
            out["catalog_checks"] = len(checks)
        with contextlib.suppress(Exception):
            out["conmon"] = await conmon.scan(session, today=today)
        with contextlib.suppress(Exception):
            out["digest"] = await digest.run(session, today=today)
        with contextlib.suppress(Exception):
            out["collection"] = await collection.collect_all(session)
        with contextlib.suppress(Exception):
            from ..fedramp20x import monitoring  # noqa: PLC0415 — lazy import keeps startup light

            out["fedramp20x"] = await monitoring.scan(session, today=today)
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
