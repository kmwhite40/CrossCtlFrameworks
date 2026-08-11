"""``ccf prep-worker``'s drain loop — reap cadence, not just startup.

Regression coverage for a bug this fix wave itself introduced: an earlier
version of the ``--loop`` fix (making the worker actually loop instead of
exiting on the first empty cycle) left the stale-job reap call sitting
*outside* the loop, called exactly once at process start. For a long-running
``--loop`` worker under ``restart: unless-stopped``, that meant the reap
could never run again for the rest of the process's life — no job could
possibly be stale yet at process start (every ``claimed_at`` is necessarily
fresher than ``prep_job_stale_after_minutes``), so a job whose worker died
mid-stage later on would stay ``claimed`` forever: never requeued, never
dead-lettered. The entire retry-cap machinery documented in ``jobs.py`` and
``config.py`` becomes unreachable — precisely the silent-failure class this
whole review wave exists to close.
"""

from __future__ import annotations

from typing import Any

import pytest

from ccf import cli
from ccf.config import get_settings

pytestmark = pytest.mark.usefixtures("fresh_engine")


class _StopTestError(Exception):
    """Raised by the mocked ``run_once`` to end an otherwise-infinite loop."""


async def test_loop_reaps_stale_jobs_again_on_a_later_cycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reap_calls: list[int] = []
    run_once_calls = 0

    async def _reap_stale(session: Any, *, older_than_minutes: int) -> int:
        reap_calls.append(older_than_minutes)
        return 0

    async def _run_once(session: Any, *, worker: str, limit: int) -> dict[str, int]:
        nonlocal run_once_calls
        run_once_calls += 1
        if run_once_calls >= 3:
            raise _StopTestError
        return {"claimed": 0, "finished": 0, "failed": 0}

    async def _no_sleep(_seconds: float) -> None:
        return None

    # Controls how far apart consecutive clock reads inside _drain_loop
    # appear: cycle 1 always reaps (last_reap starts at -inf); cycle 2's
    # clock hasn't advanced past the interval, so it must NOT reap again;
    # cycle 3's clock has, so it must. Passed in via _drain_loop's own `now`
    # parameter rather than monkeypatching the real `time.monotonic` --
    # `time` is one shared module object for the whole process, and
    # asyncio's own internal scheduling calls `time.monotonic()`
    # continuously, so patching it globally would starve this iterator on
    # unrelated calls almost immediately.
    clock = iter([0.0, 0.0, 1_000.0])

    monkeypatch.setattr(cli.prep_jobs, "reap_stale", _reap_stale)
    monkeypatch.setattr(cli.prep_jobs, "run_once", _run_once)
    monkeypatch.setattr(cli.asyncio, "sleep", _no_sleep)

    settings = get_settings()
    monkeypatch.setattr(settings, "prep_worker_reap_interval_seconds", 500.0)

    with pytest.raises(_StopTestError):
        await cli._drain_loop(
            once=False, worker="test-worker", batch=5, settings=settings,
            now=lambda: next(clock),
        )

    assert run_once_calls == 3
    assert len(reap_calls) == 2, (
        "reap_stale must run again once the reap interval has elapsed, not "
        "only once at the very first cycle -- got calls at cycles "
        f"corresponding to {len(reap_calls)} reap(s)"
    )


async def test_once_mode_still_reaps_before_its_single_cycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``--once`` must keep reaping before its one cycle, matching the
    pre-existing behavior for that mode (only ``--loop``'s cadence changed).
    """
    reap_calls = 0
    run_once_calls = 0

    async def _reap_stale(session: Any, *, older_than_minutes: int) -> int:
        nonlocal reap_calls
        reap_calls += 1
        return 0

    async def _run_once(session: Any, *, worker: str, limit: int) -> dict[str, int]:
        nonlocal run_once_calls
        run_once_calls += 1
        return {"claimed": 0, "finished": 0, "failed": 0}

    monkeypatch.setattr(cli.prep_jobs, "reap_stale", _reap_stale)
    monkeypatch.setattr(cli.prep_jobs, "run_once", _run_once)

    settings = get_settings()
    await cli._drain_loop(once=True, worker="test-worker", batch=5, settings=settings)

    assert reap_calls == 1
    assert run_once_calls == 1
