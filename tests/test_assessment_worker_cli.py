"""``ccf assessment-worker`` -- the objective-level assessment engine's drain loop.

Regression coverage for the exact same class of incident ``ccf prep-worker``
shipped and then had to fix (see ``tests/test_prep_cli.py``): a worker whose
stale-job reap ran only once, at process start, rather than on its own
cadence inside the loop. For a long-running ``--loop`` worker under
``restart: unless-stopped``, that means no job can ever be found stale --
every ``claimed_at`` is necessarily fresher than the staleness window at
process start -- so a job whose worker later dies mid-evaluation stays
``claimed`` forever: never requeued, never dead-lettered. The retry-cap
machinery in ``ccf.assessment.engine.jobs``/``ccf.config`` becomes
unreachable, silently.
"""

from __future__ import annotations

from typing import Any

import pytest
from typer.testing import CliRunner

from ccf import cli
from ccf.config import get_settings

pytestmark = pytest.mark.usefixtures("fresh_engine")

runner = CliRunner()


class _StopTestError(Exception):
    """Raised by the mocked ``run_once`` to end an otherwise-infinite loop."""


def test_worker_is_absent_when_the_engine_is_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """assessment_engine_enabled=False -> clean exit, clear message, no work."""
    settings = get_settings()
    monkeypatch.setattr(settings, "assessment_engine_enabled", False)

    called = False

    async def _run_once(session: Any, *, worker: str, limit: int) -> dict[str, int]:
        nonlocal called
        called = True
        return {"claimed": 0, "finished": 0, "failed": 0}

    monkeypatch.setattr(cli.assessment_jobs, "run_once", _run_once)

    result = runner.invoke(cli.app, ["assessment-worker"])

    assert result.exit_code == 0
    assert "disabled" in result.stdout.lower()
    assert not called, "a disabled engine must do no work, not merely print a warning first"


def test_worker_help_lists_the_expected_options() -> None:
    result = runner.invoke(cli.app, ["assessment-worker", "--help"])

    assert result.exit_code == 0
    assert "--once" in result.stdout
    assert "--loop" in result.stdout
    assert "--limit" in result.stdout
    assert "--worker" in result.stdout


async def test_the_reaper_runs_inside_the_loop_not_once_at_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Slice 1 shipped a worker that reaped only at startup, silently disabling
    the dead-letter net. Assert a job becoming stale AFTER startup is reaped.
    """
    reap_calls = 0
    run_once_calls = 0

    async def _reap(session: Any) -> dict[str, int]:
        nonlocal reap_calls
        reap_calls += 1
        return {"requeued": 0, "dead_lettered": 0}

    async def _run_once(session: Any, *, worker: str, limit: int) -> dict[str, int]:
        nonlocal run_once_calls
        run_once_calls += 1
        if run_once_calls >= 3:
            raise _StopTestError
        return {"claimed": 0, "finished": 0, "failed": 0}

    async def _no_sleep(_seconds: float) -> None:
        return None

    # Controls how far apart consecutive clock reads inside
    # _assessment_drain_loop appear: cycle 1 always reaps (last_reap starts
    # at -inf); cycle 2's clock hasn't advanced past the interval, so it must
    # NOT reap again -- that would be cycle 1's behavior repeating, not proof
    # the cadence is real; cycle 3's clock has advanced past it (a job going
    # stale *after* startup), so it must reap again. Passed in via
    # _assessment_drain_loop's own `now` parameter rather than monkeypatching
    # the real `time.monotonic` -- `time` is one shared module object for the
    # whole process, and asyncio's own internal scheduling calls
    # `time.monotonic()` continuously, so patching it globally would starve
    # this iterator on unrelated calls almost immediately.
    clock = iter([0.0, 0.0, 1_000.0])

    monkeypatch.setattr(cli.assessment_jobs, "reap", _reap)
    monkeypatch.setattr(cli.assessment_jobs, "run_once", _run_once)
    monkeypatch.setattr(cli.asyncio, "sleep", _no_sleep)

    settings = get_settings()
    monkeypatch.setattr(settings, "assessment_worker_reap_interval_seconds", 500.0)

    with pytest.raises(_StopTestError):
        await cli._assessment_drain_loop(
            once=False,
            worker="test-worker",
            batch=5,
            settings=settings,
            now=lambda: next(clock),
        )

    assert run_once_calls == 3
    assert reap_calls == 2, (
        "reap must run again once the reap interval has elapsed, not only "
        f"once at the very first cycle -- got {reap_calls} reap call(s)"
    )


async def test_loop_sleeps_between_empty_cycles(monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty cycle in ``--loop`` mode must actually sleep for
    ``assessment_worker_poll_interval_seconds`` -- not spin the claim query
    hot and not silently skip the sleep and exit (the reap-cadence test above
    patches ``asyncio.sleep`` to a no-op too, but only for its own unrelated
    purpose and without asserting on it, so it would not catch the sleep
    itself being deleted). This test captures the argument the loop actually
    passes to the patched ``asyncio.sleep``.
    """
    sleep_calls: list[float] = []
    run_once_calls = 0

    async def _reap(session: Any) -> dict[str, int]:
        return {"requeued": 0, "dead_lettered": 0}

    async def _run_once(session: Any, *, worker: str, limit: int) -> dict[str, int]:
        nonlocal run_once_calls
        run_once_calls += 1
        if run_once_calls >= 2:
            raise _StopTestError
        return {"claimed": 0, "finished": 0, "failed": 0}

    async def _capture_sleep(seconds: float) -> None:
        sleep_calls.append(seconds)

    monkeypatch.setattr(cli.assessment_jobs, "reap", _reap)
    monkeypatch.setattr(cli.assessment_jobs, "run_once", _run_once)
    monkeypatch.setattr(cli.asyncio, "sleep", _capture_sleep)

    settings = get_settings()
    monkeypatch.setattr(settings, "assessment_worker_poll_interval_seconds", 42.0)

    with pytest.raises(_StopTestError):
        await cli._assessment_drain_loop(
            once=False, worker="test-worker", batch=5, settings=settings
        )

    assert sleep_calls == [42.0], (
        "an empty cycle in --loop mode must sleep for exactly "
        "assessment_worker_poll_interval_seconds, not spin hot or skip the sleep -- "
        f"got sleep calls {sleep_calls}"
    )
