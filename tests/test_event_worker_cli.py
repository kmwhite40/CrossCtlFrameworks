"""Running the event bus: ``ccf event-worker``, the API's inline drain, the compose wiring.

The inline loop is the dev-loop path (no worker container): it runs only when
``event_drain_inline and not event_worker_enabled``, so a deployment with a real
worker never double-drains. conftest defaults ``CCF_EVENT_DRAIN_INLINE`` to false so no
background drain races an unrelated test; the tests here switch it on explicitly.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from ccf import cli
from ccf.api import main as api_main
from ccf.config import get_settings
from ccf.events import consumers

runner = CliRunner()
COMPOSE = Path(__file__).resolve().parent.parent / "docker-compose.yml"


@pytest.fixture
def settings_env(monkeypatch: pytest.MonkeyPatch) -> Any:
    def _set(**env: str) -> None:
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        get_settings.cache_clear()

    yield _set
    monkeypatch.undo()
    get_settings.cache_clear()


def _fake_drain(calls: list[dict[str, Any]]) -> Any:
    async def fake(**kw: Any) -> dict[str, int]:
        calls.append(kw)
        return {"done": 0, "merged": 0, "retried": 0, "failed": 0, "skipped": 0}

    return fake


def test_event_worker_once_drains_and_exits(
    monkeypatch: pytest.MonkeyPatch, settings_env: Any
) -> None:
    settings_env(CCF_EVENT_WORKER_ENABLED="true")
    calls: list[dict[str, Any]] = []
    reaps: list[int] = []

    async def fake_reap(**_kw: Any) -> int:
        reaps.append(1)
        return 0

    monkeypatch.setattr(cli.event_worker, "drain_once", _fake_drain(calls))
    monkeypatch.setattr(cli.event_worker, "reap", fake_reap)
    result = runner.invoke(cli.app, ["event-worker", "--once"])
    assert result.exit_code == 0, result.output
    assert len(calls) == 1 and calls[0]["worker"] == "event-worker"
    assert reaps == [1]
    # The worker process drains registered consumers: importing the package registered them.
    assert consumers.REGISTRY


def test_event_worker_exits_cleanly_when_disabled(
    monkeypatch: pytest.MonkeyPatch, settings_env: Any
) -> None:
    settings_env(CCF_EVENT_WORKER_ENABLED="false")
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(cli.event_worker, "drain_once", _fake_drain(calls))
    result = runner.invoke(cli.app, ["event-worker", "--once"])
    assert result.exit_code == 0
    assert "disabled" in result.output.lower()
    assert calls == []


async def _run_lifespan_briefly(calls: list[dict[str, Any]], seconds: float) -> None:
    async with api_main.lifespan(api_main.create_app()):
        await asyncio.sleep(seconds)


async def test_the_inline_loop_is_off_when_the_worker_is_enabled(
    monkeypatch: pytest.MonkeyPatch, settings_env: Any
) -> None:
    settings_env(
        CCF_EVENT_DRAIN_INLINE="true",
        CCF_EVENT_WORKER_ENABLED="true",
        CCF_EVENT_DRAIN_INTERVAL_SECONDS="0.01",
    )
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(api_main.event_worker, "drain_once", _fake_drain(calls))
    await _run_lifespan_briefly(calls, 0.2)
    assert calls == []


async def test_the_inline_loop_is_off_when_inline_is_disabled(
    monkeypatch: pytest.MonkeyPatch, settings_env: Any
) -> None:
    settings_env(
        CCF_EVENT_DRAIN_INLINE="false",
        CCF_EVENT_WORKER_ENABLED="false",
        CCF_EVENT_DRAIN_INTERVAL_SECONDS="0.01",
    )
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(api_main.event_worker, "drain_once", _fake_drain(calls))
    await _run_lifespan_briefly(calls, 0.2)
    assert calls == []


async def test_the_inline_loop_drains_a_pending_job(
    monkeypatch: pytest.MonkeyPatch, settings_env: Any
) -> None:
    settings_env(
        CCF_EVENT_DRAIN_INLINE="true",
        CCF_EVENT_WORKER_ENABLED="false",
        CCF_EVENT_DRAIN_INTERVAL_SECONDS="0.01",
    )
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(api_main.event_worker, "drain_once", _fake_drain(calls))
    await _run_lifespan_briefly(calls, 0.2)
    assert calls, "the inline loop never drained"
    assert all(c == {"worker": "api-inline", "limit": 1} for c in calls)


async def test_a_failing_drain_does_not_stop_the_inline_loop(
    monkeypatch: pytest.MonkeyPatch, settings_env: Any
) -> None:
    settings_env(
        CCF_EVENT_DRAIN_INLINE="true",
        CCF_EVENT_WORKER_ENABLED="false",
        CCF_EVENT_DRAIN_INTERVAL_SECONDS="0.01",
    )
    n = 0

    async def flaky(**_kw: Any) -> dict[str, int]:
        nonlocal n
        n += 1
        raise RuntimeError("boom")

    monkeypatch.setattr(api_main.event_worker, "drain_once", flaky)
    await _run_lifespan_briefly([], 0.3)
    assert n >= 2


def test_compose_sets_the_worker_flag_on_api_and_worker() -> None:
    services = yaml.safe_load(COMPOSE.read_text())["services"]
    assert services["api"]["environment"]["CCF_EVENT_WORKER_ENABLED"] in ("true", True)
    worker = services["event-worker"]
    assert worker["environment"]["CCF_EVENT_WORKER_ENABLED"] in ("true", True)
    # No profile: it must start with a plain `docker compose up`, since the api
    # (flag true) skips the inline drain.
    assert "profiles" not in worker
    assert worker["healthcheck"] == {"disable": True}
    assert "event-worker" in " ".join(worker["command"])
