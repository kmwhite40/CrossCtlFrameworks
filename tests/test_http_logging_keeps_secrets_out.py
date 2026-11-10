"""httpx must not log the URLs Concord posts to: their paths are credentials.

httpx 0.28 logs ``HTTP Request: POST <full url> "HTTP/1.1 200 OK"`` at INFO, and
``configure_logging`` runs the root logger at INFO. A Slack/Teams incoming
webhook's path is its token, so every alert-channel test post and delivery, and
every tenant webhook delivery, wrote the secret to the log.

A REAL ``httpx.AsyncClient`` is used (on a ``MockTransport``): replacing the
client, as the delivery tests do, would also replace the logging under test.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from ccf import logging as ccf_logging
from ccf.events import webhooks
from ccf.governance import delivery, webhook_url
from ccf.models import Event

SECRET = "T0SECRET/B0SECRET/xoxSECRETtoken42"
URL = f"https://hooks.slack.example/services/{SECRET}"


@pytest.fixture
def real_client(monkeypatch: pytest.MonkeyPatch) -> list[httpx.Request]:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200)

    class _Real(httpx.AsyncClient):
        def __init__(self, **k: Any) -> None:
            super().__init__(transport=httpx.MockTransport(handler), **k)

    monkeypatch.setattr("ccf.governance.delivery.httpx.AsyncClient", _Real)
    monkeypatch.setattr("ccf.events.webhooks.httpx.AsyncClient", _Real)
    monkeypatch.setattr(webhook_url, "_resolve", lambda host: ["93.184.216.34"])
    return seen


@pytest.fixture
def production_logging() -> Iterator[None]:
    """``configure_logging`` as the services run it: root at INFO.

    Under pytest ``basicConfig`` finds pytest's handlers and does nothing, so
    the root level is set here as production's ``basicConfig(level=INFO)``
    would set it. Every level touched is put back."""
    root, names = logging.getLogger(), ("httpx", "httpcore")
    saved = (
        root.level,
        {n: (logging.getLogger(n).level, logging.getLogger(n).disabled) for n in names},
    )
    # Alembic's fileConfig (run by the test session's migrations) disables
    # loggers that existed before it; a service process never runs it, so the
    # httpx logger is re-enabled here or this test could not fail.
    for n in names:
        logging.getLogger(n).disabled = False
        logging.getLogger(n).setLevel(logging.NOTSET)
    ccf_logging.configure_logging()
    root.setLevel(logging.INFO)
    yield
    root.setLevel(saved[0])
    for n, (lvl, disabled) in saved[1].items():
        logging.getLogger(n).setLevel(lvl)
        logging.getLogger(n).disabled = disabled


async def test_an_alert_channel_post_does_not_log_its_url(
    real_client: list[httpx.Request],
    production_logging: None,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    logging.getLogger("ccf.positive_control").info("control line")
    reason, status = await delivery.send_pinned(URL, "hello")
    assert (reason, status) == (None, 200)
    assert len(real_client) == 1 and SECRET in str(real_client[0].url)  # really sent
    assert "control line" in caplog.text  # INFO records are captured at all
    out = capsys.readouterr()
    assert SECRET not in caplog.text
    assert SECRET not in out.out + out.err


async def test_a_tenant_webhook_delivery_does_not_log_its_url(
    real_client: list[httpx.Request],
    production_logging: None,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    hook = SimpleNamespace(url=URL, secret=None)
    ev = Event(id=1, verb="created", entity_type="risk", summary="s", payload={})
    reason, status = await webhooks.send(hook, ev)
    assert (reason, status) == (None, 200)
    assert len(real_client) == 1
    out = capsys.readouterr()
    assert SECRET not in caplog.text
    assert SECRET not in out.out + out.err


async def test_the_ops_post_does_not_log_its_url(
    real_client: list[httpx.Request],
    production_logging: None,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert await delivery.send(URL, "hello") == 200
    out = capsys.readouterr()
    assert SECRET not in caplog.text
    assert SECRET not in out.out + out.err


def test_httpx_warnings_still_reach_the_log(production_logging: None) -> None:
    assert logging.getLogger("httpx").getEffectiveLevel() == logging.WARNING
    assert logging.getLogger("httpcore").getEffectiveLevel() == logging.WARNING


async def test_the_capture_would_see_httpx_if_it_logged_at_info(
    real_client: list[httpx.Request],
    production_logging: None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Positive control: without the level, httpx's request line -- secret and
    all -- is exactly what the tests above would catch."""
    logging.getLogger("httpx").setLevel(logging.INFO)
    await delivery.send_pinned(URL, "hello")
    assert "HTTP Request: POST" in caplog.text and SECRET in caplog.text
