"""Playwright end-to-end smoke for the FedRAMP 20x UI.

Launches the real ASGI app under uvicorn in a background thread and drives it with
a headless Chromium. Skips cleanly when Playwright or its browser binaries are not
installed, so it never breaks CI on a machine without the e2e toolchain.

Run locally with:  pip install playwright && playwright install chromium
"""

from __future__ import annotations

import socket
import threading
import time

import httpx
import pytest
import uvicorn
from alembic import command
from alembic.config import Config

from ccf import db as ccf_db
from ccf.api.main import create_app
from ccf.config import get_settings

# Browser e2e: excluded from the default `pytest` run (it drives a real server +
# Chromium and owns the process's event loop). Run on demand:  pytest -m e2e
pytestmark = pytest.mark.e2e

playwright_api = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_fedramp20x_ui_renders_in_browser() -> None:
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(create_app(), host="127.0.0.1", port=port, log_level="warning")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    try:
        # Wait for the server to accept requests.
        for _ in range(100):
            try:
                if httpx.get(f"{base}/healthz", timeout=0.5).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.1)
        else:
            pytest.fail("uvicorn did not start")
        httpx.post(f"{base}/api/fedramp/20x/ksis/seed", timeout=10)

        try:
            with playwright_api.sync_playwright() as p:
                browser = p.chromium.launch()
        except Exception as exc:  # browser binaries missing → skip, don't fail
            pytest.skip(f"Chromium unavailable: {exc}")

        with playwright_api.sync_playwright() as p:
            browser = p.chromium.launch()
            try:
                page = browser.new_page()
                page.goto(f"{base}/fedramp20x", wait_until="networkidle")
                assert "FedRAMP 20x" in page.content()
                # The KSI catalog rendered at least the IAM family after seeding.
                assert page.locator("text=Identity and Access Management").count() >= 1
            finally:
                browser.close()
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        # The app bound the global async engine to uvicorn's (now-dead) event loop;
        # reset it so later DB-backed tests recreate it on their own loop.
        ccf_db._engine = None
        ccf_db._session_factory = None
