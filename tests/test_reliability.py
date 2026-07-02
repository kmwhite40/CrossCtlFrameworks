"""Reliability check subsystem — service, summary, API, and 20x coverage."""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.reliability import run_checks, summarize
from ccf.reliability.checks import Check
from ccf.reliability.checks import summarize as summarize_checks

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def test_summarize_overall_precedence() -> None:
    passing = [Check("a", "pass", "ok"), Check("b", "pass", "ok")]
    assert summarize_checks(passing)["overall"] == "pass"
    warn = [*passing, Check("c", "warn", "meh")]
    assert summarize_checks(warn)["overall"] == "warn"
    fail = [*warn, Check("d", "fail", "bad")]
    assert summarize_checks(fail)["overall"] == "fail"
    assert summarize_checks(fail)["counts"] == {"pass": 2, "warn": 1, "fail": 1}


@pytest.mark.asyncio
async def test_run_checks_covers_platform_and_20x() -> None:
    async with session_scope() as s:
        checks = await run_checks(s)
    names = {c.name for c in checks}
    # Platform checks.
    assert "database_connectivity" in names
    assert "required_tables" in names
    assert "alembic_migration_status" in names
    # FedRAMP 20x checks.
    assert "fedramp20x_ksi_catalog_file" in names
    assert "fedramp20x_validation_service" in names
    assert "fedramp20x_package_export" in names
    assert "fedramp20x_api_endpoints" in names
    # Structural: every check has a status + timestamp.
    for c in checks:
        assert c.status in {"pass", "warn", "fail"}
        assert c.timestamp

    summary = summarize(checks)
    # DB is connected and migrated in the test env -> no hard failures.
    assert summary["overall"] in {"pass", "warn"}
    assert summary["total"] == len(checks)


@pytest.mark.asyncio
async def test_reliability_endpoint() -> None:
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        # Seed KSIs so the catalog-loaded check passes cleanly.
        await c.post("/api/fedramp/20x/ksis/seed")
        r = await c.get("/api/admin/reliability")
        assert r.status_code in (200, 503)
        body = r.json()
        assert body["overall"] in {"pass", "warn", "fail"}
        assert any(chk["name"] == "fedramp20x_ksi_catalog_loaded" for chk in body["checks"])
