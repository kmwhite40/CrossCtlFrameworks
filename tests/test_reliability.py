"""Reliability check subsystem — service, summary, API, and 20x coverage."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import get_engine, session_scope
from ccf.fedramp20x import package as pkg
from ccf.governance import scheduler
from ccf.reliability import checks as checks_mod
from ccf.reliability import run_checks, summarize
from ccf.reliability.checks import Check, _check_auth_posture
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


@pytest.mark.asyncio
async def test_auth_posture_check(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(env: str, enabled: bool, secret: str) -> object:
        return SimpleNamespace(env=env, auth_enabled=enabled, auth_session_secret=secret)

    # Dev is allowed to be open.
    monkeypatch.setattr(checks_mod, "get_settings", lambda: fake("dev", False, "x"))
    assert (await _check_auth_posture(None)).status == "pass"  # type: ignore[arg-type]

    # Production with auth disabled -> fail.
    monkeypatch.setattr(checks_mod, "get_settings", lambda: fake("prod", False, "x"))
    assert (await _check_auth_posture(None)).status == "fail"  # type: ignore[arg-type]

    # Production with the default secret -> fail.
    monkeypatch.setattr(
        checks_mod, "get_settings", lambda: fake("prod", True, "dev-insecure-change-me")
    )
    assert (await _check_auth_posture(None)).status == "fail"  # type: ignore[arg-type]

    # Production, auth on, real secret -> pass.
    monkeypatch.setattr(checks_mod, "get_settings", lambda: fake("prod", True, "s3cret"))
    assert (await _check_auth_posture(None)).status == "pass"  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_scheduler_leader_lock_skips_when_held() -> None:
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("advisory locks are a PostgreSQL feature")
    engine = get_engine()
    # Hold the scheduler advisory lock on a dedicated connection.
    async with engine.connect() as held:
        got = (
            await held.execute(
                text("SELECT pg_try_advisory_lock(:k)"), {"k": scheduler._SCHEDULER_LOCK_KEY}
            )
        ).scalar()
        assert got is True
        # A concurrent cycle must skip rather than double-run.
        result = await scheduler.run_cycle()
        assert "skipped" in result
        await held.execute(
            text("SELECT pg_advisory_unlock(:k)"), {"k": scheduler._SCHEDULER_LOCK_KEY}
        )


async def test_package_export_check_fails_when_oscal_validation_reports_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The FAIL branch of _check_package_service, which nothing exercised.

    The check was tested only for appearing in the check list by name.
    Replacing its `pkg.validate_oscal(...)` call with a bare `errors = []`
    -- i.e. removing the validation entirely -- left all 18 reliability tests
    green, so the ops layer would have reported the OSCAL exporter healthy
    without ever validating anything.
    """
    monkeypatch.setattr(pkg, "validate_oscal", lambda _doc: ["missing required field: uuid"])
    async with session_scope() as s:
        result = await checks_mod._check_package_service(s)

    assert result.name == "fedramp20x_package_export"
    assert result.status == checks_mod.FAIL, "validation errors must fail the check"
    assert "missing required field: uuid" in result.message, (
        "the actual validator error must reach the operator, not just a generic failure"
    )


async def test_package_export_check_passes_when_oscal_validation_is_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The other side, so the FAIL test above cannot pass by always failing."""
    monkeypatch.setattr(pkg, "validate_oscal", lambda _doc: [])
    async with session_scope() as s:
        result = await checks_mod._check_package_service(s)

    assert result.status == checks_mod.PASS
    assert "OSCAL valid" in result.message
