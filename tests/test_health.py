"""``/healthz`` (liveness) and ``/readyz`` (readiness) probes.

``/readyz`` must run the *blocking* reliability checks (see
``ccf.reliability.checks.BLOCKING_CHECKS``) and gate rotation: 503 + the
failing check name(s) when any blocking check FAILs, 200 otherwise.
``/healthz`` stays a cheap liveness probe independent of the reliability
suite — it must not flap just because a blocking check fails, or the
container would restart-loop instead of simply being pulled from rotation.
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.reliability import checks as checks_mod

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.mark.asyncio
async def test_healthz_is_cheap_and_ok() -> None:
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        r = await c.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_readyz_returns_200_when_blocking_checks_pass() -> None:
    """Test env: auth off + env=test, so auth_posture passes; migrated DB, so the
    rest of the blocking subset passes too -> /readyz must be 200."""
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        r = await c.get("/readyz")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ready"
    assert body["failing_checks"] == []
    names = {chk["name"] for chk in body["checks"]}
    # The full blocking subset actually ran (not the whole ~40-check suite).
    # external_access_scope_integrity is a global data-integrity condition, not
    # a per-instance readiness signal, so it is intentionally excluded here —
    # see BLOCKING_CHECKS in ccf.reliability.checks.
    assert names == {
        "database_connectivity",
        "alembic_migration_status",
        "required_tables",
        "auth_posture",
    }


@pytest.mark.asyncio
async def test_readyz_returns_503_and_names_failing_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Force a blocking check to FAIL by constructing an env where auth_posture
    legitimately fails (auth disabled outside dev) — not by weakening the check."""

    class _FakeSettings:
        env = "prod"
        auth_enabled = False
        auth_session_secret = "dev-insecure-change-me"

    monkeypatch.setattr(checks_mod, "get_settings", _FakeSettings)

    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        r = await c.get("/readyz")
    assert r.status_code == 503
    body = r.json()
    assert body["status"] == "not_ready"
    assert "auth_posture" in body["failing_checks"]
    failing_check = next(chk for chk in body["checks"] if chk["name"] == "auth_posture")
    assert failing_check["status"] == "fail"


@pytest.mark.asyncio
async def test_readyz_returns_503_when_migrations_are_behind_head(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A schema that is behind alembic head is unsafe to serve traffic from (it
    may be missing columns/tables a newer code path expects) and must gate
    readiness just like a missing alembic_version row does — not just WARN."""
    monkeypatch.setattr(ScriptDirectory, "get_current_head", lambda self: "drifted0000head")

    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        r = await c.get("/readyz")
    assert r.status_code == 503
    body = r.json()
    assert body["status"] == "not_ready"
    assert "alembic_migration_status" in body["failing_checks"]
    failing_check = next(chk for chk in body["checks"] if chk["name"] == "alembic_migration_status")
    assert failing_check["status"] == "fail"


@pytest.mark.asyncio
async def test_readyz_503_does_not_affect_healthz(monkeypatch: pytest.MonkeyPatch) -> None:
    """/healthz must stay 200 even while /readyz is failing — liveness must not
    depend on the reliability suite, or a failing blocking check would cause a
    restart loop instead of just being pulled from rotation."""

    class _FakeSettings:
        env = "prod"
        auth_enabled = False
        auth_session_secret = "dev-insecure-change-me"

    monkeypatch.setattr(checks_mod, "get_settings", _FakeSettings)

    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        ready = await c.get("/readyz")
        live = await c.get("/healthz")
    assert ready.status_code == 503
    assert live.status_code == 200
    assert live.json() == {"status": "ok"}
