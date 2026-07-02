"""Concord-on-Concord self-assurance — init, run produces evidence, status, package."""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import ControlImplementation, System
from ccf.models_evidence import EvidenceObject, EvidenceVersion
from ccf.self_assurance import init_self_assurance, run_self_assessment, status

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def _local_evidence_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("CCF_EVIDENCE_BACKEND", "local")
    monkeypatch.setenv("CCF_EVIDENCE_LOCAL_DIR", str(tmp_path / "ev"))
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


@pytest.mark.asyncio
async def test_init_seeds_system_and_controls() -> None:
    async with session_scope() as s:
        out = await init_self_assurance(s)
        assert out["controls"] == 5
        sys_id = out["system_id"]
    async with session_scope() as s:
        sysm = await s.get(System, sys_id)
        assert sysm is not None and sysm.name == "Concord Platform"
        impls = (
            await s.execute(
                select(func.count()).select_from(ControlImplementation).where(
                    ControlImplementation.system_id == sys_id
                )
            )
        ).scalar_one()
        assert impls == 5


@pytest.mark.asyncio
async def test_init_is_idempotent() -> None:
    async with session_scope() as s:
        await init_self_assurance(s)
    async with session_scope() as s:
        await init_self_assurance(s)  # again
    async with session_scope() as s:
        systems = (
            await s.execute(select(System).where(System.name == "Concord Platform"))
        ).scalars().all()
        assert len(systems) == 1  # not duplicated


@pytest.mark.asyncio
async def test_run_produces_evidence_and_readiness() -> None:
    async with session_scope() as s:
        run = await run_self_assessment(s)
        assert run.readiness_pct >= 0
        assert run.checks_total > 0
        sys_id = run.system_id
    # Reliability output attached as evidence versions on the self evidence objects.
    async with session_scope() as s:
        obj = (
            await s.execute(
                select(EvidenceObject).where(
                    EvidenceObject.system_id == sys_id, EvidenceObject.framework == "CONCORD"
                ).limit(1)
            )
        ).scalars().first()
        assert obj is not None
        versions = (
            await s.execute(
                select(EvidenceVersion).where(EvidenceVersion.evidence_object_id == obj.id)
            )
        ).scalars().all()
        assert versions and versions[0].sha256  # digest present → scored/reproducible


@pytest.mark.asyncio
async def test_status_and_package_via_api() -> None:
    async with _client() as c:
        assert (await c.post("/api/admin/self-assurance/init")).status_code == 200
        run = await c.post("/api/admin/self-assurance/run")
        assert run.status_code == 200
        assert "control_status" in run.json()

        st = await c.get("/api/admin/self-assurance/status")
        assert st.json()["initialized"] is True

        pkg = await c.get("/api/admin/self-assurance/package")
        assert pkg.status_code == 200
        assert pkg.json()["package_id"] > 0


@pytest.mark.asyncio
async def test_status_before_init() -> None:
    # A fresh DB (this test may run first) reports uninitialized OR initialized;
    # the contract is only that it never errors and returns the flag.
    async with session_scope() as s:
        out = await status(s)
        assert "initialized" in out
