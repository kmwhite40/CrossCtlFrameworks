"""The UI scan upload runs the same ingest as the API, guards included.

``POST /scans`` (the HTML form) was a hand copy of ``POST /api/scans/ingest``
that had lost four things on the way: the system scope check, the 64 MiB cap,
the parse-error-to-422 translation (a bad file was a 500), and the event plus
notification, so scans uploaded through the UI never alerted anyone. Both
routes now call ``scans.ingest_upload``.
"""

from __future__ import annotations

import io

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.api.routes import scans
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Notification, Organization, ScanIngestion, System
from tests.test_scan_ingest import NESSUS_XML

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _make_system(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"{name} system")
        s.add(sysm)
        await s.flush()
        return sysm.id


def _file(content: bytes, name: str = "scan.nessus") -> dict:
    return {"file": (name, io.BytesIO(content), "text/xml")}


@pytest.mark.asyncio
async def test_ui_upload_notifies_like_the_api() -> None:
    sys_id = await _make_system("UiScanOrg-notify")
    async with _client() as c:
        r = await c.post(
            "/scans", data={"system_id": sys_id, "scanner": "nessus"}, files=_file(NESSUS_XML)
        )
        assert r.status_code == 303, r.text

    async with session_scope() as s:
        ingestion = (
            await s.execute(select(ScanIngestion).where(ScanIngestion.system_id == sys_id))
        ).scalar_one()
        note = (
            await s.execute(
                select(Notification).where(
                    Notification.entity_type == "scan_ingestion",
                    Notification.entity_id == str(ingestion.id),
                )
            )
        ).scalar_one_or_none()
        assert note is not None


@pytest.mark.asyncio
async def test_ui_upload_of_an_unparseable_file_is_a_422() -> None:
    sys_id = await _make_system("UiScanOrg-parse")
    async with _client() as c:
        r = await c.post(
            "/scans",
            data={"system_id": sys_id, "scanner": "nessus"},
            files=_file(b"<<<not xml"),
        )
        assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_ui_upload_enforces_the_size_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    sys_id = await _make_system("UiScanOrg-size")
    monkeypatch.setattr(scans, "_MAX_SCAN_BYTES", len(NESSUS_XML) - 1)
    async with _client() as c:
        r = await c.post(
            "/scans", data={"system_id": sys_id, "scanner": "nessus"}, files=_file(NESSUS_XML)
        )
        assert r.status_code == 413, r.text


@pytest.mark.asyncio
async def test_ui_upload_checks_the_system_exists_in_scope() -> None:
    async with _client() as c:
        r = await c.post(
            "/scans", data={"system_id": 987654321, "scanner": "nessus"}, files=_file(NESSUS_XML)
        )
        assert r.status_code == 404, r.text
