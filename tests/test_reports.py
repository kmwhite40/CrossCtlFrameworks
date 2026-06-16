"""Custom report builder export formats (CSV / XLSX / DOCX / JSON)."""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.reporting import report_to_docx, report_to_xlsx

pytestmark = pytest.mark.usefixtures("fresh_engine")

_XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
_DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


def test_renderers_emit_real_office_files() -> None:
    summary = {"organization": "Acme", "baseline": "mod", "total_rows": 1}
    rows = [
        {"identifier": "AC-1", "family": "AC", "control_name": "Policy", "baseline_mod": True},
    ]
    xlsx = report_to_xlsx(summary, rows)
    docx = report_to_docx(summary, rows)
    assert xlsx[:2] == b"PK" and len(xlsx) > 0
    assert docx[:2] == b"PK" and len(docx) > 0


@pytest.mark.asyncio
async def test_build_endpoint_serves_each_format() -> None:
    async with _client() as c:
        j = await c.get("/api/reports/build", params={"baseline": "mod", "fmt": "json"})
        assert j.status_code == 200
        assert {"summary", "rows"} <= j.json().keys()

        xlsx = await c.get(
            "/api/reports/build", params={"baseline": "mod", "fmt": "xlsx", "filename": "audit pkg"}
        )
        assert xlsx.status_code == 200
        assert xlsx.headers["content-type"] == _XLSX
        assert "audit_pkg.xlsx" in xlsx.headers["content-disposition"]
        assert xlsx.content[:2] == b"PK"

        docx = await c.get("/api/reports/build", params={"baseline": "mod", "fmt": "docx"})
        assert docx.status_code == 200
        assert docx.headers["content-type"] == _DOCX
        assert docx.content[:2] == b"PK"
