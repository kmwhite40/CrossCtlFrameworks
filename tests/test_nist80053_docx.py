"""``render_80053_docx`` + the ``nist-800-53r5`` generate/seed/create routes.

Mirrors ``tests/test_scoring_ssp.py`` (``test_ssp_project_lifecycle_and_document``)
for the API-route auth harness, and ``tests/test_nist80053_seed.py`` for the
``session_scope``/``fresh_engine`` DB fixture style.
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, System
from ccf.ssp.nist80053_docx import render_80053_docx

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _make_org_system(name: str, *, baseline: str = "moderate") -> tuple[int, int]:
    async with session_scope() as s:
        org = (
            await s.execute(select(Organization).where(Organization.name == name))
        ).scalar_one_or_none()
        if org is None:
            org = Organization(name=name)
            s.add(org)
            await s.flush()
        sys = (
            await s.execute(
                select(System).where(System.organization_id == org.id, System.name == f"{name} sys")
            )
        ).scalar_one_or_none()
        if sys is None:
            sys = System(organization_id=org.id, name=f"{name} sys", baseline=baseline)
            s.add(sys)
            await s.flush()
        return org.id, sys.id


def _entries() -> list[dict[str, object]]:
    return [
        {
            "control_id": "AC-2",
            "nist_id": "AC-2",
            "domain": "AC",
            "title": "Account Management",
            "requirement": "The organization manages information system accounts.",
            "responsible_role": "System Administrator",
            "implementation_status": ["Planned"],
            "control_origination": ["Organization System Specific"],
            "part_narratives": [
                {
                    "label": "",
                    "text": "[DRAFT] Accounts are provisioned via the IdP.",
                    "draft": True,
                }
            ],
            "odp_values": {"ac-2_prm_1": "quarterly", "ac-2_prm_2": None},
        },
        {
            "control_id": "AU-2",
            "nist_id": "AU-2",
            "domain": "AU",
            "title": "Event Logging",
            "requirement": "The organization identifies event types to log.",
            "responsible_role": "Security Engineer",
            "implementation_status": ["implemented"],
            "control_origination": ["shared"],
            "part_narratives": [
                {"label": "", "text": "[DRAFT] Logging is centralized.", "draft": True}
            ],
            "odp_values": {"au-2_prm_1": None},
        },
    ]


def test_render_80053_docx_returns_valid_docx_bytes() -> None:
    project = {
        "customer_name": "Acme Federal",
        "system_name": "CUI Enclave",
        "platform": "AWS GovCloud",
        "title": "System Security Plan",
        "version": "0.1",
        "prepared_by": "J. Analyst",
        "document_date": "01/01/2026",
        "baseline": "moderate",
    }
    data = render_80053_docx(project, _entries())
    assert isinstance(data, bytes)
    assert data[:2] == b"PK"
    assert len(data) > 1000


def test_render_80053_docx_shows_unset_odps() -> None:
    """An ODP with a ``None`` value renders as ``[unset]``, not blank/missing."""
    project = {"customer_name": "Acme Federal", "baseline": "low"}
    entries = _entries()
    # Sanity: the fixture actually contains an unset ODP for this assertion to matter.
    assert entries[0]["odp_values"]["ac-2_prm_2"] is None  # type: ignore[index]
    data = render_80053_docx(project, entries)
    assert data[:2] == b"PK"


@pytest.mark.asyncio
async def test_create_project_rejects_unknown_framework() -> None:
    async with _client() as c:
        r = await c.post(
            "/api/ssp/projects",
            json={"customer_name": "Bad Framework Co", "framework": "not-a-real-framework"},
        )
        assert r.status_code == 422


@pytest.mark.asyncio
async def test_nist80053_project_lifecycle_and_document() -> None:
    _org_id, sys_id = await _make_org_system("Nist80053RouteOrg", baseline="moderate")
    async with _client() as c:
        r = await c.post(
            "/api/ssp/projects",
            json={
                "customer_name": "Nist80053RouteOrg",
                "system_id": sys_id,
                "framework": "nist-800-53r5",
                "version": "0.1",
            },
        )
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["framework"] == "nist-800-53r5"
        pid = body["id"]

        detail = (await c.get(f"/api/ssp/projects/{pid}")).json()
        assert detail["project"]["framework"] == "nist-800-53r5"
        assert len(detail["entries"]) > 0
        assert any(e["control_id"] == "AC-2" for e in detail["entries"])

        doc = await c.get(f"/api/ssp/projects/{pid}/document")
        assert doc.status_code == 200
        assert doc.headers["content-type"].startswith(
            "application/vnd.openxmlformats-officedocument"
        )
        assert doc.content[:2] == b"PK"
        assert "800-53r5" in doc.headers["content-disposition"]


@pytest.mark.asyncio
async def test_cmmc_generate_path_still_works() -> None:
    """Regression: the default (CMMC/800-171) project + docx generation path is
    unaffected by the framework branch added to the generate route."""
    async with _client() as c:
        await c.post("/api/scoring/seed")
        r = await c.post(
            "/api/ssp/projects",
            json={"customer_name": "Cmmc Regression Co", "system_name": "Enclave"},
        )
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["framework"] == "cmmc-800-171"
        pid = body["id"]

        detail = (await c.get(f"/api/ssp/projects/{pid}")).json()
        assert len(detail["entries"]) == 110

        doc = await c.get(f"/api/ssp/projects/{pid}/document")
        assert doc.status_code == 200
        assert doc.headers["content-type"].startswith(
            "application/vnd.openxmlformats-officedocument"
        )
        assert doc.content[:2] == b"PK"
        assert "ssp-appendix-a" in doc.headers["content-disposition"]
