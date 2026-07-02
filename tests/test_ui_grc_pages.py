"""Smoke + flow tests for the new server-rendered GRC pages."""

from __future__ import annotations

import io

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import POAM, Organization, System, Vendor
from ccf.models_people import Person
from ccf.models_tprm import QuestionnaireResponse, VendorQuestionnaire

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


NESSUS = b"""<?xml version="1.0"?>
<NessusClientData_v2><Report name="s"><ReportHost name="h1">
  <ReportItem severity="4" pluginID="1" pluginName="Crit"><cve>CVE-2026-9</cve></ReportItem>
</ReportHost></Report></NessusClientData_v2>"""


@pytest.mark.asyncio
async def test_pages_render() -> None:
    async with _client() as c:
        for path in ("/personnel", "/scans", "/vendor-questionnaires"):
            r = await c.get(path)
            assert r.status_code == 200, path
            assert "Concord" in r.text


@pytest.mark.asyncio
async def test_personnel_page_onboard_flow() -> None:
    async with _client() as c:
        r = await c.post(
            "/personnel",
            data={"full_name": "UI Hire", "risk_designation": "high"},
            follow_redirects=True,
        )
        assert r.status_code == 200
        assert "UI Hire" in r.text
    async with session_scope() as s:
        p = (
            await s.execute(select(Person).where(Person.full_name == "UI Hire"))
        ).scalar_one_or_none()
        assert p is not None and p.status == "active"


@pytest.mark.asyncio
async def test_scans_page_upload_creates_poam() -> None:
    async with session_scope() as s:
        org = Organization(name="UIScanOrg")
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name="UIScanSys", baseline="moderate")
        s.add(sysm)
        await s.flush()
        sid = sysm.id
    async with _client() as c:
        r = await c.post(
            "/scans",
            data={"system_id": sid, "scanner": "nessus"},
            files={"file": ("s.nessus", io.BytesIO(NESSUS), "text/xml")},
            follow_redirects=True,
        )
        assert r.status_code == 200
        assert "nessus" in r.text
    async with session_scope() as s:
        poams = (await s.execute(select(POAM).where(POAM.system_id == sid))).scalars().all()
        assert len(poams) == 1
        assert poams[0].scanner == "nessus"


@pytest.mark.asyncio
async def test_questionnaire_page_full_flow_scores_and_rates_vendor() -> None:
    async with session_scope() as s:
        org = Organization(name="UIQnrOrg")
        s.add(org)
        await s.flush()
        v = Vendor(organization_id=org.id, name="UI Vendor")
        s.add(v)
        await s.flush()
        vid = v.id
    async with _client() as c:
        # Instantiate → detail page.
        inst = await c.post(
            "/vendor-questionnaires", data={"vendor_id": vid}, follow_redirects=False
        )
        assert inst.status_code == 303
        loc = inst.headers["location"]
        qid = int(loc.rsplit("/", 1)[-1])

        detail = await c.get(loc)
        assert detail.status_code == 200

        # Answer every question 'yes'.
        async with session_scope() as s:
            resp_ids = [
                r.id
                for r in (
                    await s.execute(
                        select(QuestionnaireResponse).where(
                            QuestionnaireResponse.questionnaire_id == qid
                        )
                    )
                ).scalars().all()
            ]
        for rid in resp_ids:
            await c.post(
                f"/vendor-questionnaires/{qid}/responses/{rid}", data={"answer": "yes"}
            )

        rev = await c.post(
            f"/vendor-questionnaires/{qid}/review", data={"open_tasks": "1"},
            follow_redirects=True,
        )
        assert rev.status_code == 200

    async with session_scope() as s:
        q = (
            await s.execute(select(VendorQuestionnaire).where(VendorQuestionnaire.id == qid))
        ).scalar_one()
        assert q.status == "reviewed"
        assert q.score == 100.0
        vendor = (await s.execute(select(Vendor).where(Vendor.id == vid))).scalar_one()
        assert vendor.risk_rating == "low"
