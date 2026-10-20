"""An SSP reaches a terminal status only through the approval workflow.

``approvals.decide`` sets ``SSPProject.status = "approved"`` behind the
separation-of-duties check. But ``PATCH /api/ssp/projects/{id}`` accepted any
``status`` string from an author, and the UI metadata form offered ``final``,
so an author could mark their own SSP approved or final with no reviewer.

The form also had no ``approved`` option. An approved project rendered with no
option selected, so the browser submitted the first one, ``draft``, and saving
the customer name silently threw the approval away.
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, SSPProject

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _make_project(name: str, status: str = "draft") -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        proj = SSPProject(organization_id=org.id, customer_name=f"{name} customer", status=status)
        s.add(proj)
        await s.flush()
        return proj.id


async def _status(pid: int) -> str:
    async with session_scope() as s:
        proj = await s.get(SSPProject, pid)
        assert proj is not None
        return proj.status


@pytest.mark.asyncio
@pytest.mark.parametrize("terminal", ["approved", "final"])
async def test_patch_cannot_set_a_terminal_status(terminal: str) -> None:
    pid = await _make_project(f"SspStatusOrg-patch-{terminal}")
    async with _client() as c:
        r = await c.patch(f"/api/ssp/projects/{pid}", json={"status": terminal})
        assert r.status_code == 422, r.text
    assert await _status(pid) == "draft"


@pytest.mark.asyncio
async def test_patch_can_move_a_draft_into_review() -> None:
    pid = await _make_project("SspStatusOrg-review")
    async with _client() as c:
        r = await c.patch(f"/api/ssp/projects/{pid}", json={"status": "in_review"})
        assert r.status_code == 200, r.text
    assert await _status(pid) == "in_review"


@pytest.mark.asyncio
async def test_the_metadata_form_cannot_set_final() -> None:
    pid = await _make_project("SspStatusOrg-form-final")
    async with _client() as c:
        r = await c.post(f"/ssp/{pid}/meta", data={"customer_name": "C", "status": "final"})
        assert r.status_code in (303, 422), r.text
    assert await _status(pid) == "draft"


@pytest.mark.asyncio
async def test_saving_metadata_keeps_an_approval() -> None:
    pid = await _make_project("SspStatusOrg-keep")
    async with _client() as c:
        assert (await c.post(f"/api/approvals/ssp_project/{pid}/submit")).status_code == 200
        assert (
            await c.post(f"/api/approvals/ssp_project/{pid}/approve", json={})
        ).status_code == 200
        assert await _status(pid) == "approved"

        # What the browser sends when no <option> matches: the first one.
        r = await c.post(f"/ssp/{pid}/meta", data={"customer_name": "Renamed", "status": "draft"})
        assert r.status_code == 303, r.text
    assert await _status(pid) == "approved"


@pytest.mark.asyncio
async def test_the_form_renders_the_current_status_selected() -> None:
    pid = await _make_project("SspStatusOrg-render", status="approved")
    async with _client() as c:
        page = await c.get(f"/ssp/{pid}")
        assert page.status_code == 200, page.text
        # The approval is shown, and nothing offers to post it back as draft.
        assert "approved" in page.text
        assert 'name="status"' not in page.text
