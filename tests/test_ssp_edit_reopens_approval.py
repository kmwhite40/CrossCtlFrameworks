"""Changing an approved SSP's content sends it back for review.

The approval was of the text the reviewer read. Editing a control statement,
adding or removing an entry, or changing the plan's own content afterwards
left it ``approved``, so the package carried text nobody had approved. A
trigger (migration 0113) returns the plan -- and its approval -- to draft on
any content change, from any writer: the editor's routes, statement
generation, autofill, templates and the UI's forms alike.

Not content: the status itself, timestamps, the entries' order, and the
revision log (``version`` / ``revision_history``), which records the plan's
history rather than changing what it says.
"""

from __future__ import annotations

import uuid

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select, update

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Approval, Organization, SSPControlEntry, SSPProject

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _approved_plan() -> tuple[int, int]:
    """An approved plan with two entries. Returns (project id, an entry id)."""
    tag = uuid.uuid4().hex[:8]
    async with session_scope() as s:
        org = Organization(name=f"sspre-{tag}")
        s.add(org)
        await s.flush()
        proj = SSPProject(organization_id=org.id, customer_name=f"cust {tag}")
        s.add(proj)
        await s.flush()
        first = SSPControlEntry(
            project_id=proj.id, control_id="AC-2", part_narratives=[{"text": "approved text"}]
        )
        s.add_all([first, SSPControlEntry(project_id=proj.id, control_id="AC-3")])
        await s.flush()
        pid, eid = proj.id, first.id
    async with _client() as c:
        assert (await c.post(f"/api/approvals/ssp_project/{pid}/submit")).status_code == 200
        r = await c.post(f"/api/approvals/ssp_project/{pid}/approve", json={})
        assert r.status_code == 200, r.text
    assert await _states(pid) == ("approved", "approved")
    return pid, eid


async def _states(pid: int) -> tuple[str, str]:
    """(plan status, approval state)."""
    async with session_scope() as s:
        status = (
            await s.execute(select(SSPProject.status).where(SSPProject.id == pid))
        ).scalar_one()
        approval = (
            await s.execute(
                select(Approval.state).where(
                    Approval.entity_type == "ssp_project", Approval.entity_id == str(pid)
                )
            )
        ).scalar_one()
    return status, approval


@pytest.mark.asyncio
async def test_editing_a_control_statement_reopens_the_plan() -> None:
    pid, _ = await _approved_plan()
    async with _client() as c:
        r = await c.put(
            f"/api/ssp/projects/{pid}/entries/AC-2",
            json={"part_narratives": [{"text": "something nobody approved"}]},
        )
        assert r.status_code == 200, r.text
        again = await c.post(f"/api/approvals/ssp_project/{pid}/submit")
    assert again.status_code == 200, again.text  # it can be put back for review


@pytest.mark.asyncio
async def test_each_kind_of_content_change_reopens_it() -> None:
    changes = {
        "entry updated": lambda pid, eid: (
            update(SSPControlEntry)
            .where(SSPControlEntry.id == eid)
            .values(responsible_role="someone else")
        ),
        "entry added": lambda pid, eid: SSPControlEntry.__table__.insert().values(
            project_id=pid, control_id="AC-4"
        ),
        "entry removed": lambda pid, eid: delete(SSPControlEntry).where(SSPControlEntry.id == eid),
        "plan content": lambda pid, eid: (
            update(SSPProject).where(SSPProject.id == pid).values(system_name="renamed system")
        ),
    }
    for name, stmt in changes.items():
        pid, eid = await _approved_plan()
        async with session_scope() as s:
            await s.execute(stmt(pid, eid))
        assert await _states(pid) == ("draft", "draft"), name


@pytest.mark.asyncio
async def test_what_is_not_content_leaves_it_approved() -> None:
    pid, eid = await _approved_plan()
    async with _client() as c:
        # A whole-form client re-sends what it was given.
        resend = await c.patch(f"/api/ssp/projects/{pid}", json={"status": "approved"})
        same = await c.put(
            f"/api/ssp/projects/{pid}/entries/AC-2",
            json={"part_narratives": [{"text": "approved text"}]},
        )
        # The revision log records the approval; it does not change the text.
        rev = await c.post(
            f"/api/ssp/projects/{pid}/revisions", json={"version": "1.0", "notes": "Approved"}
        )
    assert (resend.status_code, same.status_code, rev.status_code) == (200, 200, 201)
    async with session_scope() as s:
        await s.execute(
            update(SSPControlEntry).where(SSPControlEntry.id == eid).values(sort_order=99)
        )
    assert await _states(pid) == ("approved", "approved")


@pytest.mark.asyncio
async def test_another_plans_edit_leaves_this_one_alone() -> None:
    pid, _ = await _approved_plan()
    other, other_entry = await _approved_plan()
    async with session_scope() as s:
        await s.execute(
            update(SSPControlEntry)
            .where(SSPControlEntry.id == other_entry)
            .values(responsible_role="changed")
        )
    assert await _states(pid) == ("approved", "approved")
    assert await _states(other) == ("draft", "draft")


@pytest.mark.asyncio
async def test_a_draft_plan_is_edited_freely() -> None:
    tag = uuid.uuid4().hex[:8]
    async with session_scope() as s:
        org = Organization(name=f"sspd-{tag}")
        s.add(org)
        await s.flush()
        proj = SSPProject(organization_id=org.id, customer_name=f"cust {tag}", status="in_review")
        s.add(proj)
        await s.flush()
        s.add(SSPControlEntry(project_id=proj.id, control_id="AC-2"))
        await s.flush()
        pid = proj.id
    async with session_scope() as s:
        await s.execute(
            update(SSPControlEntry)
            .where(SSPControlEntry.project_id == pid)
            .values(responsible_role="x")
        )
        status = (
            await s.execute(select(SSPProject.status).where(SSPProject.id == pid))
        ).scalar_one()
    assert status == "in_review"


@pytest.mark.asyncio
async def test_an_approved_plan_can_still_be_deleted() -> None:
    """Deleting the plan cascades to its entries, whose trigger then updates a
    plan already being deleted: that must not fail the delete."""
    pid, _ = await _approved_plan()
    async with _client() as c:
        r = await c.delete(f"/api/ssp/projects/{pid}")
    assert r.status_code == 204, r.text
    async with session_scope() as s:
        await s.execute(delete(SSPProject).where(SSPProject.id == pid))
        gone = (
            await s.execute(select(SSPProject.id).where(SSPProject.id == pid))
        ).scalar_one_or_none()
    assert gone is None
