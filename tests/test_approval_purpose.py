"""An approval authorizes the decision it was requested for, and no other.

One approval row per entity carried only a state, so an approval an ISSO
granted to close a remediated POA&M was equally spendable on extending its
risk acceptance, and a reviewer approving "POA&M #12" could not see which.
Each gate now names its decision (``approvals.consume(purpose=...)``) and
spends only an approval submitted and decided for it (migration 0112).
"""

from __future__ import annotations

import html
import os
import uuid
from collections.abc import Iterator
from datetime import date, timedelta

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance import approvals
from ccf.models import POAM, Approval, Organization, SSPProject, System, User

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture
def _auth_enabled() -> Iterator[None]:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


class W:
    sys_id: int
    owner_id: int
    org_id: int
    prep: dict[str, str]
    appr: dict[str, str]


async def _world() -> W:
    """A system, a preparer and an admin approver (who holds every authority)."""
    w, tag = W(), uuid.uuid4().hex[:8]
    async with session_scope() as s:
        org = Organization(name=f"purpose-{tag}")
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"purpose {tag}")
        s.add(sysm)
        users = {}
        for key, role in (("prep", "control_owner"), ("appr", "admin")):
            u = User(
                email=f"{key}-{tag}@purpose.example",
                organization_id=org.id,
                role=role,
                active=True,
                password_hash=hash_password("pw"),
                api_token=new_api_token(),
            )
            s.add(u)
            users[key] = u
        await s.flush()
        w.sys_id, w.org_id, w.owner_id = sysm.id, org.id, users["prep"].id
        w.prep = {"Authorization": f"Bearer {users['prep'].api_token}"}
        w.appr = {"Authorization": f"Bearer {users['appr'].api_token}"}
    return w


async def _approve(c: AsyncClient, w: W, kind: str, eid: int, purpose: str) -> dict:
    sub = await c.post(
        f"/api/approvals/{kind}/{eid}/submit", json={"purpose": purpose}, headers=w.prep
    )
    assert sub.status_code == 200, sub.text
    ok = await c.post(
        f"/api/approvals/{kind}/{eid}/approve", json={"purpose": purpose}, headers=w.appr
    )
    assert ok.status_code == 200, ok.text
    return ok.json()


async def _state(c: AsyncClient, w: W, kind: str, eid: int) -> str:
    return (await c.get(f"/api/approvals/{kind}/{eid}", headers=w.prep)).json()["state"]


async def _poam(c: AsyncClient, w: W) -> int:
    r = await c.post("/api/poams", json={"system_id": w.sys_id, "title": "W"}, headers=w.prep)
    return r.json()["id"]


def _accept(w: W, until: date) -> dict:
    return {
        "status": "risk_accepted",
        "owner_user_id": w.owner_id,
        "due_on": str(until),
        "acceptance_rationale": "Compensating control.",
    }


@pytest.mark.asyncio
async def test_a_closure_approval_cannot_accept_the_poams_risk(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        pid = await _poam(c, w)
        decided = await _approve(c, w, "poam", pid, "close")
        refused = await c.patch(
            f"/api/poams/{pid}", json=_accept(w, date.today() + timedelta(days=30)), headers=w.prep
        )
        left = await _state(c, w, "poam", pid)
    assert decided["purpose"] == "close" and decided["purpose_label"]
    assert refused.status_code == 409 and "accept_risk" in refused.json()["detail"]
    assert left == "approved"  # unspent: still good for what it was granted for


@pytest.mark.asyncio
async def test_an_acceptance_approval_cannot_extend_the_acceptance(_auth_enabled: None) -> None:
    w = await _world()
    until = date.today() + timedelta(days=30)
    async with _client() as c:
        pid = await _poam(c, w)
        await _approve(c, w, "poam", pid, "accept_risk")
        assert (
            await c.patch(f"/api/poams/{pid}", json=_accept(w, until), headers=w.prep)
        ).status_code == 200
        # An approval to *close* it is not an extension either.
        await _approve(c, w, "poam", pid, "close")
        later = {"due_on": str(until + timedelta(days=365))}
        refused = await c.patch(f"/api/poams/{pid}", json=later, headers=w.prep)
        await _approve(c, w, "poam", pid, "extend_acceptance")
        allowed = await c.patch(f"/api/poams/{pid}", json=later, headers=w.prep)
    assert refused.status_code == 409, refused.text
    assert allowed.status_code == 200, allowed.text


@pytest.mark.asyncio
async def test_a_review_extension_approval_cannot_accept_a_risk(_auth_enabled: None) -> None:
    w = await _world()
    accept = {
        "status": "accepted",
        "owner_user_id": w.owner_id,
        "next_review_on": str(date.today() + timedelta(days=90)),
    }
    async with _client() as c:
        rid = (
            await c.post("/api/risks", json={"system_id": w.sys_id, "title": "R"}, headers=w.prep)
        ).json()["id"]
        await _approve(c, w, "risk", rid, "extend_review")
        refused = await c.patch(f"/api/risks/{rid}", json=accept, headers=w.prep)
        await _approve(c, w, "risk", rid, "accept")
        allowed = await c.patch(f"/api/risks/{rid}", json=accept, headers=w.prep)
    assert refused.status_code == 409 and "'accept'" in refused.json()["detail"]
    assert allowed.status_code == 200, allowed.text


@pytest.mark.asyncio
async def test_an_approval_granted_before_purposes_authorizes_nothing(_auth_enabled: None) -> None:
    """Rows from before migration 0112 have no purpose: which decision they were
    granted for was never recorded, so no gate may assume it was its own."""
    w = await _world()
    async with _client() as c:
        pid = await _poam(c, w)
        mid = (
            await c.post(
                f"/api/poams/{pid}/milestones", json={"description": "fix"}, headers=w.prep
            )
        ).json()["id"]
        await c.patch(
            f"/api/poams/{pid}/milestones/{mid}", json={"status": "completed"}, headers=w.prep
        )
        async with session_scope() as s:
            s.add(
                Approval(
                    organization_id=w.org_id,
                    entity_type="poam",
                    entity_id=str(pid),
                    state="approved",
                    submitted_by="someone",
                    reviewed_by="someone else",
                )
            )
        refused = await c.post(f"/api/poams/{pid}/close", headers=w.prep)
    assert refused.status_code == 409, refused.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("kind", "body"),
    [
        ("poam", None),
        ("poam", {"purpose": "accept"}),  # a risk's purpose, not a POA&M's
        ("risk", {}),
        ("ssp_project", {"purpose": "close"}),  # one decision, nothing to name
    ],
    ids=["poam-none", "poam-wrong", "risk-none", "ssp-named"],
)
async def test_a_request_must_name_a_purpose_its_entity_has(
    _auth_enabled: None, kind: str, body: dict | None
) -> None:
    w = await _world()
    async with session_scope() as s:
        if kind == "ssp_project":
            row = SSPProject(organization_id=w.org_id, customer_name="SSP")
        elif kind == "risk":
            from ccf.models import Risk  # noqa: PLC0415

            row = Risk(system_id=w.sys_id, title="R")
        else:
            row = POAM(system_id=w.sys_id, title="W")
        s.add(row)
        await s.flush()
        eid = row.id
    async with _client() as c:
        r = await c.post(f"/api/approvals/{kind}/{eid}/submit", json=body, headers=w.prep)
        state = await _state(c, w, kind, eid)
    assert r.status_code == 422, r.text
    assert state == "draft"


@pytest.mark.asyncio
async def test_a_gate_that_names_no_purpose_is_a_programming_error() -> None:
    """A POA&M or risk gate that forgot its purpose would spend any approval."""
    async with session_scope() as s:
        with pytest.raises(ValueError, match="must name its purpose"):
            await approvals.consume(s, entity_type="poam", entity_id=1, actor="a")
        with pytest.raises(ValueError, match="must name its purpose"):
            await approvals.consume(s, entity_type="risk", entity_id=1, actor="a", purpose="close")


@pytest.mark.asyncio
async def test_the_reviewer_sees_what_they_are_asked_to_authorize(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        accept_id, close_id = await _poam(c, w), await _poam(c, w)
        for pid, purpose in ((accept_id, "accept_risk"), (close_id, "close")):
            r = await c.post(
                f"/api/approvals/poam/{pid}/submit", json={"purpose": purpose}, headers=w.prep
            )
            assert r.status_code == 200, r.text
        workspace = await c.get(f"/ato/{w.sys_id}", headers=w.appr)
        listing = await c.get("/approvals", headers=w.appr)
    assert workspace.status_code == 200, workspace.text[:300]
    for label in (approvals.PURPOSES["poam"]["accept_risk"], approvals.PURPOSES["poam"]["close"]):
        assert html.escape(label) in workspace.text
        assert html.escape(label) in listing.text


@pytest.mark.asyncio
async def test_an_approval_read_off_a_stale_page_is_refused(_auth_enabled: None) -> None:
    """The submitter may re-submit for another purpose while a request awaits
    review. A reviewer who read "close" and pressed Approve must not authorize
    the extension asked for since: the approval names what it approves."""
    w = await _world()
    async with _client() as c:
        pid = await _poam(c, w)
        for purpose in ("close", "extend_acceptance"):
            r = await c.post(
                f"/api/approvals/poam/{pid}/submit", json={"purpose": purpose}, headers=w.prep
            )
            assert r.status_code == 200, r.text
        stale = await c.post(
            f"/api/approvals/poam/{pid}/approve", json={"purpose": "close"}, headers=w.appr
        )
        unnamed = await c.post(f"/api/approvals/poam/{pid}/approve", json={}, headers=w.appr)
        still = await _state(c, w, "poam", pid)
        # From the workspace page: its form carries the purpose it showed.
        form = await c.post(
            f"/ato/{w.sys_id}/approvals/poam/{pid}/approve",
            data={"purpose": "close", "note": ""},
            headers=w.appr,
            follow_redirects=False,
        )
        after_form = await _state(c, w, "poam", pid)
        # Rejecting grants nothing, so it needs no purpose.
        rejected = await c.post(f"/api/approvals/poam/{pid}/reject", json={}, headers=w.appr)
    assert stale.status_code == 409 and "Extend the risk acceptance" in stale.json()["detail"]
    assert unnamed.status_code == 409
    assert still == "submitted"
    assert form.status_code == 303 and after_form == "submitted"
    assert rejected.status_code == 200 and rejected.json()["state"] == "rejected"


@pytest.mark.asyncio
async def test_the_workspace_form_approves_what_it_showed(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        pid = await _poam(c, w)
        await c.post(f"/api/approvals/poam/{pid}/submit", json={"purpose": "close"}, headers=w.prep)
        page = await c.get(f"/ato/{w.sys_id}", headers=w.appr)
        form = await c.post(
            f"/ato/{w.sys_id}/approvals/poam/{pid}/approve",
            data={"purpose": "close", "note": ""},
            headers=w.appr,
            follow_redirects=False,
        )
        state = await _state(c, w, "poam", pid)
    assert 'name="purpose" value="close"' in page.text
    assert form.status_code == 303 and state == "approved"


@pytest.mark.asyncio
async def test_a_resubmission_in_flight_cannot_be_approved_unseen() -> None:
    """Stages the race: a re-submission for another purpose holds the row,
    uncommitted, when a decision for the old purpose starts. The decision
    must wait for it and then refuse -- not read the old purpose, pass, and
    write "approved" over the new request once the lock is released."""
    import asyncio  # noqa: PLC0415

    w = await _world()
    async with session_scope() as s:
        poam = POAM(system_id=w.sys_id, title="W")
        s.add(poam)
        await s.flush()
        pid = str(poam.id)
        await approvals.submit(s, entity_type="poam", entity_id=pid, actor="p", purpose="close")

    resubmitting = session_scope()
    s1 = await resubmitting.__aenter__()
    try:
        await approvals.submit(
            s1, entity_type="poam", entity_id=pid, actor="p", purpose="extend_acceptance"
        )

        async def decide_as_close() -> None:
            async with session_scope() as s2:
                await approvals.decide(
                    s2,
                    entity_type="poam",
                    entity_id=pid,
                    approve=True,
                    actor="r",
                    role="admin",
                    purpose="close",
                )

        decision = asyncio.create_task(decide_as_close())
        await asyncio.sleep(0.5)
        assert not decision.done(), "the decision must wait on the re-submission's lock"
    finally:
        await resubmitting.__aexit__(None, None, None)
    with pytest.raises(approvals.PurposeChangedError):
        await decision
    async with session_scope() as s:
        row = (
            await s.execute(
                select(Approval).where(Approval.entity_type == "poam", Approval.entity_id == pid)
            )
        ).scalar_one()
    assert (row.state, row.purpose) == ("submitted", "extend_acceptance")


async def _approval(pid: int, kind: str = "poam") -> Approval | None:
    async with session_scope() as s:
        return (
            await s.execute(
                select(Approval).where(Approval.entity_type == kind, Approval.entity_id == str(pid))
            )
        ).scalar_one_or_none()


@pytest.mark.asyncio
async def test_a_decision_can_be_requested_from_the_workspace(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        pid = await _poam(c, w)
        page = await c.get(f"/ato/{w.sys_id}", headers=w.prep)
        r = await c.post(
            f"/ato/{w.sys_id}/approvals/request",
            data={"item": f"poam:{pid}", "purpose": "close"},
            headers=w.prep,
            follow_redirects=False,
        )
        after = await c.get(f"/ato/{w.sys_id}", headers=w.appr)
    assert 'action="/ato/' in page.text and f'value="poam:{pid}"' in page.text
    assert r.status_code == 303 and "error" not in r.headers["location"]
    row = await _approval(pid)
    assert row is not None and (row.state, row.purpose) == ("submitted", "close")
    assert row.submitted_by and row.submitted_by.startswith("prep-")
    assert html.escape(approvals.PURPOSES["poam"]["close"]) in after.text


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["wrong-kind-purpose", "other-system", "garbage"])
async def test_the_workspace_refuses_a_request_it_cannot_make(
    _auth_enabled: None, case: str
) -> None:
    w = await _world()
    async with session_scope() as s:
        other = System(organization_id=w.org_id, name="another system")
        s.add(other)
        await s.flush()
        foreign = POAM(system_id=other.id, title="not this system's")
        s.add(foreign)
        await s.flush()
        foreign_id = foreign.id
    async with _client() as c:
        pid = await _poam(c, w)
        item, purpose, probe = {
            "wrong-kind-purpose": (f"poam:{pid}", "accept", pid),  # a risk's purpose
            "other-system": (f"poam:{foreign_id}", "close", foreign_id),
            "garbage": ("vendor:1", "close", pid),
        }[case]
        r = await c.post(
            f"/ato/{w.sys_id}/approvals/request",
            data={"item": item, "purpose": purpose},
            headers=w.prep,
            follow_redirects=False,
        )
    assert r.status_code == 303 and "error=" in r.headers["location"]
    row = await _approval(probe)
    assert row is None or row.state != "submitted"
