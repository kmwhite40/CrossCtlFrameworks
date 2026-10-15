"""Marking a notification read changes only the caller's inbox.

``notifications.read_at`` was one column on an org-wide broadcast row: any
member's "read all" silenced every member's alerts, and re-notification never
cleared it. Found by independent review of the viewer gate (764e87e).
"""

from __future__ import annotations

import itertools
import os
from collections.abc import Iterator

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Notification, Organization, User

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture
def auth_on() -> Iterator[None]:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


async def _org_with_two_members() -> tuple[int, tuple[int, str], tuple[int, str]]:
    async with session_scope() as s:
        org = Organization(name=f"Inbox Org {next(_SEQ)}")
        s.add(org)
        await s.flush()
        members = []
        for who in ("alice", "bob"):
            u = User(
                email=f"{who}-{next(_SEQ)}@inbox.test",
                organization_id=org.id,
                role="control_owner",
                active=True,
                password_hash=hash_password("pw"),
                api_token=new_api_token(),
            )
            s.add(u)
            await s.flush()
            members.append((u.id, u.api_token))
        return org.id, members[0], members[1]


async def _notify(org_id: int, title: str, user_id: int | None = None) -> int:
    async with session_scope() as s:
        n = Notification(
            organization_id=org_id,
            user_id=user_id,
            category="test",
            title=title,
            severity="warning",
        )
        s.add(n)
        await s.flush()
        return n.id


def _client(token: str) -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(app=create_app()),
        base_url="http://t",
        headers={"Authorization": f"Bearer {token}"},
    )


async def _inbox(token: str) -> dict:
    async with _client(token) as c:
        r = await c.get("/api/notifications")
        assert r.status_code == 200, r.text
        return r.json()


@pytest.mark.usefixtures("auth_on")
async def test_read_all_leaves_another_members_alerts_unread() -> None:
    org, (_a_id, alice), (_b_id, bob) = await _org_with_two_members()
    await _notify(org, "ATO expires in 30 days")
    await _notify(org, "Access review overdue")
    async with _client(alice) as c:
        r = await c.post("/api/notifications/read-all")
        assert r.json() == {"marked_read": 2}
    assert (await _inbox(alice))["unread"] == 0
    assert (await _inbox(bob))["unread"] == 2  # Alice silenced nothing for Bob
    async with _client(alice) as c:  # idempotent
        assert (await c.post("/api/notifications/read-all")).json() == {"marked_read": 0}


@pytest.mark.usefixtures("auth_on")
async def test_marking_one_read_is_per_user() -> None:
    org, _alice, (_b_id, bob) = await _org_with_two_members()
    nid = await _notify(org, "Overdue task")
    async with _client(bob) as c:
        r = await c.post(f"/api/notifications/{nid}/read")
        assert r.status_code == 200 and r.json()["read"] is True
    bob_items = {i["id"]: i for i in (await _inbox(bob))["items"]}
    alice_items = {i["id"]: i for i in (await _inbox(_alice[1]))["items"]}
    assert bob_items[nid]["read"] is True and alice_items[nid]["read"] is False
    async with _client(_alice[1]) as c:
        listed = (await c.get("/api/notifications?unread_only=true")).json()
    assert nid in {i["id"] for i in listed["items"]}


@pytest.mark.usefixtures("auth_on")
async def test_a_notification_addressed_to_one_member_is_not_shown_to_another() -> None:
    org, (a_id, alice), (_b_id, bob) = await _org_with_two_members()
    mine = await _notify(org, "For Alice only", user_id=a_id)
    assert mine in {i["id"] for i in (await _inbox(alice))["items"]}
    assert mine not in {i["id"] for i in (await _inbox(bob))["items"]}
    async with _client(bob) as c:
        assert (await c.post(f"/api/notifications/{mine}/read")).status_code == 404


@pytest.mark.usefixtures("auth_on")
async def test_the_governance_page_counts_the_callers_unread() -> None:
    org, (_a_id, alice), (_b_id, bob) = await _org_with_two_members()
    await _notify(org, "One")
    async with _client(alice) as c:
        await c.post("/api/notifications/read-all")
        alice_page = (await c.get("/governance")).text
    async with _client(bob) as c:
        bob_page = (await c.get("/governance")).text
    assert "0 unread" in alice_page
    assert "1 unread" in bob_page


async def test_without_auth_the_system_principal_keeps_the_org_column() -> None:
    org, _a, _b = await _org_with_two_members()
    nid = await _notify(org, "System inbox")
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        await c.post(f"/api/notifications/{nid}/read")
    async with session_scope() as s:
        n = await s.get(Notification, nid)
        assert n is not None and n.read_at is not None


@pytest.mark.usefixtures("auth_on")
async def test_unread_counts_the_whole_inbox_not_the_page() -> None:
    org, (_a, alice), _b = await _org_with_two_members()
    for i in range(30):
        await _notify(org, f"n{i}")
    async with _client(alice) as c:
        body = (await c.get("/api/notifications?limit=10")).json()
    assert len(body["items"]) == 10 and body["unread"] == 30


@pytest.mark.usefixtures("auth_on")
async def test_read_all_survives_a_backlog_past_the_parameter_limit() -> None:
    from sqlalchemy import text  # noqa: PLC0415

    org, (_a, alice), _b = await _org_with_two_members()
    async with session_scope() as s:
        await s.execute(
            text(
                "INSERT INTO ccf.notifications (organization_id, category, title, severity) "
                "SELECT :org, 'bulk', 'n' || g, 'info' FROM generate_series(1, 11000) g"
            ),
            {"org": org},
        )
    async with _client(alice) as c:
        r = await c.post("/api/notifications/read-all")
    assert r.status_code == 200 and r.json()["marked_read"] == 11000


async def test_an_escalated_alert_comes_back_for_everyone() -> None:
    from ccf.auth import Principal  # noqa: PLC0415
    from ccf.governance import bus, inbox  # noqa: PLC0415

    org, (a_id, _alice), _b = await _org_with_two_members()
    key = f"escalate-{next(_SEQ)}"
    who = Principal(user_id=a_id, email="a@t", org_id=org, role="control_owner")
    async with session_scope() as s:
        n = await bus.notify(
            s, category="t", title="ATO in 30 days", org_id=org, severity="warning", dedupe_key=key
        )
        assert n is not None
        await inbox.mark_read(s, who, [n])
    async with session_scope() as s:
        same = await bus.notify(
            s, category="t", title="ATO in 29 days", org_id=org, severity="warning", dedupe_key=key
        )
        assert same is not None
        assert await inbox.read_ids(s, who, [same]) == {same.id}  # same severity: stays read
    async with session_scope() as s:
        worse = await bus.notify(
            s, category="t", title="ATO expired", org_id=org, severity="critical", dedupe_key=key
        )
        assert worse is not None
        assert await inbox.read_ids(s, who, [worse]) == set()  # escalated: unread again
