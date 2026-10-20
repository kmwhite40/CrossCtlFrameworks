"""An approval authorizes one decision, then it is spent.

There is one ``Approval`` row per entity and nothing ever reset it. Once a
POA&M or risk was approved, every later gated transition on it passed on that
same approval: close it, reopen it, close it again; accept a risk, reopen it,
rescore it, accept it again. The reviewer made one decision, and the platform
recorded several in their name. ``submit`` also refused an approved entity
outright, so a fresh review could never be requested.

A gate that relies on an approval now consumes it, and the entity can be
submitted again. Moving a risk_accepted POA&M's expiry (``due_on``) later also
needs a fresh approval. The scanner keeps an acceptance only until ``due_on``,
so an expiry an author could push out freely was an acceptance with no end.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Iterator
from datetime import date, timedelta

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance import approvals
from ccf.models import Approval, Organization, System, User

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


async def _org_with_people(name: str) -> tuple[int, int, int, dict, dict]:
    """A system, an owner id, and auth headers for a preparer and an approver."""
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"{name} system")
        s.add(sysm)
        people = {}
        for key, role in (("prep", "control_owner"), ("appr", "admin")):
            u = User(
                email=f"{key}@{name.lower()}.example",
                organization_id=org.id,
                role=role,
                active=True,
                password_hash=hash_password("pw"),
                api_token=new_api_token(),
            )
            s.add(u)
            people[key] = u
        await s.flush()
        return (
            sysm.id,
            people["prep"].id,
            org.id,
            {"Authorization": f"Bearer {people['prep'].api_token}"},
            {"Authorization": f"Bearer {people['appr'].api_token}"},
        )


async def _approve(c: AsyncClient, kind: str, eid: int, prep: dict, appr: dict) -> None:
    sub = await c.post(f"/api/approvals/{kind}/{eid}/submit", headers=prep)
    assert sub.status_code == 200, sub.text
    ok = await c.post(f"/api/approvals/{kind}/{eid}/approve", headers=appr)
    assert ok.status_code == 200, ok.text


async def _closable_poam(c: AsyncClient, sys_id: int, prep: dict) -> int:
    pid = (
        await c.post("/api/poams", json={"system_id": sys_id, "title": "W"}, headers=prep)
    ).json()["id"]
    mid = (
        await c.post(f"/api/poams/{pid}/milestones", json={"description": "fix"}, headers=prep)
    ).json()["id"]
    await c.patch(f"/api/poams/{pid}/milestones/{mid}", json={"status": "completed"}, headers=prep)
    return pid


@pytest.mark.asyncio
async def test_a_closure_approval_does_not_close_the_poam_twice(_auth_enabled: None) -> None:
    sys_id, _owner, _org, prep, appr = await _org_with_people("SingleUseOrgA")
    async with _client() as c:
        pid = await _closable_poam(c, sys_id, prep)
        await _approve(c, "poam", pid, prep, appr)
        assert (await c.post(f"/api/poams/{pid}/close", headers=prep)).status_code == 200

        reopened = await c.patch(f"/api/poams/{pid}", json={"status": "open"}, headers=prep)
        assert reopened.status_code == 200, reopened.text
        again = await c.post(f"/api/poams/{pid}/close", headers=prep)
        assert again.status_code == 409, again.text


@pytest.mark.asyncio
async def test_a_spent_approval_can_be_requested_again(_auth_enabled: None) -> None:
    sys_id, _owner, _org, prep, appr = await _org_with_people("SingleUseOrgB")
    async with _client() as c:
        pid = await _closable_poam(c, sys_id, prep)
        await _approve(c, "poam", pid, prep, appr)
        assert (await c.post(f"/api/poams/{pid}/close", headers=prep)).status_code == 200
        await c.patch(f"/api/poams/{pid}", json={"status": "open"}, headers=prep)

        await _approve(c, "poam", pid, prep, appr)
        assert (await c.post(f"/api/poams/{pid}/close", headers=prep)).status_code == 200


@pytest.mark.asyncio
async def test_a_risk_acceptance_approval_does_not_accept_twice(_auth_enabled: None) -> None:
    sys_id, owner_id, _org, prep, appr = await _org_with_people("SingleUseOrgC")
    accept = {
        "status": "accepted",
        "owner_user_id": owner_id,
        "next_review_on": str(date.today() + timedelta(days=90)),
    }
    async with _client() as c:
        rid = (
            await c.post("/api/risks", json={"system_id": sys_id, "title": "R"}, headers=prep)
        ).json()["id"]
        await _approve(c, "risk", rid, prep, appr)
        assert (await c.patch(f"/api/risks/{rid}", json=accept, headers=prep)).status_code == 200

        await c.patch(f"/api/risks/{rid}", json={"status": "open"}, headers=prep)
        again = await c.patch(f"/api/risks/{rid}", json=accept, headers=prep)
        assert again.status_code == 409, again.text


@pytest.mark.asyncio
async def test_extending_an_accepted_poams_expiry_needs_a_fresh_approval(
    _auth_enabled: None,
) -> None:
    sys_id, owner_id, _org, prep, appr = await _org_with_people("SingleUseOrgD")
    expires = date.today() + timedelta(days=30)
    async with _client() as c:
        pid = (
            await c.post("/api/poams", json={"system_id": sys_id, "title": "W"}, headers=prep)
        ).json()["id"]
        await _approve(c, "poam", pid, prep, appr)
        accepted = await c.patch(
            f"/api/poams/{pid}",
            json={
                "status": "risk_accepted",
                "owner_user_id": owner_id,
                "due_on": str(expires),
                "acceptance_rationale": "Compensating control.",
            },
            headers=prep,
        )
        assert accepted.status_code == 200, accepted.text

        later = str(expires + timedelta(days=365))
        refused = await c.patch(f"/api/poams/{pid}", json={"due_on": later}, headers=prep)
        assert refused.status_code == 409, refused.text
        assert (await c.get(f"/api/poams/{pid}", headers=prep)).json()["due_on"] == str(expires)

        # Shortening an acceptance asks nobody's permission, and a reviewer
        # can still approve an extension.
        sooner = str(expires - timedelta(days=10))
        assert (
            await c.patch(f"/api/poams/{pid}", json={"due_on": sooner}, headers=prep)
        ).status_code == 200
        await _approve(c, "poam", pid, prep, appr)
        assert (
            await c.patch(f"/api/poams/{pid}", json={"due_on": later}, headers=prep)
        ).status_code == 200


@pytest.mark.asyncio
async def test_resaving_an_accepted_risk_needs_no_second_approval(_auth_enabled: None) -> None:
    """A whole-form client re-sends status on every save. Once the approval is
    spent on the acceptance, that re-save must not be refused for want of one."""
    sys_id, owner_id, _org, prep, appr = await _org_with_people("SingleUseOrgE")
    accept = {
        "status": "accepted",
        "owner_user_id": owner_id,
        "next_review_on": str(date.today() + timedelta(days=90)),
    }
    async with _client() as c:
        rid = (
            await c.post("/api/risks", json={"system_id": sys_id, "title": "R"}, headers=prep)
        ).json()["id"]
        await _approve(c, "risk", rid, prep, appr)
        assert (await c.patch(f"/api/risks/{rid}", json=accept, headers=prep)).status_code == 200
        resave = await c.patch(
            f"/api/risks/{rid}", json={**accept, "title": "R, renamed"}, headers=prep
        )
        assert resave.status_code == 200, resave.text


@pytest.mark.asyncio
async def test_resaving_a_closed_poam_needs_no_second_approval(_auth_enabled: None) -> None:
    sys_id, _owner, _org, prep, appr = await _org_with_people("SingleUseOrgF")
    async with _client() as c:
        pid = await _closable_poam(c, sys_id, prep)
        await _approve(c, "poam", pid, prep, appr)
        assert (await c.post(f"/api/poams/{pid}/close", headers=prep)).status_code == 200
        resave = await c.patch(
            f"/api/poams/{pid}", json={"status": "closed", "title": "W, renamed"}, headers=prep
        )
        assert resave.status_code == 200, resave.text
        again = await c.post(f"/api/poams/{pid}/close", headers=prep)
        assert again.status_code == 200, again.text


@pytest.mark.asyncio
async def test_two_concurrent_spends_of_one_approval_succeed_once() -> None:
    """A read-then-write spend let two concurrent requests both see "approved"
    and both pass their gate on one review. The spend is one conditional
    UPDATE, so the second waits on the row lock, re-reads, and finds nothing.

    Measured limit: this catches a read-then-write spend only when the event
    loop switches between its read and its write; with no await in that gap the
    two sessions happened to serialize and the mutant passed. The guarantee is
    the conditional UPDATE itself, not this test."""
    _sys, _owner, org_id, _prep, _appr = await _org_with_people("SingleUseOrgRace")
    async with session_scope() as s:
        s.add(
            Approval(
                organization_id=org_id,
                entity_type="poam",
                entity_id="race-1",
                state="approved",
                reviewed_by="appr@race.example",
            )
        )

    async def spend() -> bool:
        async with session_scope() as s:
            return await approvals.consume(
                s, entity_type="poam", entity_id="race-1", actor="prep@race.example"
            )

    results = await asyncio.gather(spend(), spend())
    assert sorted(results) == [False, True]


@pytest.mark.asyncio
async def test_extending_an_accepted_risks_review_date_needs_a_fresh_approval(
    _auth_enabled: None,
) -> None:
    """The risk-register sibling of the POA&M expiry rule: next_review_on is when
    an accepted risk must be looked at again, so pushing it out is a new
    acceptance decision."""
    sys_id, owner_id, _org, prep, appr = await _org_with_people("SingleUseOrgG")
    review = date.today() + timedelta(days=90)
    async with _client() as c:
        rid = (
            await c.post("/api/risks", json={"system_id": sys_id, "title": "R"}, headers=prep)
        ).json()["id"]
        await _approve(c, "risk", rid, prep, appr)
        accepted = await c.patch(
            f"/api/risks/{rid}",
            json={"status": "accepted", "owner_user_id": owner_id, "next_review_on": str(review)},
            headers=prep,
        )
        assert accepted.status_code == 200, accepted.text

        later = str(review + timedelta(days=365))
        refused = await c.patch(f"/api/risks/{rid}", json={"next_review_on": later}, headers=prep)
        assert refused.status_code == 409, refused.text

        sooner = str(review - timedelta(days=10))
        assert (
            await c.patch(f"/api/risks/{rid}", json={"next_review_on": sooner}, headers=prep)
        ).status_code == 200
        await _approve(c, "risk", rid, prep, appr)
        assert (
            await c.patch(f"/api/risks/{rid}", json={"next_review_on": later}, headers=prep)
        ).status_code == 200
