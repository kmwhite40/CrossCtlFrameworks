"""Waiver endpoints: request, approve, revoke -- and the audit trail."""

from __future__ import annotations

import itertools

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.db import session_scope
from ccf.governance.waivers import can_approve
from ccf.models import AuditLog, Organization, System
from ccf.models_waivers import Waiver

_SEQ = itertools.count()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://test")


async def _system() -> int:
    async with session_scope() as session:
        org = Organization(name=f"WaiverApiOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"WaiverApiSys-{next(_SEQ)}")
        session.add(sys_)
        await session.flush()
        return sys_.id


def _body(system_id: int, **kw) -> dict:
    base = {
        "system_id": system_id,
        "check_key": "m365.identity.mfa_registered",
        "rationale": "Break-glass account exempt by design; compensating control in place.",
    }
    base.update(kw)
    return base


@pytest.mark.asyncio
async def test_openapi_lists_the_waiver_routes() -> None:
    async with _client() as client:
        paths = (await client.get("/openapi.json")).json()["paths"]
        assert "/api/waivers" in paths
        assert "/api/waivers/{waiver_id}/approve" in paths
        assert "/api/waivers/{waiver_id}/revoke" in paths


@pytest.mark.asyncio
async def test_a_new_waiver_is_requested_not_approved() -> None:
    """It must not arrive in force."""
    system_id = await _system()
    async with _client() as client:
        created = await client.post("/api/waivers", json=_body(system_id))
        assert created.status_code == 201, created.text
        assert created.json()["status"] == "requested"
        assert created.json()["approved_at"] is None


@pytest.mark.asyncio
async def test_approve_records_who_and_when() -> None:
    system_id = await _system()
    async with _client() as client:
        wid = (await client.post("/api/waivers", json=_body(system_id))).json()["id"]
        approved = await client.post(f"/api/waivers/{wid}/approve")
        assert approved.status_code == 200, approved.text
        body = approved.json()
        assert body["status"] == "approved"
        assert body["approved_by"]
        assert body["approved_at"] is not None


@pytest.mark.asyncio
async def test_revoke_stops_a_waiver() -> None:
    system_id = await _system()
    async with _client() as client:
        wid = (await client.post("/api/waivers", json=_body(system_id))).json()["id"]
        await client.post(f"/api/waivers/{wid}/approve")
        revoked = await client.post(f"/api/waivers/{wid}/revoke")
        assert revoked.status_code == 200
        assert revoked.json()["status"] == "revoked"


@pytest.mark.asyncio
async def test_a_revoked_waiver_cannot_be_re_approved() -> None:
    """Revocation is terminal -- re-approving would resurrect an acceptance
    someone deliberately withdrew, with no new decision recorded."""
    system_id = await _system()
    async with _client() as client:
        wid = (await client.post("/api/waivers", json=_body(system_id))).json()["id"]
        await client.post(f"/api/waivers/{wid}/revoke")
        again = await client.post(f"/api/waivers/{wid}/approve")
        assert again.status_code == 409, again.text


@pytest.mark.asyncio
async def test_listing_filters_by_system_and_check() -> None:
    system_id = await _system()
    other_system = await _system()
    async with _client() as client:
        await client.post("/api/waivers", json=_body(system_id))
        await client.post("/api/waivers", json=_body(other_system))
        mine = await client.get("/api/waivers", params={"system_id": system_id})
        assert mine.status_code == 200
        assert {w["system_id"] for w in mine.json()} == {system_id}

        by_check = await client.get(
            "/api/waivers",
            params={"system_id": system_id, "check_key": "m365.identity.mfa_registered"},
        )
        assert len(by_check.json()) == 1
        none = await client.get(
            "/api/waivers", params={"system_id": system_id, "check_key": "nope"}
        )
        assert none.json() == []


@pytest.mark.asyncio
async def test_active_only_excludes_requested_and_expired() -> None:
    system_id = await _system()
    async with _client() as client:
        await client.post("/api/waivers", json=_body(system_id))  # stays requested
        expired = (
            await client.post(
                "/api/waivers",
                json=_body(system_id, control_id="AC-2", check_key=None,
                           expires_on="2020-01-01"),
            )
        ).json()["id"]
        await client.post(f"/api/waivers/{expired}/approve")

        active = await client.get(
            "/api/waivers", params={"system_id": system_id, "active_only": True}
        )
        assert active.json() == []


@pytest.mark.asyncio
async def test_exactly_one_target_is_required() -> None:
    """Mirrored from the database constraint so the client gets 400, not 500."""
    system_id = await _system()
    async with _client() as client:
        neither = await client.post(
            "/api/waivers", json=_body(system_id, check_key=None)
        )
        assert neither.status_code == 400, neither.text
        both = await client.post(
            "/api/waivers", json=_body(system_id, control_id="AC-2")
        )
        assert both.status_code == 400, both.text


@pytest.mark.asyncio
async def test_a_blank_rationale_is_rejected() -> None:
    """An acceptance with no stated reason is not reviewable."""
    system_id = await _system()
    async with _client() as client:
        blank = await client.post("/api/waivers", json=_body(system_id, rationale="   "))
        assert blank.status_code == 400


@pytest.mark.asyncio
async def test_an_unknown_system_is_rejected() -> None:
    async with _client() as client:
        missing = await client.post("/api/waivers", json=_body(9_999_999))
        assert missing.status_code == 404


@pytest.mark.asyncio
async def test_an_organization_id_in_the_body_is_ignored() -> None:
    """Tenancy comes from the principal, never from the request."""
    system_id = await _system()
    async with _client() as client:
        created = await client.post(
            "/api/waivers", json=_body(system_id, organization_id=424_242)
        )
        assert created.status_code == 201
        async with session_scope() as session:
            w = (
                await session.execute(
                    select(Waiver).where(Waiver.id == created.json()["id"])
                )
            ).scalar_one()
            assert w.organization_id != 424_242


@pytest.mark.asyncio
async def test_every_transition_is_audited_through_the_hash_chain() -> None:
    system_id = await _system()
    async with _client() as client:
        wid = (await client.post("/api/waivers", json=_body(system_id))).json()["id"]
        await client.post(f"/api/waivers/{wid}/approve")
        await client.post(f"/api/waivers/{wid}/revoke")
    async with session_scope() as session:
        rows = (
            await session.execute(
                select(AuditLog)
                .where(AuditLog.entity_type == "waiver", AuditLog.entity_id == str(wid))
                .order_by(AuditLog.id)
            )
        ).scalars().all()
        events = [r.diff.get("event") for r in rows]
        assert events == ["requested", "approved", "revoked"], events
        # The chain is what makes the trail tamper-evident; a hand-built row
        # would have neither hash.
        assert all(r.row_hash for r in rows)


# ── separation of duties, as a pure rule ─────────────────────────────────────


def test_a_scoped_user_cannot_approve_their_own_request() -> None:
    assert can_approve("isso@acme.gov", "isso@acme.gov", is_global=False) is False


def test_a_scoped_user_can_approve_someone_elses_request() -> None:
    assert can_approve("isso@acme.gov", "ao@acme.gov", is_global=False) is True


def test_a_global_principal_bypasses_separation_of_duties() -> None:
    """Auth-disabled and system callers are not people; enforcing SoD there
    would make the endpoint unusable in development and for the scheduler."""
    assert can_approve("system", "system", is_global=True) is True


def test_an_unattributed_request_can_be_approved_by_a_named_approver() -> None:
    """requested_by is nullable -- a waiver written before attribution existed
    must not become permanently unapprovable."""
    assert can_approve(None, "ao@acme.gov", is_global=False) is True


def test_approval_is_refused_when_neither_party_is_identified() -> None:
    """Separation of duties cannot be demonstrated, so refuse. Found by
    mutation testing: the explicit unattributed-request branch was redundant
    for every named approver and weaker than the inequality here."""
    assert can_approve(None, None, is_global=False) is False
    assert can_approve("isso@acme.gov", "", is_global=False) is False
