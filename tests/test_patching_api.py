"""Flaw-remediation endpoints: the report, the policy, and campaigns."""

from __future__ import annotations

import itertools
from datetime import date, timedelta

import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.auth_deps import get_principal
from ccf.api.main import create_app
from ccf.api.routes.patching import _owned_campaign
from ccf.auth import Principal
from ccf.db import session_scope
from ccf.models import POAM, Organization, System
from ccf.models_patching import PatchWave

_SEQ = itertools.count()
TODAY = date.today()


class _Session:
    """A client whose identity and role can change between calls."""

    def __init__(self, *, org_id: int | None = None, role: str = "admin") -> None:
        self.app = create_app()
        self.email = "isso@acme.gov"
        self.org_id = org_id
        self.role = role
        self.app.dependency_overrides[get_principal] = self._principal

    def _principal(self) -> Principal:
        return Principal(user_id=1, email=self.email, org_id=self.org_id, role=self.role)

    def as_(self, email: str, *, role: str | None = None) -> _Session:
        self.email = email
        if role is not None:
            self.role = role
        return self

    def client(self) -> AsyncClient:
        return AsyncClient(transport=ASGITransport(app=self.app), base_url="http://test")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://test")


async def _system_with_flaws(n: int = 4, *, severity: str = "critical", age: int = 45):
    async with session_scope() as session:
        org = Organization(name=f"PatchApiOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"PatchApiSys-{next(_SEQ)}")
        session.add(sys_)
        await session.flush()
        for i in range(n):
            session.add(
                POAM(
                    system_id=sys_.id,
                    title=f"flaw-{next(_SEQ)}-{i}",
                    severity=severity,
                    status="open",
                    source="scan",
                    identified_on=TODAY - timedelta(days=age),
                )
            )
        await session.flush()
        return sys_.id, org.id


@pytest.mark.asyncio
async def test_openapi_lists_the_patching_routes() -> None:
    async with _client() as client:
        paths = (await client.get("/openapi.json")).json()["paths"]
        assert "/api/systems/{system_id}/flaw-remediation" in paths
        assert "/api/remediation-policy" in paths
        assert "/api/systems/{system_id}/patch-campaigns" in paths
        assert "/api/patch-campaigns/{campaign_id}" in paths
        assert "/api/patch-waves/{wave_id}/complete" in paths


@pytest.mark.asyncio
async def test_there_is_no_endpoint_that_applies_a_patch() -> None:
    """Concord has no endpoint-management provider, and no route should imply
    otherwise."""
    async with _client() as client:
        paths = (await client.get("/openapi.json")).json()["paths"]
    for path in paths:
        assert "apply-patch" not in path
        assert "install-update" not in path


@pytest.mark.asyncio
async def test_the_report_breaches_on_aged_criticals() -> None:
    system_id, _org = await _system_with_flaws(2, severity="critical", age=45)
    async with _client() as client:
        resp = await client.get(f"/api/systems/{system_id}/flaw-remediation")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["buckets"]["breached"] == 2
        assert body["window"]["critical"] == 30
        assert len(body["breaching_ids"]) == 2


@pytest.mark.asyncio
async def test_a_default_policy_is_reported_as_a_default_not_a_decision() -> None:
    """A caller should know whether it is looking at a decision or a fallback."""
    async with _client() as client:
        body = (await client.get("/api/remediation-policy")).json()
        assert body["explicit"] is False
        assert body["source"] == "fedramp-default"
        assert body["window"]["moderate"] == 90


@pytest.mark.asyncio
async def test_setting_a_tighter_policy_moves_the_buckets() -> None:
    system_id, org_id = await _system_with_flaws(1, severity="moderate", age=45)
    session = _Session(org_id=org_id, role="issm")
    async with session.client() as client:
        before = (await client.get(f"/api/systems/{system_id}/flaw-remediation")).json()
        assert before["buckets"]["within_sla"] == 1

        put = await client.put(
            "/api/remediation-policy",
            json={"moderate_days": 14, "source": "organization policy 4.2"},
        )
        assert put.status_code == 200, put.text
        assert put.json()["window"]["moderate"] == 14
        assert put.json()["explicit"] is True

        after = (await client.get(f"/api/systems/{system_id}/flaw-remediation")).json()
        assert after["buckets"]["breached"] == 1


@pytest.mark.asyncio
async def test_a_zero_day_window_is_rejected() -> None:
    session = _Session(org_id=None, role="admin")
    async with session.client() as client:
        resp = await client.put("/api/remediation-policy", json={"critical_days": 0})
        assert resp.status_code == 400


@pytest.mark.asyncio
async def test_setting_a_policy_is_role_gated() -> None:
    """A scoped viewer cannot redefine the timeframe the organization is
    measured against."""
    _system_id, org_id = await _system_with_flaws(1)
    viewer = _Session(org_id=org_id, role="viewer").as_("viewer@acme.gov")
    async with viewer.client() as client:
        resp = await client.put("/api/remediation-policy", json={"critical_days": 365})
        assert resp.status_code == 403


@pytest.mark.asyncio
async def test_create_a_campaign_and_complete_its_waves_in_order() -> None:
    system_id, org_id = await _system_with_flaws(5)
    session = _Session(org_id=org_id, role="isso")
    async with session.client() as client:
        created = await client.post(
            f"/api/systems/{system_id}/patch-campaigns",
            json={
                "name": "September criticals",
                "window_start": str(TODAY),
                "window_end": str(TODAY + timedelta(days=7)),
                "wave_size": 2,
            },
        )
        assert created.status_code == 201, created.text
        body = created.json()
        assert body["status"] == "planned"
        assert [len(w["poam_ids"]) for w in body["waves"]] == [1, 2, 2]
        waves = body["waves"]

        # Out of order is refused.
        out_of_order = await client.post(
            f"/api/patch-waves/{waves[1]['id']}/complete", json={}
        )
        assert out_of_order.status_code == 409
        assert "still pending" in out_of_order.json()["detail"]

        for w in waves:
            done = await client.post(
                f"/api/patch-waves/{w['id']}/complete",
                json={"evidence_ref": f"CHG-{w['sequence']}"},
            )
            assert done.status_code == 200, done.text
            assert done.json()["status"] == "completed"

        final = (await client.get(f"/api/patch-campaigns/{body['id']}")).json()
        assert final["status"] == "completed"


@pytest.mark.asyncio
async def test_a_campaign_with_no_open_flaws_is_a_conflict() -> None:
    async with session_scope() as session:
        org = Organization(name=f"PatchApiOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"Bare-{next(_SEQ)}")
        session.add(sys_)
        await session.flush()
        system_id = sys_.id
    async with _client() as client:
        resp = await client.post(
            f"/api/systems/{system_id}/patch-campaigns",
            json={"name": "empty", "window_start": str(TODAY), "window_end": str(TODAY)},
        )
        assert resp.status_code == 409
        assert "no open scan-sourced findings" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_completing_a_wave_is_role_gated() -> None:
    system_id, org_id = await _system_with_flaws(2)
    author = _Session(org_id=org_id, role="isso")
    async with author.client() as client:
        waves = (
            await client.post(
                f"/api/systems/{system_id}/patch-campaigns",
                json={"name": "c", "window_start": str(TODAY), "window_end": str(TODAY)},
            )
        ).json()["waves"]
    viewer = _Session(org_id=org_id, role="viewer").as_("viewer@acme.gov")
    async with viewer.client() as client:
        resp = await client.post(f"/api/patch-waves/{waves[0]['id']}/complete", json={})
        assert resp.status_code == 403
    async with session_scope() as db:
        wave = (
            await db.execute(select(PatchWave).where(PatchWave.id == waves[0]["id"]))
        ).scalar_one()
        assert wave.status == "pending", "a rejected call changed nothing"


@pytest.mark.asyncio
async def test_listing_filters_by_system() -> None:
    """Two systems, so the filter must exclude."""
    mine, _org_id = await _system_with_flaws(2)
    theirs, _ = await _system_with_flaws(2)
    async with _client() as client:
        for system_id in (mine, theirs):
            await client.post(
                f"/api/systems/{system_id}/patch-campaigns",
                json={"name": "c", "window_start": str(TODAY), "window_end": str(TODAY)},
            )
        listed = (
            await client.get("/api/patch-campaigns", params={"system_id": mine})
        ).json()
        assert {c["system_id"] for c in listed} == {mine}


@pytest.mark.asyncio
async def test_an_unknown_system_and_campaign_are_not_found() -> None:
    async with _client() as client:
        assert (
            await client.get("/api/systems/9999999/flaw-remediation")
        ).status_code == 404
        assert (await client.get("/api/patch-campaigns/9999999")).status_code == 404
        assert (
            await client.post("/api/patch-waves/9999999/complete", json={})
        ).status_code == 404


@pytest.mark.asyncio
async def test_a_scoped_principal_cannot_reach_another_tenants_campaign() -> None:
    """Exercised directly: the default client is a global principal, so the
    cross-tenant branch is unreachable through it."""
    system_id, org_id = await _system_with_flaws(2)
    session = _Session(org_id=org_id, role="isso")
    async with session.client() as client:
        campaign_id = (
            await client.post(
                f"/api/systems/{system_id}/patch-campaigns",
                json={"name": "c", "window_start": str(TODAY), "window_end": str(TODAY)},
            )
        ).json()["id"]
    async with session_scope() as db:
        intruder = Principal(
            user_id=1, email="other@example.gov", org_id=org_id + 1000, role="admin"
        )
        with pytest.raises(HTTPException) as caught:
            await _owned_campaign(db, campaign_id, intruder)
        assert caught.value.status_code == 404
        owner = Principal(user_id=2, email="o@example.gov", org_id=org_id, role="admin")
        assert (await _owned_campaign(db, campaign_id, owner)).id == campaign_id
