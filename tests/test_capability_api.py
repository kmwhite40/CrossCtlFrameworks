"""Capability endpoints: CRUD, edge replacement, reach, and derivation."""

from __future__ import annotations

import itertools

import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.api.routes.capabilities import ComponentEdgesIn, RiskEdgesIn, set_components, set_risks
from ccf.auth import Principal
from ccf.db import session_scope
from ccf.models import Organization, Risk, System, SystemComponent
from ccf.models_capability import Capability

_SEQ = itertools.count()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://test")


@pytest.mark.asyncio
async def test_openapi_lists_capability_routes() -> None:
    async with _client() as client:
        paths = (await client.get("/openapi.json")).json()["paths"]
        assert "/api/capabilities" in paths
        assert "/api/capabilities/{capability_id}" in paths
        assert "/api/capabilities/{capability_id}/controls" in paths
        assert "/api/capabilities/{capability_id}/frameworks" in paths
        assert "/api/controls/{control_id}/capabilities" in paths
        assert "/api/systems/{system_id}/derive-status" in paths


@pytest.mark.asyncio
async def test_create_list_and_fetch_a_capability() -> None:
    async with _client() as client:
        created = await client.post(
            "/api/capabilities",
            json={"key": "api-mfa", "title": "MFA everywhere", "status": "implemented"},
        )
        assert created.status_code == 201, created.text
        cap_id = created.json()["id"]

        listed = await client.get("/api/capabilities")
        assert listed.status_code == 200
        assert any(c["id"] == cap_id for c in listed.json())

        one = await client.get(f"/api/capabilities/{cap_id}")
        assert one.status_code == 200
        assert one.json()["key"] == "api-mfa"


@pytest.mark.asyncio
async def test_replacing_control_edges_is_idempotent() -> None:
    async with _client() as client:
        cap_id = (
            await client.post(
                "/api/capabilities",
                json={"key": "api-edges", "title": "Edges", "status": "planned"},
            )
        ).json()["id"]

        first = await client.put(
            f"/api/capabilities/{cap_id}/controls", json={"control_ids": ["AC-2", "IA-2"]}
        )
        assert first.status_code == 200, first.text
        assert sorted(first.json()["control_ids"]) == ["AC-2", "IA-2"]

        again = await client.put(
            f"/api/capabilities/{cap_id}/controls", json={"control_ids": ["AC-2", "IA-2"]}
        )
        assert sorted(again.json()["control_ids"]) == ["AC-2", "IA-2"]

        shrunk = await client.put(
            f"/api/capabilities/{cap_id}/controls", json={"control_ids": ["AC-2"]}
        )
        assert shrunk.json()["control_ids"] == ["AC-2"]


@pytest.mark.asyncio
async def test_control_edges_are_stored_canonicalized() -> None:
    """A padded id in, the canonical form out -- one spelling in the database."""
    async with _client() as client:
        cap_id = (
            await client.post(
                "/api/capabilities",
                json={"key": "api-canon", "title": "Canon", "status": "planned"},
            )
        ).json()["id"]
        r = await client.put(
            f"/api/capabilities/{cap_id}/controls", json={"control_ids": ["AC-02"]}
        )
        assert r.json()["control_ids"] == ["AC-2"]


@pytest.mark.asyncio
async def test_unparseable_control_id_is_422() -> None:
    async with _client() as client:
        cap_id = (
            await client.post(
                "/api/capabilities",
                json={"key": "api-bad-ctl", "title": "Bad", "status": "planned"},
            )
        ).json()["id"]
        r = await client.put(
            f"/api/capabilities/{cap_id}/controls", json={"control_ids": ["not a control"]}
        )
        assert r.status_code == 422


@pytest.mark.asyncio
async def test_unknown_capability_is_404() -> None:
    async with _client() as client:
        assert (await client.get("/api/capabilities/999999")).status_code == 404
        assert (await client.get("/api/capabilities/999999/frameworks")).status_code == 404


@pytest.mark.asyncio
async def test_duplicate_key_is_409() -> None:
    async with _client() as client:
        body = {"key": "api-dup", "title": "Dup", "status": "planned"}
        assert (await client.post("/api/capabilities", json=body)).status_code == 201
        assert (await client.post("/api/capabilities", json=body)).status_code == 409


@pytest.mark.asyncio
async def test_key_is_generated_from_the_title_when_omitted() -> None:
    """Spec open item 1: server-generated, client may override."""
    async with _client() as client:
        first = await client.post(
            "/api/capabilities",
            json={"title": "Conditional Access Enforces MFA", "status": "implemented"},
        )
        assert first.status_code == 201, first.text
        assert first.json()["key"] == "conditional-access-enforces-mfa"

        second = await client.post(
            "/api/capabilities",
            json={"title": "Conditional Access Enforces MFA", "status": "planned"},
        )
        assert second.status_code == 201
        assert second.json()["key"] == "conditional-access-enforces-mfa-2"


@pytest.mark.asyncio
async def test_invalid_status_is_422() -> None:
    async with _client() as client:
        r = await client.post(
            "/api/capabilities", json={"title": "Bad status", "status": "nonsense"}
        )
        assert r.status_code == 422


@pytest.mark.asyncio
async def test_patch_and_delete() -> None:
    async with _client() as client:
        cap_id = (
            await client.post(
                "/api/capabilities",
                json={"key": "api-patch", "title": "Before", "status": "planned"},
            )
        ).json()["id"]

        patched = await client.patch(
            f"/api/capabilities/{cap_id}", json={"title": "After", "solution": "identity"}
        )
        assert patched.status_code == 200
        assert patched.json()["title"] == "After"
        assert patched.json()["solution"] == "identity"

        assert (await client.delete(f"/api/capabilities/{cap_id}")).status_code == 204
        assert (await client.get(f"/api/capabilities/{cap_id}")).status_code == 404


@pytest.mark.asyncio
async def test_derive_status_endpoint_reports_a_count() -> None:
    async with session_scope() as session:
        org = Organization(name="ApiDeriveOrg")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name="ApiDeriveSys")
        session.add(sys_)
        await session.flush()
        sid = sys_.id

    async with _client() as client:
        r = await client.post(f"/api/systems/{sid}/derive-status")
        assert r.status_code == 200
        assert r.json() == {"system_id": sid, "rows_annotated": 0}


# --- edge-target ownership -------------------------------------------------
#
# The FK check on a component/risk id proves the row exists *somewhere*, not
# that it belongs to the calling capability's organization -- and it does not
# consult RLS. Called directly with a synthetic scoped Principal against a
# session_scope() (RLS-bypass) session, so this isolates the app-layer
# ownership check itself rather than the DB's RLS enforcement.


@pytest.mark.asyncio
async def test_set_components_rejects_a_component_owned_by_another_org() -> None:
    async with session_scope() as session:
        org_a = Organization(name=f"CompOwnOrgA-{next(_SEQ)}")
        org_b = Organization(name=f"CompOwnOrgB-{next(_SEQ)}")
        session.add_all([org_a, org_b])
        await session.flush()
        sys_b = System(organization_id=org_b.id, name=f"CompOwnSysB-{next(_SEQ)}")
        session.add(sys_b)
        await session.flush()
        comp_b = SystemComponent(
            organization_id=org_b.id, system_id=sys_b.id, type="service", title="B Comp"
        )
        session.add(comp_b)
        cap_a = Capability(organization_id=org_a.id, key=f"comp-own-a-{next(_SEQ)}", title="Cap A")
        session.add(cap_a)
        await session.flush()

        principal_a = Principal(user_id=None, email="compowna@t", org_id=org_a.id, role="admin")
        with pytest.raises(HTTPException) as exc:
            await set_components(
                cap_a.id,
                ComponentEdgesIn(component_ids=[comp_b.id]),
                session=session,
                principal=principal_a,
            )
        assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_set_components_rejects_a_nonexistent_component_id() -> None:
    async with session_scope() as session:
        org_a = Organization(name=f"CompMissingOrgA-{next(_SEQ)}")
        session.add(org_a)
        await session.flush()
        cap_a = Capability(
            organization_id=org_a.id, key=f"comp-missing-a-{next(_SEQ)}", title="Cap A"
        )
        session.add(cap_a)
        await session.flush()

        principal_a = Principal(user_id=None, email="compmissa@t", org_id=org_a.id, role="admin")
        with pytest.raises(HTTPException) as exc:
            await set_components(
                cap_a.id,
                ComponentEdgesIn(component_ids=[999_999_999]),
                session=session,
                principal=principal_a,
            )
        assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_set_risks_rejects_a_risk_owned_by_another_org() -> None:
    async with session_scope() as session:
        org_a = Organization(name=f"RiskOwnOrgA-{next(_SEQ)}")
        org_b = Organization(name=f"RiskOwnOrgB-{next(_SEQ)}")
        session.add_all([org_a, org_b])
        await session.flush()
        sys_b = System(organization_id=org_b.id, name=f"RiskOwnSysB-{next(_SEQ)}")
        session.add(sys_b)
        await session.flush()
        risk_b = Risk(system_id=sys_b.id, title="B Risk")
        session.add(risk_b)
        cap_a = Capability(organization_id=org_a.id, key=f"risk-own-a-{next(_SEQ)}", title="Cap A")
        session.add(cap_a)
        await session.flush()

        principal_a = Principal(user_id=None, email="riskowna@t", org_id=org_a.id, role="admin")
        with pytest.raises(HTTPException) as exc:
            await set_risks(
                cap_a.id,
                RiskEdgesIn(risk_ids=[risk_b.id]),
                session=session,
                principal=principal_a,
            )
        assert exc.value.status_code == 404
