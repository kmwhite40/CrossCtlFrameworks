"""Capability endpoints: CRUD, edge replacement, reach, and derivation."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.db import session_scope
from ccf.models import Organization, System


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
