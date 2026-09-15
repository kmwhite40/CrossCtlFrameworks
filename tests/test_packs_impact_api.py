"""The impact endpoint: what a version bump would do, before adopting it."""

from __future__ import annotations

import itertools

import pytest
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.db import session_scope
from ccf.models import Organization, System
from ccf.models_waivers import Waiver
from ccf.packs.service import install_pack
from ccf.posture.providers import m365

_SEQ = itertools.count()

RULE = {
    "key": "org.stale_accounts.60d",
    "kind": "posture",
    "definition": {
        "evaluator": m365.STALE_ACCOUNTS.key,
        "parameters": {"threshold_days": 60},
    },
}


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://test")


def _manifest(*rules: dict, pack_id: str, version: str) -> dict:
    return {
        "id": pack_id,
        "name": "Impact API Pack",
        "version": version,
        "schema_version": "1",
        "controls": [{"control_id": "AC-2"}],
        "rules": list(rules),
    }


async def _install_two_versions(pack_id: str) -> tuple[int, int]:
    """A pack at 1.0.0 with the rule, then 2.0.0 without it."""
    async with session_scope() as session:
        org = Organization(name=f"ImpactApiOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"ImpactApiSys-{next(_SEQ)}")
        session.add(sys_)
        await session.flush()
        await install_pack(
            session, org_id=org.id, manifest=_manifest(RULE, pack_id=pack_id, version="1.0.0")
        )
        await install_pack(
            session, org_id=org.id, manifest=_manifest(pack_id=pack_id, version="2.0.0")
        )
        return org.id, sys_.id


@pytest.mark.asyncio
async def test_openapi_lists_the_impact_route() -> None:
    async with _client() as client:
        paths = (await client.get("/openapi.json")).json()["paths"]
        assert "/api/packs/{pack_key}/impact" in paths


@pytest.mark.asyncio
async def test_the_impact_of_removing_a_rule_is_reported() -> None:
    pack_id = f"impact-api-{next(_SEQ)}"
    await _install_two_versions(pack_id)
    async with _client() as client:
        resp = await client.get(
            f"/api/packs/{pack_id}/impact",
            params={"from_version": "1.0.0", "to_version": "2.0.0"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["from_version"] == "1.0.0"
        assert body["to_version"] == "2.0.0"
        controls = {c["control_id"] for c in body["impact"]["controls_affected"]}
        assert controls == set(m365.STALE_ACCOUNTS.control_ids)
        assert {c["change"] for c in body["impact"]["controls_affected"]} == {"removed"}


@pytest.mark.asyncio
async def test_omitting_the_versions_compares_the_two_most_recent() -> None:
    pack_id = f"impact-api-{next(_SEQ)}"
    await _install_two_versions(pack_id)
    async with _client() as client:
        resp = await client.get(f"/api/packs/{pack_id}/impact")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["from_version"] == "1.0.0"
        assert body["to_version"] == "2.0.0"


@pytest.mark.asyncio
async def test_an_orphaned_waiver_is_reported_through_the_endpoint() -> None:
    pack_id = f"impact-api-{next(_SEQ)}"
    org_id, system_id = await _install_two_versions(pack_id)
    async with session_scope() as session:
        session.add(
            Waiver(
                organization_id=org_id,
                system_id=system_id,
                check_key=RULE["key"],
                rationale="accepted",
                status="approved",
            )
        )
    async with _client() as client:
        resp = await client.get(f"/api/packs/{pack_id}/impact")
        orphaned = resp.json()["impact"]["waivers_orphaned"]
        assert [w["check_key"] for w in orphaned] == [RULE["key"]]


@pytest.mark.asyncio
async def test_an_unknown_pack_is_not_found() -> None:
    async with _client() as client:
        resp = await client.get("/api/packs/no-such-pack/impact")
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_an_unknown_version_is_not_found_and_names_which() -> None:
    pack_id = f"impact-api-{next(_SEQ)}"
    await _install_two_versions(pack_id)
    async with _client() as client:
        resp = await client.get(
            f"/api/packs/{pack_id}/impact",
            params={"from_version": "1.0.0", "to_version": "9.9.9"},
        )
        assert resp.status_code == 404
        assert "9.9.9" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_a_pack_with_one_version_reports_no_comparison() -> None:
    """Nothing to compare against is not an impact of nothing."""
    pack_id = f"impact-api-{next(_SEQ)}"
    async with session_scope() as session:
        org = Organization(name=f"ImpactApiOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        await install_pack(
            session, org_id=org.id, manifest=_manifest(RULE, pack_id=pack_id, version="1.0.0")
        )
    async with _client() as client:
        resp = await client.get(f"/api/packs/{pack_id}/impact")
        assert resp.status_code == 409, resp.text
        assert "one version" in resp.json()["detail"]
