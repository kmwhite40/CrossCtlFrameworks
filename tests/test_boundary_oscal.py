"""OSCAL SSP export sourced from the real system-boundary inventory (Task 4).

Verifies ``GET /api/oscal/ssp/{project_id}`` builds ``system-implementation``
and ``information-types`` from ``SystemComponent``/``InventoryItem``/
``InformationType``/``Interconnection`` rows — using each row's persisted
``oscal_uuid`` (never a freshly minted one) — and still falls back to the
single annotated placeholder component when the project's system has no
boundary enumerated.
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import (
    InformationType,
    Interconnection,
    InventoryItem,
    Organization,
    System,
    SystemComponent,
)
from ccf.oscal import validate_document

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _make_org_system(name: str) -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        sysrow = System(organization_id=org.id, name=f"{name} system")
        s.add(sysrow)
        await s.flush()
        return org.id, sysrow.id


async def _make_project(org_id: int, sys_id: int, customer_name: str) -> int:
    async with _client() as c:
        pid = (
            await c.post(
                "/api/ssp/projects",
                json={
                    "customer_name": customer_name,
                    "system_id": sys_id,
                    "system_name": f"{customer_name} System",
                },
            )
        ).json()["id"]
    return pid


async def _populate_boundary(org_id: int, sys_id: int) -> dict[str, str]:
    """Populate one of each boundary entity for ``sys_id``; return the
    persisted ``oscal_uuid`` values keyed by entity kind."""
    async with session_scope() as s:
        comp = SystemComponent(
            organization_id=org_id,
            system_id=sys_id,
            type="software",
            title="Case Management App",
            description="Core case management application.",
            status="operational",
        )
        s.add(comp)
        await s.flush()
        comp_id = comp.id
        comp_uuid = comp.oscal_uuid

        item = InventoryItem(
            organization_id=org_id,
            system_id=sys_id,
            component_id=comp_id,
            asset_id="ASSET-001",
            description="Primary application server.",
            asset_type="virtual",
        )
        s.add(item)
        await s.flush()
        item_uuid = item.oscal_uuid

        info = InformationType(
            organization_id=org_id,
            system_id=sys_id,
            title="Controlled Unclassified Information",
            description="CUI processed by the case management app.",
            confidentiality_impact="moderate",
            integrity_impact="moderate",
            availability_impact="low",
            adjustment_justification="Adjusted per org policy.",
        )
        s.add(info)
        await s.flush()
        info_uuid = info.oscal_uuid

        icx = Interconnection(
            organization_id=org_id,
            system_id=sys_id,
            remote_system_name="Partner System",
            direction="bidirectional",
            agreement_type="ISA",
            data_description="Case data exchange.",
        )
        s.add(icx)
        await s.flush()
        icx_uuid = icx.oscal_uuid

    return {
        "component": comp_uuid,
        "inventory_item": item_uuid,
        "info_type": info_uuid,
        "interconnection": icx_uuid,
    }


@pytest.mark.asyncio
async def test_ssp_export_uses_real_boundary_inventory() -> None:
    org_id, sys_id = await _make_org_system("Boundary OSCAL Org")
    uuids = await _populate_boundary(org_id, sys_id)
    pid = await _make_project(org_id, sys_id, "BoundaryCo")

    async with _client() as c:
        doc = (await c.get(f"/api/oscal/ssp/{pid}")).json()

    ssp = doc["system-security-plan"]
    impl = ssp["system-implementation"]

    components = impl["components"]
    comp_node = next(c for c in components if c["uuid"] == uuids["component"])
    assert comp_node["title"] == "Case Management App"
    assert comp_node["type"] == "software"
    assert comp_node["status"]["state"] == "operational"

    icx_node = next(c for c in components if c["uuid"] == uuids["interconnection"])
    assert icx_node["type"] == "interconnection"
    assert icx_node["title"] == "Partner System"

    inv_items = impl["inventory-items"]
    inv_node = next(i for i in inv_items if i["uuid"] == uuids["inventory_item"])
    assert inv_node["implemented-components"] == [{"component-uuid": uuids["component"]}]

    info_types = ssp["system-characteristics"]["system-information"]["information-types"]
    info_node = next(i for i in info_types if i["uuid"] == uuids["info_type"])
    assert info_node["confidentiality-impact"]["base"] == "moderate"
    assert info_node["integrity-impact"]["base"] == "moderate"
    assert info_node["availability-impact"]["base"] == "low"
    # The OSCAL "information-type" object has no "remarks" property
    # (additionalProperties: false) — the adjustment justification is carried
    # as a props entry instead, the one schema-legal extensible field.
    info_props = {p["name"]: p["value"] for p in info_node["props"]}
    assert info_props["adjustment-justification"] == "Adjusted per org policy."

    report = validate_document(doc)
    assert report.ok, report.errors


@pytest.mark.asyncio
async def test_ssp_export_component_uuid_is_stable_across_exports() -> None:
    org_id, sys_id = await _make_org_system("Boundary Stable Org")
    uuids = await _populate_boundary(org_id, sys_id)
    pid = await _make_project(org_id, sys_id, "StableCo")

    async with _client() as c:
        doc1 = (await c.get(f"/api/oscal/ssp/{pid}")).json()
        doc2 = (await c.get(f"/api/oscal/ssp/{pid}")).json()

    comp1 = doc1["system-security-plan"]["system-implementation"]["components"][0]
    comp2 = doc2["system-security-plan"]["system-implementation"]["components"][0]
    assert comp1["uuid"] == comp2["uuid"] == uuids["component"]


@pytest.mark.asyncio
async def test_ssp_export_falls_back_to_placeholder_when_boundary_empty() -> None:
    org_id, sys_id = await _make_org_system("Boundary Empty Org")
    pid = await _make_project(org_id, sys_id, "EmptyCo")

    async with _client() as c:
        doc = (await c.get(f"/api/oscal/ssp/{pid}")).json()

    impl = doc["system-security-plan"]["system-implementation"]
    assert len(impl["components"]) == 1
    placeholder = impl["components"][0]
    assert placeholder["title"] == "EmptyCo System"
    assert "not yet enumerated" in placeholder["remarks"]
    assert "inventory-items" not in impl

    report = validate_document(doc)
    assert report.ok, report.errors


@pytest.mark.asyncio
async def test_ssp_export_without_system_id_still_placeholders() -> None:
    """A project not linked to any System (system_id is None) must not error
    and must produce the same placeholder fallback."""
    async with _client() as c:
        pid = (
            await c.post("/api/ssp/projects", json={"customer_name": "NoSystemCo"})
        ).json()["id"]
        doc = (await c.get(f"/api/oscal/ssp/{pid}")).json()

    impl = doc["system-security-plan"]["system-implementation"]
    assert len(impl["components"]) == 1
    assert "not yet enumerated" in impl["components"][0]["remarks"]

    report = validate_document(doc)
    assert report.ok, report.errors
