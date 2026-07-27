"""System boundary & inventory (Keystone #1) — ORM model + RLS coverage.

Mirrors ``tests/test_ato.py``'s setup (module-scoped ``fresh_engine`` +
``_migrate`` autouse fixture, ``session_scope()``) since this repo has no
``db_session`` fixture. Covers: (a) create/read round-trip proving the
SOTA-hook columns (``oscal_uuid``, ``source``) default correctly, and (b)
tenant isolation via ``set_session_tenant``, following the pattern in
``tests/test_rls_coverage.py``.
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select

from ccf.config import get_settings
from ccf.db import session_scope, set_session_tenant
from ccf.models import (
    InformationType,
    Interconnection,
    InventoryItem,
    Organization,
    System,
    SystemComponent,
)

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _make_org_system(name: str) -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        sysrow = System(organization_id=org.id, name=f"{name} system")
        s.add(sysrow)
        await s.flush()
        return org.id, sysrow.id


@pytest.mark.asyncio
async def test_create_and_read_boundary_entities() -> None:
    org_id, sys_id = await _make_org_system("Boundary Org A")

    async with session_scope() as s:
        comp = SystemComponent(
            organization_id=org_id,
            system_id=sys_id,
            type="software",
            title="Web App",
        )
        s.add(comp)
        await s.flush()
        comp_id = comp.id
        assert comp.oscal_uuid and len(comp.oscal_uuid) == 36
        assert comp.source == "manual"

        item = InventoryItem(
            organization_id=org_id,
            system_id=sys_id,
            component_id=comp_id,
            asset_id="ASSET-001",
            asset_type="virtual",
        )
        s.add(item)
        await s.flush()
        assert item.oscal_uuid and len(item.oscal_uuid) == 36
        assert item.source == "manual"
        assert item.component_id == comp_id

        info = InformationType(
            organization_id=org_id,
            system_id=sys_id,
            title="Controlled Unclassified Information",
            confidentiality_impact="moderate",
            integrity_impact="moderate",
            availability_impact="low",
        )
        s.add(info)
        await s.flush()
        assert info.oscal_uuid and len(info.oscal_uuid) == 36
        assert info.source == "manual"
        assert info.categorization_system == "https://doi.org/10.6028/NIST.SP.800-60v2r1"

        icx = Interconnection(
            organization_id=org_id,
            system_id=sys_id,
            remote_system_name="Partner System",
            direction="bidirectional",
            agreement_type="ISA",
        )
        s.add(icx)
        await s.flush()
        assert icx.oscal_uuid and len(icx.oscal_uuid) == 36
        assert icx.source == "manual"

    async with session_scope() as s:
        fetched = (
            await s.execute(
                select(SystemComponent).where(SystemComponent.id == comp_id)
            )
        ).scalar_one()
        assert fetched.title == "Web App"
        assert fetched.status == "operational"


@pytest.mark.asyncio
async def test_rls_isolates_boundary_across_tenants() -> None:
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")

    org_a, sys_a = await _make_org_system("Boundary RLS Org A")
    org_b, _sys_b = await _make_org_system("Boundary RLS Org B")

    async with session_scope() as s:
        await set_session_tenant(s, None)
        comp = SystemComponent(
            organization_id=org_a, system_id=sys_a, type="software", title="Tenant A Component"
        )
        s.add(comp)
        await s.flush()
        comp_id = comp.id

        item = InventoryItem(
            organization_id=org_a,
            system_id=sys_a,
            asset_id="RLS-ASSET-A",
            asset_type="hardware",
        )
        s.add(item)
        await s.flush()
        item_id = item.id

        info = InformationType(organization_id=org_a, system_id=sys_a, title="Tenant A Info Type")
        s.add(info)
        await s.flush()
        info_id = info.id

        icx = Interconnection(
            organization_id=org_a,
            system_id=sys_a,
            remote_system_name="Tenant A Remote",
            direction="outgoing",
            agreement_type="MOU",
        )
        s.add(icx)
        await s.flush()
        icx_id = icx.id

    # Under tenant B, none of tenant A's boundary rows are visible.
    async with session_scope() as s:
        await set_session_tenant(s, org_b)
        assert (
            await s.execute(select(SystemComponent).where(SystemComponent.id == comp_id))
        ).scalar_one_or_none() is None
        assert (
            await s.execute(select(InventoryItem).where(InventoryItem.id == item_id))
        ).scalar_one_or_none() is None
        assert (
            await s.execute(select(InformationType).where(InformationType.id == info_id))
        ).scalar_one_or_none() is None
        assert (
            await s.execute(select(Interconnection).where(Interconnection.id == icx_id))
        ).scalar_one_or_none() is None

    # Under tenant A, the rows are visible again.
    async with session_scope() as s:
        await set_session_tenant(s, org_a)
        assert (
            await s.execute(select(SystemComponent).where(SystemComponent.id == comp_id))
        ).scalar_one_or_none() is not None
        assert (
            await s.execute(select(InventoryItem).where(InventoryItem.id == item_id))
        ).scalar_one_or_none() is not None
        assert (
            await s.execute(select(InformationType).where(InformationType.id == info_id))
        ).scalar_one_or_none() is not None
        assert (
            await s.execute(select(Interconnection).where(Interconnection.id == icx_id))
        ).scalar_one_or_none() is not None
