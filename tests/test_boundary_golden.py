"""Golden end-to-end test for the system-boundary/inventory feature (Task 8).

Ties together every piece built across Tasks 1-7: build a full boundary
through the service layer, then walk it through the entire downstream
pipeline that consumes it — ``system_boundary_summary``, categorization
reconciliation, the real OSCAL SSP export (no fabricated placeholder), the
Mermaid boundary diagram, and SSP completeness scoring — asserting each
stage sees the same data and that the under-categorization introduced by one
of the information types is flagged end to end.
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from ccf.api.main import create_app
from ccf.boundary import service
from ccf.boundary.diagram import boundary_mermaid
from ccf.boundary.summary import reconcile_categorization, system_boundary_summary
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, SSPProject, System
from ccf.ssp import completeness as ssp_completeness

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


_FULL_META = {
    "system_type": "Cloud",
    "fips199": {"overall": "moderate"},
    "authorization_boundary": "the tenant",
    "roles": {
        "system_owner": {"name": "A"},
        "isso": {"name": "B"},
        "authorizing_official": {"name": "C"},
    },
}


@pytest.mark.asyncio
async def test_golden_boundary_end_to_end() -> None:
    # Isolation: the boundary tables are shared across the whole module-scoped
    # engine, so clear them before building this test's fixture data.
    async with session_scope() as s:
        await s.execute(
            text(
                "TRUNCATE ccf.system_components, ccf.inventory_items, "
                "ccf.information_types, ccf.interconnections CASCADE"
            )
        )

    async with session_scope() as s:
        org = Organization(name="Golden Boundary Org")
        s.add(org)
        await s.flush()
        sysrow = System(
            organization_id=org.id,
            name="Golden Boundary System",
            fips199_confidentiality="moderate",
        )
        s.add(sysrow)
        await s.flush()
        proj = SSPProject(
            organization_id=org.id,
            system_id=sysrow.id,
            customer_name="Golden Boundary Org",
            system_name="Golden Boundary System",
            metadata_json=_FULL_META,
        )
        s.add(proj)
        await s.flush()
        org_id, sys_id, proj_id, sys_name = org.id, sysrow.id, proj.id, sysrow.name

    # --- Build a full boundary via the service layer -----------------------
    async with session_scope() as s:
        comp1 = await service.create_component(
            s,
            system_id=sys_id,
            org_id=org_id,
            data={
                "type": "software",
                "title": "Case Management App",
                "description": "Core case management application.",
                "status": "operational",
            },
        )
        comp2 = await service.create_component(
            s,
            system_id=sys_id,
            org_id=org_id,
            data={
                "type": "hardware",
                "title": "Database Server",
                "description": "Primary database server.",
                "status": "operational",
            },
        )
        comp1_id, comp2_id = comp1.id, comp2.id
        comp1_uuid, comp2_uuid = comp1.oscal_uuid, comp2.oscal_uuid

    async with session_scope() as s:
        item1 = await service.create_inventory_item(
            s,
            system_id=sys_id,
            org_id=org_id,
            data={
                "component_id": comp1_id,
                "asset_id": "ASSET-001",
                "description": "Application server instance.",
                "asset_type": "virtual",
            },
        )
        item2 = await service.create_inventory_item(
            s,
            system_id=sys_id,
            org_id=org_id,
            data={
                "component_id": comp2_id,
                "asset_id": "ASSET-002",
                "description": "Database server instance.",
                "asset_type": "hardware",
            },
        )
        item1_uuid, item2_uuid = item1.oscal_uuid, item2.oscal_uuid

    async with session_scope() as s:
        # This information type's confidentiality impact ("high") exceeds the
        # system's FIPS-199 confidentiality ("moderate") — it should surface
        # as an under-categorization finding downstream.
        info1 = await service.create_information_type(
            s,
            system_id=sys_id,
            org_id=org_id,
            data={
                "title": "Controlled Unclassified Information",
                "description": "CUI processed by the case management app.",
                "confidentiality_impact": "high",
                "integrity_impact": "moderate",
                "availability_impact": "low",
                "adjustment_justification": "Adjusted per org policy.",
            },
        )
        info2 = await service.create_information_type(
            s,
            system_id=sys_id,
            org_id=org_id,
            data={
                "title": "General Business Information",
                "description": "Routine business data.",
                "confidentiality_impact": "low",
                "integrity_impact": "low",
                "availability_impact": "low",
            },
        )
        info1_uuid, info2_uuid = info1.oscal_uuid, info2.oscal_uuid

    async with session_scope() as s:
        icx = await service.create_interconnection(
            s,
            system_id=sys_id,
            org_id=org_id,
            data={
                "remote_system_name": "Partner System",
                "direction": "bidirectional",
                "agreement_type": "ISA",
                "agreement_ref": "ISA-2026-01",
                "data_description": "Case data exchange.",
            },
        )
        icx_uuid = icx.oscal_uuid

    # --- 1. system_boundary_summary sees the full boundary ------------------
    async with session_scope() as s:
        summary = await system_boundary_summary(s, sys_id)

    assert len(summary.components) == 2
    assert len(summary.inventory) == 2
    assert len(summary.info_types) == 2
    assert len(summary.interconnections) == 1

    # --- 2. reconcile_categorization flags the under-categorization --------
    async with session_scope() as s:
        sys_for_reconcile = await s.get(System, sys_id)
        findings = reconcile_categorization(sys_for_reconcile, summary.info_types)

    assert any(
        f["level"] == "confidentiality"
        and f["kind"] == "under_categorized"
        and f["rollup"] == "high"
        and f["system"] == "moderate"
        for f in findings
    )

    # --- 3. OSCAL export uses the real boundary — no fabricated placeholder -
    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        doc = (await c.get(f"/api/oscal/ssp/{proj_id}")).json()

    ssp = doc["system-security-plan"]
    impl = ssp["system-implementation"]

    components = impl["components"]
    comp_uuids = {c["uuid"] for c in components}
    assert comp1_uuid in comp_uuids
    assert comp2_uuid in comp_uuids
    assert icx_uuid in comp_uuids
    # No fabricated placeholder component when the boundary is populated.
    assert not any(
        "not yet enumerated" in (c.get("remarks") or "") for c in components
    )
    assert len(components) == 3  # 2 real components + 1 interconnection component

    inv_items = impl["inventory-items"]
    inv_node = next(i for i in inv_items if i["uuid"] == item1_uuid)
    assert inv_node["implemented-components"] == [{"component-uuid": comp1_uuid}]
    inv_node2 = next(i for i in inv_items if i["uuid"] == item2_uuid)
    assert inv_node2["implemented-components"] == [{"component-uuid": comp2_uuid}]

    info_types = ssp["system-characteristics"]["system-information"]["information-types"]
    assert len(info_types) == 2
    high_info = next(i for i in info_types if i["uuid"] == info1_uuid)
    assert high_info["confidentiality-impact"]["base"] == "high"
    assert info2_uuid in {i["uuid"] for i in info_types}

    # --- 4. boundary_mermaid renders both components + the interconnection -
    mermaid = boundary_mermaid(summary, sys_name)
    assert mermaid.startswith("flowchart")
    assert "Case Management App" in mermaid
    assert "Database Server" in mermaid
    assert "Partner System" in mermaid

    # --- 5. SSP completeness reflects the populated boundary + the gap -----
    # Build the boundary dict the same way src/ccf/api/routes/ssp.py does.
    async with session_scope() as s:
        summary2 = await system_boundary_summary(s, sys_id)
        sys_for_completeness = await s.get(System, sys_id)
        reconciles = (
            reconcile_categorization(sys_for_completeness, summary2.info_types) == []
        )
        ic_total = len(summary2.interconnections)
        ic_with_agreement = sum(
            1
            for ic in summary2.interconnections
            if ic.agreement_type not in (None, "", "none")
            and (ic.agreement_ref or "").strip()
        )
        boundary = {
            "components": len(summary2.components),
            "info_types": len(summary2.info_types),
            "categorization_reconciles": reconciles,
            "interconnections_with_agreements": (ic_with_agreement, ic_total),
        }

    assert reconciles is False

    report = ssp_completeness.assess(_FULL_META, [], boundary=boundary)
    assert "No boundary components defined" not in report["missing_sections"]
    assert "No information types categorized" not in report["missing_sections"]
    assert not any(
        "interconnections lack an agreement" in m for m in report["missing_sections"]
    )
    assert (
        "System categorization does not reconcile with information types"
        in report["missing_sections"]
    )
