"""Golden end-to-end test for the NIST 800-53r5 SSP pipeline (Task 8).

Drives the whole pipeline in one pass: boundary (2 components + 1 information
type) + a Moderate system + a ``nist-800-53r5`` project -> ``seed_80053_project``
-> fill one ODP -> OSCAL SSP export (real control-ids + ``set-parameters`` +
boundary-backed ``system-implementation``, Keystone #1 integration) -> the
FedRAMP-style ``.docx`` -> the completeness report. Mirrors
``tests/test_ato.py`` for DB/fixture style, ``tests/test_nist80053_seed.py``
for the expected-count computation, ``tests/test_nist80053_oscal.py`` for the
OSCAL export route, and ``tests/test_boundary_oscal.py`` for how boundary
components surface in the export.
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text

from ccf.api.main import create_app
from ccf.boundary.service import create_component, create_information_type
from ccf.catalog.oscal import load_oscal_catalog
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, SSPControlEntry, SSPProject, System
from ccf.ssp import completeness as ssp_completeness
from ccf.ssp.nist80053_docx import render_80053_docx
from ccf.ssp.seed import entry_to_dict, seed_80053_project

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


@pytest.mark.asyncio
async def test_golden_e2e_nist80053_pipeline() -> None:
    # Isolation: this test asserts an exact seeded row count against the full
    # moderate baseline, so start from a clean slate for every table it touches.
    async with session_scope() as s:
        await s.execute(
            text(
                "TRUNCATE ccf.ssp_control_entries, ccf.ssp_projects, "
                "ccf.system_components, ccf.inventory_items, "
                "ccf.information_types, ccf.interconnections CASCADE"
            )
        )

    # --- 1. Organization + Moderate System + a small boundary + project ---
    async with session_scope() as s:
        org = Organization(name="Golden 80053 Org")
        s.add(org)
        await s.flush()
        sysrow = System(organization_id=org.id, name="Golden 80053 System", baseline="moderate")
        s.add(sysrow)
        await s.flush()
        org_id, sys_id = org.id, sysrow.id

    async with session_scope() as s:
        comp1 = await create_component(
            s,
            system_id=sys_id,
            org_id=org_id,
            data={
                "type": "software",
                "title": "Case API",
                "description": "Core case management API.",
                "status": "operational",
            },
        )
        comp2 = await create_component(
            s,
            system_id=sys_id,
            org_id=org_id,
            data={
                "type": "software",
                "title": "Case Database",
                "description": "Primary case datastore.",
                "status": "operational",
            },
        )
        comp1_uuid, comp2_uuid = comp1.oscal_uuid, comp2.oscal_uuid
        await create_information_type(
            s,
            system_id=sys_id,
            org_id=org_id,
            data={
                "title": "Controlled Unclassified Information",
                "description": "CUI processed by the case API.",
                "confidentiality_impact": "moderate",
                "integrity_impact": "moderate",
                "availability_impact": "low",
            },
        )

    async with session_scope() as s:
        project = SSPProject(
            organization_id=org_id,
            system_id=sys_id,
            customer_name="Golden 80053 Co",
            system_name="Golden 80053 System",
            framework="nist-800-53r5",
        )
        s.add(project)
        await s.flush()
        project_id = project.id

    # --- 2. Seed the moderate baseline --------------------------------------
    catalog = load_oscal_catalog()
    # Same filter build_80053_entries applies: every non-withdrawn control id
    # in the moderate 800-53B baseline.
    expected_ids = {
        cid
        for cid in catalog.baselines["moderate"]
        if catalog.get(cid) and not catalog.get(cid).withdrawn
    }

    async with session_scope() as s:
        proj = await s.get(SSPProject, project_id)
        assert proj is not None
        n = await seed_80053_project(s, proj, catalog=catalog)
        assert n == len(expected_ids)

    async with session_scope() as s:
        rows = (
            (
                await s.execute(
                    select(SSPControlEntry).where(SSPControlEntry.project_id == project_id)
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == len(expected_ids)
        assert any(r.control_id == "AC-2" for r in rows)

    # --- 3. Fill one ODP on AC-2 --------------------------------------------
    async with session_scope() as s:
        ac2 = (
            await s.execute(
                select(SSPControlEntry).where(
                    SSPControlEntry.project_id == project_id,
                    SSPControlEntry.control_id == "AC-2",
                )
            )
        ).scalar_one()
        assert ac2.odp_values, "AC-2 should have scaffolded ODPs to fill"
        first_odp_key = next(iter(ac2.odp_values))
        ac2.odp_values = {**ac2.odp_values, first_odp_key: "24 hours"}
        await s.commit()

    # --- 4. Export the SSP OSCAL (same route as test_nist80053_oscal.py) ---
    async with _client() as c:
        doc = (await c.get(f"/api/oscal/ssp/{project_id}")).json()

    ssp = doc["system-security-plan"]
    reqs = ssp["control-implementation"]["implemented-requirements"]
    ac2_req = next(r for r in reqs if r["control-id"] == "ac-2")
    assert {"param-id": first_odp_key, "values": ["24 hours"]} in ac2_req["set-parameters"]

    # Keystone #1 integration: the boundary's real components (not a
    # freshly-minted placeholder) show up in system-implementation.
    component_uuids = {comp["uuid"] for comp in ssp["system-implementation"]["components"]}
    assert {comp1_uuid, comp2_uuid} <= component_uuids

    # --- 5. Render the docx --------------------------------------------------
    async with session_scope() as s:
        rows = (
            (
                await s.execute(
                    select(SSPControlEntry)
                    .where(SSPControlEntry.project_id == project_id)
                    .order_by(SSPControlEntry.sort_order)
                )
            )
            .scalars()
            .all()
        )
        entry_dicts = [entry_to_dict(r) for r in rows]

    project_meta = {
        "customer_name": "Golden 80053 Co",
        "system_name": "Golden 80053 System",
        "baseline": "moderate",
    }
    data = render_80053_docx(project_meta, entry_dicts)
    assert isinstance(data, bytes)
    assert data[:2] == b"PK"
    assert len(data) > 2000

    # --- 6. Completeness: most ODPs are still unset -------------------------
    report = ssp_completeness.assess({}, entry_dicts)
    assert report["odp_summary"]["unset"] > 0
    assert any(
        "organization-defined parameters (ODPs) unset" in m for m in report["missing_sections"]
    )
