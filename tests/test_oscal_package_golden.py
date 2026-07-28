"""Golden end-to-end test for the assessment SAR + authorization-package
bundle (Keystone #3, Task 4).

Drives the whole authorization package pipeline in one pass against a fully
populated system: a boundary (2 ``SystemComponent`` rows via
``ccf.boundary.service``, Keystone #1), a NIST 800-53r5 SSP project seeded
with ``seed_80053_project`` (Keystone #2), ``ControlImplementation``s with an
``Assessment`` + ``AssessmentResult``s + an ``EvidenceObject`` + an open
``POAM``. Asserts the SAR export validates with findings/observations/risks,
the authorization-package ZIP contains all five members with four
schema-valid OSCAL docs, and — the composition proof this task exists for —
that the bundled ``ssp.json`` carries both the 800-53 ``ac-2``
implemented-requirement (Keystone #2) and the boundary's real component
uuids (Keystone #1).

Mirrors ``tests/test_ato.py`` for DB setup (``session_scope``/``fresh_engine``,
module-scoped Alembic migration), ``tests/test_oscal_sar.py`` /
``tests/test_oscal_package.py`` for hitting the routes, and
``tests/test_nist80053_golden.py`` / ``tests/test_boundary_oscal.py`` for how
boundary components are expected to surface in the exported SSP.
"""

from __future__ import annotations

import io
import json
import zipfile
from datetime import date, timedelta

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.boundary.service import create_component
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import (
    POAM,
    Assessment,
    AssessmentResult,
    Control,
    ControlImplementation,
    Organization,
    SSPProject,
    System,
)
from ccf.models_evidence import EvidenceObject
from ccf.oscal import validate_document
from ccf.ssp.seed import seed_80053_project

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


@pytest.mark.asyncio
async def test_golden_e2e_sar_and_authorization_package() -> None:
    # --- 1. Organization + Moderate System -----------------------------
    async with session_scope() as s:
        org = Organization(name="Golden Package Org")
        s.add(org)
        await s.flush()
        sysrow = System(
            organization_id=org.id, name="Golden Package System", baseline="moderate"
        )
        s.add(sysrow)
        await s.flush()
        org_id, sys_id = org.id, sysrow.id

    # --- 2. Boundary: 2 SystemComponents (Keystone #1) ------------------
    async with session_scope() as s:
        comp1 = await create_component(
            s,
            system_id=sys_id,
            org_id=org_id,
            data={
                "type": "software",
                "title": "Golden Case API",
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
                "title": "Golden Case Database",
                "description": "Primary case datastore.",
                "status": "operational",
            },
        )
        comp1_uuid, comp2_uuid = comp1.oscal_uuid, comp2.oscal_uuid

    # --- 3. SSP: project seeded with the moderate 800-53r5 baseline (Keystone #2) ---
    async with session_scope() as s:
        project = SSPProject(
            organization_id=org_id,
            system_id=sys_id,
            customer_name="Golden Package Co",
            system_name="Golden Package System",
            framework="nist-800-53r5",
        )
        s.add(project)
        await s.flush()
        n_seeded = await seed_80053_project(s, project)
        assert n_seeded > 0

    # --- 4. Control implementations + assessment + results + evidence + POA&M ---
    async with session_scope() as s:
        impls: dict[str, ControlImplementation] = {}
        for identifier in ("AC-2", "AU-2"):
            ctrl = (
                await s.execute(select(Control).where(Control.identifier == identifier))
            ).scalar_one_or_none()
            if ctrl is None:
                ctrl = Control(identifier=identifier, control_name=f"{identifier} control title")
                s.add(ctrl)
                await s.flush()
            impl = ControlImplementation(
                system_id=sys_id,
                control_id=ctrl.id,
                status="implemented",
            )
            s.add(impl)
            await s.flush()
            impls[identifier] = impl

        assessment = Assessment(
            system_id=sys_id,
            name="Golden Package internal assessment",
            kind="internal",
            assessor="3PAO",
            started_on=date.today() - timedelta(days=10),
            finished_on=date.today(),
            summary="Internal control assessment for the golden authorization package.",
        )
        s.add(assessment)
        await s.flush()
        assessment_id = assessment.id

        s.add(
            AssessmentResult(
                assessment_id=assessment.id,
                implementation_id=impls["AC-2"].id,
                finding="satisfied",
                rationale="Account management procedures verified.",
                observed_on=date.today(),
            )
        )
        s.add(
            AssessmentResult(
                assessment_id=assessment.id,
                implementation_id=impls["AU-2"].id,
                finding="other_than_satisfied",
                rationale="Audit events not fully enumerated.",
                observed_on=date.today(),
            )
        )

        s.add(
            EvidenceObject(
                organization_id=org_id,
                title="AC-2 account review screenshot",
                description="Screenshot of the account review meeting.",
                system_id=sys_id,
                implementation_id=impls["AC-2"].id,
                control_id="AC-2",
            )
        )

        s.add(
            POAM(
                system_id=sys_id,
                title="Audit log gaps",
                weakness="Audit events are not fully enumerated per AU-2.",
                severity="moderate",
                status="open",
            )
        )
        await s.flush()

    # --- 5. SAR export: validates, has findings/observations/risks -----
    async with _client() as c:
        sar_resp = await c.get(f"/api/oscal/sar/{assessment_id}")
    assert sar_resp.status_code == 200
    sar_doc = sar_resp.json()

    sar_report = validate_document(sar_doc)
    assert sar_report.ok, sar_report.errors

    sar_result = sar_doc["assessment-results"]["results"][0]
    assert len(sar_result["findings"]) >= 1
    assert len(sar_result["observations"]) >= 1
    assert len(sar_result["risks"]) >= 1

    # --- 6. Authorization package: ZIP with all 5 members --------------
    async with _client() as c:
        pkg_resp = await c.get(f"/api/oscal/package/{sys_id}")
    assert pkg_resp.status_code == 200
    assert pkg_resp.content[:2] == b"PK"

    zf = zipfile.ZipFile(io.BytesIO(pkg_resp.content))
    names = set(zf.namelist())
    assert names == {
        "ssp.json",
        "sar.json",
        "poam.json",
        "component-definition.json",
        "README.txt",
    }

    docs: dict[str, dict] = {}
    for name in ("ssp.json", "sar.json", "poam.json", "component-definition.json"):
        doc = json.loads(zf.read(name))
        report = validate_document(doc)
        assert report.ok, (name, report.errors)
        docs[name] = doc

    # --- 7. Composition: the bundled SSP carries both keystones --------
    ssp = docs["ssp.json"]["system-security-plan"]

    # Keystone #2 — the 800-53r5 seeded baseline's AC-2 implemented-requirement.
    reqs = ssp["control-implementation"]["implemented-requirements"]
    assert any(r["control-id"] == "ac-2" for r in reqs)

    # Keystone #1 — the boundary's real components, not a placeholder.
    components = ssp["system-implementation"]["components"]
    assert components
    component_uuids = {comp["uuid"] for comp in components}
    assert {comp1_uuid, comp2_uuid} <= component_uuids
