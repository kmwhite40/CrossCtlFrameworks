"""POA&M + component-definition exports conform to the official NIST OSCAL
v1.1.2 JSON Schema (Task 4 of the official-OSCAL-validation program).

Mirrors ``tests/test_ssp_conformance.py`` / ``tests/test_ato.py`` for DB setup
(``session_scope``/``fresh_engine``, module-scoped Alembic migration).
``build_poam_doc`` and ``build_component_definition_doc`` must produce
schema-valid documents — proven by ``validate_document(doc).mode ==
"official"`` (not the structural fallback) and ``.ok`` True — for both a
populated system and, for the component-definition, a sparse one with no
``ControlImplementation`` rows.
"""

from __future__ import annotations

from datetime import date

import pytest
from alembic import command
from alembic.config import Config

from ccf.api.routes.oscal import build_component_definition_doc, build_poam_doc
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import POAM, Control, ControlImplementation, Organization, PoamMilestone, System
from ccf.oscal import validate_document

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
        sysm = System(organization_id=org.id, name=f"{name} system", baseline="moderate")
        s.add(sysm)
        await s.flush()
        return org.id, sysm.id


@pytest.mark.asyncio
async def test_poam_export_conforms_to_official_oscal_schema() -> None:
    """A system with an open POA&M — including a control link, scanner/source
    provenance, due/identified dates, and a milestone — must export a
    schema-valid OSCAL POA&M."""
    _org_id, sys_id = await _make_org_system("PoamConformanceOrg")
    async with session_scope() as s:
        control = Control(identifier="AC-2(1)", control_name="Automated Account Management")
        s.add(control)
        await s.flush()
        poam = POAM(
            system_id=sys_id,
            control_id=control.id,
            title="Unpatched critical CVE",
            weakness="A critical vulnerability is present on internet-facing hosts.",
            severity="critical",
            status="open",
            source="scan",
            scanner="Nessus",
            due_on=date(2026, 9, 1),
            identified_on=date(2026, 7, 1),
        )
        s.add(poam)
        await s.flush()
        s.add(
            PoamMilestone(
                poam_id=poam.id,
                description="Apply vendor patch to affected hosts",
                status="open",
                due_on=date(2026, 8, 15),
            )
        )
        await s.flush()

    async with session_scope() as s:
        sysm = await s.get(System, sys_id)
        assert sysm is not None
        doc = await build_poam_doc(s, sysm)

    items = doc["plan-of-action-and-milestones"]["poam-items"]
    assert len(items) == 1
    assert items[0]["title"] == "Unpatched critical CVE"

    report = validate_document(doc)
    assert report.mode == "official", report.as_dict()
    assert report.ok, report.errors


@pytest.mark.asyncio
async def test_component_definition_export_conforms_to_official_oscal_schema() -> None:
    """A system with two ControlImplementations — one with a NIST SP 800-53
    parenthetical control-id (an OSCAL-illegal token if not sanitized) and no
    ``responsibility`` set, one fully filled in — must export a schema-valid
    OSCAL component-definition."""
    _org_id, sys_id = await _make_org_system("ComponentConformanceOrg")
    async with session_scope() as s:
        # Distinct identifiers from the POA&M test's control above — Control.identifier
        # is globally unique, and both tests run against the same fresh_engine DB.
        control_a = Control(identifier="AU-6(1)", control_name="Automated Audit Review")
        control_b = Control(identifier="AU-6", control_name="Audit Review, Analysis, and Reporting")
        s.add_all([control_a, control_b])
        await s.flush()
        s.add_all(
            [
                ControlImplementation(
                    system_id=sys_id,
                    control_id=control_a.id,
                    status="planned",
                    responsibility=None,
                ),
                ControlImplementation(
                    system_id=sys_id,
                    control_id=control_b.id,
                    status="implemented",
                    responsibility="customer",
                    narrative="Accounts are provisioned and reviewed quarterly.",
                ),
            ]
        )
        await s.flush()

    async with session_scope() as s:
        sysm = await s.get(System, sys_id)
        assert sysm is not None
        doc = await build_component_definition_doc(s, sysm)

    reqs = doc["component-definition"]["components"][0]["control-implementations"][0][
        "implemented-requirements"
    ]
    assert len(reqs) == 2
    # The parenthetical 800-53 identifier must have been sanitized to a valid
    # OSCAL token, not passed through verbatim (which would contain "(", ")").
    assert any(r["control-id"] == "au-6.1" for r in reqs)
    assert any(r["control-id"] == "au-6" for r in reqs)

    report = validate_document(doc)
    assert report.mode == "official", report.as_dict()
    assert report.ok, report.errors


@pytest.mark.asyncio
async def test_component_definition_export_conforms_when_sparse() -> None:
    """A system with zero ControlImplementation rows still exports a
    schema-valid OSCAL component-definition (the honest-placeholder
    implemented-requirement fallback, not an empty ``minItems: 1`` array)."""
    _org_id, sys_id = await _make_org_system("ComponentSparseConformanceOrg")

    async with session_scope() as s:
        sysm = await s.get(System, sys_id)
        assert sysm is not None
        doc = await build_component_definition_doc(s, sysm)

    reqs = doc["component-definition"]["components"][0]["control-implementations"][0][
        "implemented-requirements"
    ]
    assert len(reqs) == 1

    report = validate_document(doc)
    assert report.mode == "official", report.as_dict()
    assert report.ok, report.errors
