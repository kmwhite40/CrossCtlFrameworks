"""Characterization tests for the extracted OSCAL doc builders.

These mirror the existing route-level OSCAL export tests but call the
``build_*_doc`` functions directly (no HTTP layer), asserting the
behavior-preserving refactor in ``ccf.api.routes.oscal`` still produces the
expected top-level OSCAL document shape. Byte-identical output vs. the old
inline route bodies is covered by the unchanged
``tests/test_oscal_validation.py`` / ``tests/test_boundary_oscal.py`` /
``tests/test_nist80053_oscal.py`` regression suites.
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config

from ccf.api.routes.oscal import (
    build_component_definition_doc,
    build_poam_doc,
    build_ssp_doc,
)
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, SSPProject, System

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
async def test_build_ssp_doc_returns_ssp_top_level_key() -> None:
    org_id, sys_id = await _make_org_system("BuildersSspOrg")
    async with session_scope() as s:
        proj = SSPProject(
            organization_id=org_id,
            system_id=sys_id,
            customer_name="BuildersCo",
            system_name="BuildersSys",
        )
        s.add(proj)
        await s.flush()
        doc = await build_ssp_doc(s, proj)

    assert "system-security-plan" in doc
    assert isinstance(doc["system-security-plan"], dict)


@pytest.mark.asyncio
async def test_build_poam_doc_returns_poam_top_level_key() -> None:
    _org_id, sys_id = await _make_org_system("BuildersPoamOrg")
    async with session_scope() as s:
        sysrow = await s.get(System, sys_id)
        assert sysrow is not None
        doc = await build_poam_doc(s, sysrow)

    assert "plan-of-action-and-milestones" in doc
    assert isinstance(doc["plan-of-action-and-milestones"], dict)


@pytest.mark.asyncio
async def test_build_component_definition_doc_returns_component_definition_key() -> None:
    _org_id, sys_id = await _make_org_system("BuildersCompDefOrg")
    async with session_scope() as s:
        sysrow = await s.get(System, sys_id)
        assert sysrow is not None
        doc = await build_component_definition_doc(s, sysrow)

    assert "component-definition" in doc
    assert isinstance(doc["component-definition"], dict)
