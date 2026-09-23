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
from fastapi import HTTPException

from ccf.api.routes.oscal import (
    build_component_definition_doc,
    build_poam_doc,
    build_ssp_doc,
    component_definition,
    poam_export,
    sar_export_latest,
    ssp_export,
)
from ccf.auth import Principal
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Assessment, Organization, SSPProject, System

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


# --- the export routes' OWN org predicates, where RLS cannot mask them -------
#
# Each OSCAL export route carries an explicit
# ``principal.org_id is not None and row.organization_id != principal.org_id``
# check. The end-to-end tests for those checks
# (``test_auth.py::test_oscal_and_reports_are_org_scoped``,
# ``test_oscal_package.py::test_package_export_out_of_org_is_404``) assert the
# right result but cannot fail when only the explicit check is deleted: every
# table these routes read carries a ``tenant_isolation`` RLS policy, and
# ``ccf.api.deps.get_session`` binds the RLS tenant from the principal, so the
# outsider's request 404s at the query before the route's own check is reached.
# Confirmed by mutation — deleting each check left those HTTP tests passing.
#
# RLS is documented in ``ccf.api.deps.get_session`` as a backstop *beneath* the
# app-layer scoping, and the CLI/scheduler paths use the unscoped
# ``session_scope()`` that bypasses RLS by design, so the app-layer scoping
# needs tests that can actually fail. These call each route function directly
# on an unscoped ``session_scope()`` session with a foreign principal, and each
# first asserts the owning org still gets its document — so the 404 is provably
# the org check and not the row being unreachable for some unrelated reason.
#
# ``poam_export`` and ``sar_export_latest`` had no cross-tenant test at all
# before this; the other two had one that could not fail.


def _principal(org_id: int, who: str) -> Principal:
    return Principal(user_id=None, email=f"{who}@oscal-builders.test", org_id=org_id, role="admin")


@pytest.mark.asyncio
async def test_component_definition_org_check_rejects_a_foreign_principal_without_rls() -> None:
    owner_org, sys_id = await _make_org_system("BuildersCompDefOwnerOrg")
    other_org, _other_sys = await _make_org_system("BuildersCompDefOtherOrg")

    async with session_scope() as s:
        doc = await component_definition(
            sys_id, session=s, principal=_principal(owner_org, "insider-compdef")
        )
        assert "component-definition" in doc  # the owning org is not locked out

        with pytest.raises(HTTPException) as excinfo:
            await component_definition(
                sys_id, session=s, principal=_principal(other_org, "outsider-compdef")
            )
        assert excinfo.value.status_code == 404


@pytest.mark.asyncio
async def test_ssp_export_org_check_rejects_a_foreign_principal_without_rls() -> None:
    owner_org, sys_id = await _make_org_system("BuildersSspExportOwnerOrg")
    other_org, _other_sys = await _make_org_system("BuildersSspExportOtherOrg")
    async with session_scope() as s:
        proj = SSPProject(
            organization_id=owner_org,
            system_id=sys_id,
            customer_name="BuildersSspExportCo",
            system_name="BuildersSspExportSys",
        )
        s.add(proj)
        await s.flush()
        proj_id = proj.id

    async with session_scope() as s:
        doc = await ssp_export(proj_id, session=s, principal=_principal(owner_org, "insider-ssp"))
        assert "system-security-plan" in doc

        with pytest.raises(HTTPException) as excinfo:
            await ssp_export(proj_id, session=s, principal=_principal(other_org, "outsider-ssp"))
        assert excinfo.value.status_code == 404


@pytest.mark.asyncio
async def test_poam_export_org_check_rejects_a_foreign_principal_without_rls() -> None:
    owner_org, sys_id = await _make_org_system("BuildersPoamExportOwnerOrg")
    other_org, _other_sys = await _make_org_system("BuildersPoamExportOtherOrg")

    async with session_scope() as s:
        doc = await poam_export(sys_id, session=s, principal=_principal(owner_org, "insider-poam"))
        assert "plan-of-action-and-milestones" in doc

        with pytest.raises(HTTPException) as excinfo:
            await poam_export(sys_id, session=s, principal=_principal(other_org, "outsider-poam"))
        assert excinfo.value.status_code == 404


@pytest.mark.asyncio
async def test_sar_export_latest_org_check_rejects_a_foreign_principal_without_rls() -> None:
    owner_org, sys_id = await _make_org_system("BuildersSarLatestOwnerOrg")
    other_org, _other_sys = await _make_org_system("BuildersSarLatestOtherOrg")
    async with session_scope() as s:
        s.add(
            Assessment(
                system_id=sys_id,
                name="BuildersSarLatest assessment",
                kind="internal",
                assessor="Jane 3PAO",
            )
        )
        await s.flush()

    async with session_scope() as s:
        doc = await sar_export_latest(
            sys_id, session=s, principal=_principal(owner_org, "insider-sarlatest")
        )
        assert "assessment-results" in doc

        with pytest.raises(HTTPException) as excinfo:
            await sar_export_latest(
                sys_id, session=s, principal=_principal(other_org, "outsider-sarlatest")
            )
        # 404 "system not found", not the route's later "no assessment found"
        # — the org check must fire before the system is ever read from.
        assert excinfo.value.status_code == 404
