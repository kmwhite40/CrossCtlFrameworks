"""Tests for the OSCAL authorization-package ZIP bundle (Keystone #3, Task 3).

Mirrors ``tests/test_ato.py`` for DB setup (``session_scope``/``fresh_engine``,
module-scoped Alembic migration) and ``tests/test_oscal_sar.py`` for hitting
the route and validating the resulting documents.
"""

from __future__ import annotations

import io
import json
import os
import zipfile
from datetime import date, timedelta

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
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
    User,
)
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
        sysrow = System(organization_id=org.id, name=f"{name} system")
        s.add(sysrow)
        await s.flush()
        return org.id, sysrow.id


@pytest.mark.asyncio
async def test_package_export_populated_system_returns_all_artifacts() -> None:
    org_id, sys_id = await _make_org_system("Package Golden Org")
    async with session_scope() as s:
        s.add(
            SSPProject(
                organization_id=org_id,
                system_id=sys_id,
                customer_name="Package Golden Co",
                system_name="Package Golden Sys",
            )
        )
        s.add(
            Assessment(
                system_id=sys_id,
                name="Package Golden internal assessment",
                kind="internal",
                assessor="Jane 3PAO",
                started_on=date.today() - timedelta(days=10),
                finished_on=date.today(),
                summary="Internal control assessment.",
            )
        )
        s.add(
            POAM(
                system_id=sys_id,
                title="Audit log gaps",
                weakness="Audit events are not fully enumerated.",
                severity="moderate",
                status="open",
            )
        )
        await s.flush()

    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        resp = await c.get(f"/api/oscal/package/{sys_id}")

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/zip")
    assert resp.content[:2] == b"PK"

    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    names = set(zf.namelist())
    assert names >= {
        "ssp.json",
        "sar.json",
        "poam.json",
        "component-definition.json",
        "README.txt",
    }

    for name in ("ssp.json", "sar.json", "poam.json", "component-definition.json"):
        doc = json.loads(zf.read(name))
        report = validate_document(doc)
        assert report.ok, (name, report.errors)

    # This fixture's assessment has no AssessmentResult rows, so the plan Concord
    # would derive reviews nothing. `_import_ap` already refuses to cite such a
    # plan from the SAR for exactly that reason; bundling it here would put a
    # document asserting an empty assessment scope into an authorization package.
    assert "sap.json" not in names
    readme = zf.read("README.txt").decode()
    assert "sap.json: ABSENT" in readme
    assert "no recorded control coverage" in readme


@pytest.mark.asyncio
async def test_package_export_sparse_system_omits_ssp_and_sar() -> None:
    _org_id, sys_id = await _make_org_system("Package Sparse Org")

    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        resp = await c.get(f"/api/oscal/package/{sys_id}")

    assert resp.status_code == 200
    assert resp.content[:2] == b"PK"

    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    names = set(zf.namelist())
    assert "component-definition.json" in names
    assert "README.txt" in names
    assert "ssp.json" not in names
    assert "sar.json" not in names
    # A clean system with zero open POA&Ms MUST NOT bundle a poam.json: an empty
    # poam-items array is OSCAL-invalid (minItems 1). It's omitted + noted instead,
    # so the package never presents a non-conformant member as valid.
    assert "poam.json" not in names

    # Every bundled member must validate.
    doc = json.loads(zf.read("component-definition.json"))
    report = validate_document(doc)
    assert report.ok, report.errors

    readme = zf.read("README.txt").decode()
    assert "ssp.json: ABSENT" in readme
    assert "sar.json: ABSENT" in readme
    assert "poam.json: ABSENT" in readme


@pytest.mark.asyncio
async def test_package_export_out_of_org_is_404() -> None:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    try:
        _org_id, sys_id = await _make_org_system("Package Owner Org")

        async with session_scope() as s:
            other_org = Organization(name="Package Other Org")
            s.add(other_org)
            await s.flush()
            outsider = User(
                email="outsider@package-other.test",
                organization_id=other_org.id,
                role="admin",
                active=True,
                password_hash=hash_password("pw"),
                api_token=new_api_token(),
            )
            s.add(outsider)
            await s.flush()
            token = outsider.api_token

        transport = ASGITransport(app=create_app())
        async with AsyncClient(transport=transport, base_url="http://t") as c:
            r = await c.get(
                f"/api/oscal/package/{sys_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert r.status_code == 404

            r_anon = await c.get(f"/api/oscal/package/{sys_id}")
            assert r_anon.status_code == 401
    finally:
        os.environ.pop("CCF_AUTH_ENABLED", None)
        os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_package_route_org_check_rejects_a_foreign_principal_without_rls() -> None:
    """The route's OWN org check, exercised at its own layer.

    ``test_package_export_out_of_org_is_404`` above asserts the right
    end-to-end result, but it cannot fail when only the route's explicit org
    check is removed: ``ccf.systems`` carries a ``tenant_isolation`` RLS
    policy, so the outsider's request 404s at the query first (confirmed by
    mutation -- deleting the check left that test passing). RLS is documented
    in ``ccf.api.deps.get_session`` as a backstop *beneath* the app-layer
    scoping, so the app-layer scoping is pinned here with the RLS backstop out
    of the way: an unscoped ``session_scope`` session plus a principal from
    another organization. Mirrors
    ``test_oscal_sar.py::test_sar_route_org_check_rejects_a_foreign_principal_without_rls``.
    """
    from fastapi import HTTPException  # noqa: PLC0415

    from ccf.api.routes.oscal import package_export  # noqa: PLC0415
    from ccf.auth import Principal  # noqa: PLC0415

    owner_org_id, sys_id = await _make_org_system("Package Layer Owner Org")
    other_org_id, _other_sys_id = await _make_org_system("Package Layer Other Org")

    async with session_scope() as s:
        insider = Principal(
            user_id=None, email="insider@package-layer.test", org_id=owner_org_id, role="admin"
        )
        resp = await package_export(sys_id, session=s, principal=insider)
        assert resp.media_type == "application/zip"  # the owning org still gets its package

        outsider = Principal(
            user_id=None, email="outsider@package-layer.test", org_id=other_org_id, role="admin"
        )
        with pytest.raises(HTTPException) as excinfo:
            await package_export(sys_id, session=s, principal=outsider)
        assert excinfo.value.status_code == 404


async def _assessment_with_recorded_coverage(org_name: str) -> int:
    """A system whose assessment actually covers controls, so a plan has scope."""
    async with session_scope() as s:
        org = Organization(name=org_name)
        s.add(org)
        await s.flush()
        sysrow = System(organization_id=org.id, name=f"{org_name} system")
        s.add(sysrow)
        await s.flush()
        s.add(
            SSPProject(
                organization_id=org.id,
                system_id=sysrow.id,
                customer_name=f"{org_name} Co",
                system_name=f"{org_name} Sys",
            )
        )

        # Control.identifier is globally unique, so get-or-create rather than
        # insert: eleven other modules seed this same family.
        impls = []
        for identifier in ("AC-2", "AU-2"):
            ctrl = (
                await s.execute(select(Control).where(Control.identifier == identifier))
            ).scalar_one_or_none()
            if ctrl is None:
                ctrl = Control(identifier=identifier, control_name=f"{identifier} control title")
                s.add(ctrl)
                await s.flush()
            impl = ControlImplementation(
                system_id=sysrow.id, control_id=ctrl.id, status="implemented"
            )
            s.add(impl)
            await s.flush()
            impls.append(impl)

        assessment = Assessment(
            system_id=sysrow.id,
            name=f"{org_name} internal assessment",
            kind="internal",
            assessor="Jane 3PAO",
            started_on=date.today() - timedelta(days=10),
            finished_on=date.today(),
            summary="Internal control assessment.",
        )
        s.add(assessment)
        await s.flush()
        for impl, finding in zip(impls, ("satisfied", "other_than_satisfied"), strict=True):
            s.add(
                AssessmentResult(
                    assessment_id=assessment.id,
                    implementation_id=impl.id,
                    finding=finding,
                    rationale=f"{finding} rationale",
                    observed_on=date.today(),
                )
            )
        await s.flush()
        return sysrow.id


@pytest.mark.asyncio
async def test_package_bundles_the_assessment_plan_when_the_assessment_has_scope() -> None:
    """The SAP is the one FedRAMP core artifact the package never carried.

    It has been built and schema-validated since the SAR shipped, and served at
    its own route, but `build_package_zip` wrote SSP, SAR, POA&M and
    component-definition and stopped -- so the downloadable authorization
    package was missing a document a reviewer expects to find in it.
    """
    sys_id = await _assessment_with_recorded_coverage("Package Plan Org")

    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        resp = await c.get(f"/api/oscal/package/{sys_id}")

    assert resp.status_code == 200
    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    names = set(zf.namelist())
    assert "sap.json" in names, sorted(names)

    doc = json.loads(zf.read("sap.json"))
    report = validate_document(doc)
    assert report.ok, report.errors

    # It must be a plan with a scope, not an empty one that merely validates.
    selections = doc["assessment-plan"]["reviewed-controls"]["control-selections"]
    assert selections[0].get("include-controls"), selections

    readme = zf.read("README.txt").decode()
    assert "sap.json: present" in readme
    # The manifest sentence names the members; it must not keep listing four.
    assert "SAP" in readme
