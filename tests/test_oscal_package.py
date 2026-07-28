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

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import POAM, Assessment, Organization, SSPProject, System, User
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
