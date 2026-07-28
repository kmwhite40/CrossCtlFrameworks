"""SSP export conforms to the official NIST OSCAL v1.1.2 JSON Schema (Task 2 of
the official-OSCAL-validation program).

``build_ssp_doc`` must produce a schema-valid ``system-security-plan`` for both
supported frameworks — the default CMMC Level 2 path (``SSPProject.framework``
unset) and the NIST SP 800-53r5 path (``ccf.ssp.seed.seed_80053_project``) —
with ``validate_document(doc).mode == "official"`` (proving it actually ran
against the vendored NIST schema, not the structural fallback) and ``.ok``
True.
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.api.routes.oscal import build_ssp_doc
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, SSPProject, System
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


async def _make_org_system(name: str, **system_kwargs: object) -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        sysrow = System(organization_id=org.id, name=f"{name} system", **system_kwargs)
        s.add(sysrow)
        await s.flush()
        return org.id, sysrow.id


@pytest.mark.asyncio
async def test_cmmc_ssp_export_conforms_to_official_oscal_schema() -> None:
    """The default CMMC Level 2 SSP — 110 seeded control entries, NIST SP
    800-171 requirement numbers (e.g. "3.1.1") for ``nist_id`` — must be a
    schema-valid OSCAL SSP end to end, including the token-sanitized
    control-id/statement-id (leading-digit CMMC ids are not valid OSCAL
    tokens on their own)."""
    _org_id, sys_id = await _make_org_system("ConformanceCmmcOrg")
    async with _client() as c:
        assert (await c.post("/api/scoring/seed")).status_code == 200
        pid = (
            await c.post(
                "/api/ssp/projects",
                json={
                    "customer_name": "ConformanceCmmcCo",
                    "system_id": sys_id,
                    "system_name": "ConformanceCmmcSys",
                },
            )
        ).json()["id"]

    async with session_scope() as s:
        proj = await s.get(SSPProject, pid)
        assert proj is not None
        doc = await build_ssp_doc(s, proj)

    reqs = doc["system-security-plan"]["control-implementation"]["implemented-requirements"]
    assert len(reqs) == 110
    # A representative leading-digit CMMC nist_id ("3.1.1") must have been
    # sanitized into a valid OSCAL token, not dropped or left invalid.
    assert any(r["control-id"] == "_3.1.1" for r in reqs)

    report = validate_document(doc)
    assert report.mode == "official", report.as_dict()
    assert report.ok, report.errors


@pytest.mark.asyncio
async def test_nist80053_ssp_export_conforms_to_official_oscal_schema() -> None:
    """A NIST SP 800-53r5 SSP — controls seeded from the system's FIPS-199
    baseline via ``seed_80053_project`` — must also be schema-valid, with the
    canonical dotted control-ids (``ac-2``, ``ac-2.1``, ...) and any filled
    organization-defined parameters as ``set-parameters``."""
    org_id, sys_id = await _make_org_system("Conformance80053Org", baseline="moderate")
    async with session_scope() as s:
        proj = SSPProject(
            organization_id=org_id,
            system_id=sys_id,
            customer_name="Conformance80053Co",
            system_name="Conformance80053Sys",
            framework="nist-800-53r5",
        )
        s.add(proj)
        await s.flush()
        pid = proj.id
        inserted = await seed_80053_project(s, proj)
        assert inserted > 0

    async with session_scope() as s:
        reloaded = await s.get(SSPProject, pid)
        assert reloaded is not None
        doc = await build_ssp_doc(s, reloaded)

    reqs = doc["system-security-plan"]["control-implementation"]["implemented-requirements"]
    assert reqs
    assert any(r["control-id"] == "ac-2" for r in reqs)

    report = validate_document(doc)
    assert report.mode == "official", report.as_dict()
    assert report.ok, report.errors
