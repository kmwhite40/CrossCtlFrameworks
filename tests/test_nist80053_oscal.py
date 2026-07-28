"""OSCAL SSP export for NIST 800-53r5 projects — canonical control-ids and
set-parameters (Task 6 of the NIST 800-53r5 SSP pipeline).

``implemented-requirements[].control-id`` must be the lowercase, dotted OSCAL
form (``"ac-2"``, not the canonical ``"AC-2"``) for 800-53r5 projects, and
filled organization-defined parameters must surface as ``set-parameters`` —
while CMMC projects keep their existing verbatim ``control-id`` with no
``set-parameters`` at all.
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.catalog.canonical import canonical_to_oscal_id
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, SSPControlEntry, SSPProject, System
from ccf.oscal import validate_document

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _make_org_system(name: str) -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        sysrow = System(organization_id=org.id, name=f"{name} system", baseline="moderate")
        s.add(sysrow)
        await s.flush()
        return org.id, sysrow.id


# --- canonical_to_oscal_id -----------------------------------------------


def test_canonical_to_oscal_id() -> None:
    assert canonical_to_oscal_id("AC-2") == "ac-2"
    assert canonical_to_oscal_id("AC-2(1)") == "ac-2.1"
    assert canonical_to_oscal_id("AC-2(1)(2)") == "ac-2.1.2"
    assert canonical_to_oscal_id("SC-7") == "sc-7"


# --- 800-53r5 SSP export ---------------------------------------------------


@pytest.mark.asyncio
async def test_ssp_export_800_53_uses_canonical_control_id_and_set_parameters() -> None:
    org_id, sys_id = await _make_org_system("Nist80053Org")
    async with session_scope() as s:
        proj = SSPProject(
            organization_id=org_id,
            system_id=sys_id,
            customer_name="Nist80053Co",
            system_name="Nist80053Sys",
            framework="nist-800-53r5",
        )
        s.add(proj)
        await s.flush()
        pid = proj.id
        s.add(
            SSPControlEntry(
                project_id=pid,
                control_id="AC-2",
                domain="AC",
                title="Account Management",
                odp_values={"ac-02_odp.01": "24 hours", "ac-02_odp.02": None},
                part_narratives=[{"label": "", "text": "Accounts are managed per policy."}],
                sort_order=1,
            )
        )
        s.add(
            SSPControlEntry(
                project_id=pid,
                control_id="SC-7",
                domain="SC",
                title="Boundary Protection",
                odp_values={},
                part_narratives=[{"label": "", "text": "Boundary protection is enforced."}],
                sort_order=2,
            )
        )
        await s.flush()

    async with _client() as c:
        doc = (await c.get(f"/api/oscal/ssp/{pid}")).json()

    reqs = doc["system-security-plan"]["control-implementation"]["implemented-requirements"]
    ac2 = next(r for r in reqs if r["control-id"] == "ac-2")
    assert {"param-id": "ac-02_odp.01", "values": ["24 hours"]} in ac2["set-parameters"]
    assert not any(sp["param-id"] == "ac-02_odp.02" for sp in ac2["set-parameters"])

    sc7 = next(r for r in reqs if r["control-id"] == "sc-7")
    assert "set-parameters" not in sc7  # no filled ODPs -> key omitted entirely

    report = validate_document(doc)
    assert report.ok, report.errors


@pytest.mark.asyncio
async def test_ssp_export_cmmc_keeps_verbatim_control_id_no_set_parameters() -> None:
    """Regression: non-800-53 (default CMMC) projects are unaffected — the
    control-id stays verbatim and no set-parameters key is added."""
    org_id, sys_id = await _make_org_system("CmmcOrg")
    async with session_scope() as s:
        proj = SSPProject(
            organization_id=org_id,
            system_id=sys_id,
            customer_name="CmmcCo",
            system_name="CmmcSys",
        )
        s.add(proj)
        await s.flush()
        pid = proj.id
        s.add(
            SSPControlEntry(
                project_id=pid,
                control_id="AC.L2-3.1.1",
                domain="AC",
                title="Limit access",
                odp_values={"some_odp": "value"},
                part_narratives=[{"label": "", "text": "Access is limited."}],
                sort_order=1,
            )
        )
        await s.flush()

    async with _client() as c:
        doc = (await c.get(f"/api/oscal/ssp/{pid}")).json()

    reqs = doc["system-security-plan"]["control-implementation"]["implemented-requirements"]
    req = next(iter(reqs))
    assert req["control-id"] == "AC.L2-3.1.1"
    assert "set-parameters" not in req
