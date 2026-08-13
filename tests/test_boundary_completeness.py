"""SSP completeness scoring — boundary section (Task 5).

The ``assess`` unit tests below are pure (no DB): they call
``ccf.ssp.completeness.assess`` directly with a hand-built ``boundary`` dict,
mirroring ``tests/test_ssp_completeness.py``'s style. One DB-backed test
verifies the ``/api/ssp/projects/{id}/completeness`` caller in
``ccf/api/routes/ssp.py`` actually builds that dict from the real boundary
inventory (mirrors ``tests/test_ato.py``'s setup pattern).
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import (
    InformationType,
    Interconnection,
    Organization,
    SSPProject,
    System,
    SystemComponent,
)
from ccf.ssp.completeness import assess

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

_GOOD_ENTRY = dict(
    control_id="AC.L2-3.1.1",
    part_narratives=[{"text": "The organization does X."}],
    responsible_role="System Owner",
    implementation_status=["Implemented"],
    control_origination=["Inherited"],
    odp_definitions=[],
    odp_values={},
    evidence_ref="s3://evidence/default-config-export.pdf",
)

_FULL_BOUNDARY = {
    "components": 3,
    "info_types": 2,
    "categorization_reconciles": True,
    "interconnections_with_agreements": (2, 2),
}


# --------------------------------------------------------------------------
# Pure `assess()` unit tests
# --------------------------------------------------------------------------


def test_boundary_none_is_unchanged_backward_compatible_behavior() -> None:
    r = assess(_FULL_META, [_GOOD_ENTRY])
    assert r["score"] == 100.0
    assert r["missing_sections"] == []
    assert r["ready"] is True


def test_full_boundary_adds_no_gaps_and_does_not_lower_score() -> None:
    no_boundary = assess(_FULL_META, [_GOOD_ENTRY])
    with_boundary = assess(_FULL_META, [_GOOD_ENTRY], boundary=_FULL_BOUNDARY)

    assert with_boundary["missing_sections"] == []
    assert with_boundary["score"] >= no_boundary["score"]
    assert with_boundary["score"] == 100.0
    assert with_boundary["ready"] is True


def test_zero_components_adds_boundary_gap_and_lowers_score() -> None:
    boundary = dict(_FULL_BOUNDARY, components=0)
    r = assess(_FULL_META, [_GOOD_ENTRY], boundary=boundary)
    assert "No boundary components defined" in r["missing_sections"]
    assert r["ready"] is False
    assert r["score"] < 100.0


def test_zero_info_types_adds_boundary_gap() -> None:
    boundary = dict(_FULL_BOUNDARY, info_types=0)
    r = assess(_FULL_META, [_GOOD_ENTRY], boundary=boundary)
    assert "No information types categorized" in r["missing_sections"]
    assert r["ready"] is False


def test_categorization_mismatch_adds_reconcile_gap() -> None:
    boundary = dict(_FULL_BOUNDARY, categorization_reconciles=False)
    r = assess(_FULL_META, [_GOOD_ENTRY], boundary=boundary)
    assert (
        "System categorization does not reconcile with information types"
        in r["missing_sections"]
    )
    assert r["ready"] is False


def test_interconnections_lacking_agreements_adds_gap_with_counts() -> None:
    boundary = dict(_FULL_BOUNDARY, interconnections_with_agreements=(1, 3))
    r = assess(_FULL_META, [_GOOD_ENTRY], boundary=boundary)
    assert "2 of 3 interconnections lack an agreement" in r["missing_sections"]
    assert r["ready"] is False


def test_zero_total_interconnections_does_not_add_gap() -> None:
    """No interconnections at all is not itself a gap — the agreement check
    only fires when there's something unfulfilled to flag."""
    boundary = dict(_FULL_BOUNDARY, interconnections_with_agreements=(0, 0))
    r = assess(_FULL_META, [_GOOD_ENTRY], boundary=boundary)
    assert not any("interconnections" in m for m in r["missing_sections"])


def test_control_weight_stays_dominant_with_a_fully_broken_boundary() -> None:
    """Even a maximally-failing boundary (all four checks fail) must not sink
    the score below what control completeness alone would allow — the blend
    keeps the 80% control weight dominant over the 20% section (front
    matter + boundary) weight."""
    broken_boundary = {
        "components": 0,
        "info_types": 0,
        "categorization_reconciles": False,
        "interconnections_with_agreements": (0, 5),
    }
    r = assess(_FULL_META, [_GOOD_ENTRY], boundary=broken_boundary)
    assert len(r["missing_sections"]) == 4
    # control_pct=1.0, section_pct = (1.0 + 0.0) / 2 = 0.5 -> 100*(0.8*1 + 0.2*0.5) = 90.0
    assert r["score"] == 90.0


# --------------------------------------------------------------------------
# DB-backed: verify the ssp.py caller actually builds the boundary dict
# --------------------------------------------------------------------------

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _make_org_system(name: str, **fips199: str) -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        sysrow = System(
            organization_id=org.id,
            name=f"{name} system",
            fips199_confidentiality=fips199.get("confidentiality"),
            fips199_integrity=fips199.get("integrity"),
            fips199_availability=fips199.get("availability"),
        )
        s.add(sysrow)
        await s.flush()
        return org.id, sysrow.id


@pytest.mark.asyncio
async def test_completeness_endpoint_reports_no_boundary_gap_for_populated_system() -> None:
    org_id, sys_id = await _make_org_system(
        "Boundary Completeness Org", confidentiality="moderate"
    )
    async with session_scope() as s:
        s.add(
            SystemComponent(
                organization_id=org_id, system_id=sys_id, type="software", title="API"
            )
        )
        s.add(
            InformationType(
                organization_id=org_id,
                system_id=sys_id,
                title="Contact Info",
                confidentiality_impact="moderate",
            )
        )
        s.add(
            Interconnection(
                organization_id=org_id,
                system_id=sys_id,
                remote_system_name="Partner System",
                direction="bidirectional",
                agreement_type="isa",
                agreement_ref="ISA-2026-01",
            )
        )
        proj = SSPProject(
            organization_id=org_id,
            system_id=sys_id,
            customer_name="Boundary Completeness Org",
            metadata_json=_FULL_META,
        )
        s.add(proj)
        await s.flush()
        proj_id = proj.id

    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.get(f"/api/ssp/projects/{proj_id}/completeness")
        assert r.status_code == 200
        body = r.json()
        assert not any("boundary" in m.lower() for m in body["missing_sections"])
        assert not any("interconnection" in m.lower() for m in body["missing_sections"])
        assert not any("categorization" in m.lower() for m in body["missing_sections"])


@pytest.mark.asyncio
async def test_completeness_endpoint_reports_boundary_gaps_for_empty_system() -> None:
    """A project linked to a system with no boundary inventory at all must
    surface the "no components"/"no information types" gaps end to end."""
    org_id, sys_id = await _make_org_system("Boundary Gap Org")
    async with session_scope() as s:
        proj = SSPProject(
            organization_id=org_id,
            system_id=sys_id,
            customer_name="Boundary Gap Org",
            metadata_json=_FULL_META,
        )
        s.add(proj)
        await s.flush()
        proj_id = proj.id

    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.get(f"/api/ssp/projects/{proj_id}/completeness")
        assert r.status_code == 200
        body = r.json()
        assert "No boundary components defined" in body["missing_sections"]
        assert "No information types categorized" in body["missing_sections"]


@pytest.mark.asyncio
async def test_completeness_endpoint_without_system_id_has_no_boundary_gaps() -> None:
    """A project with no linked system falls back to boundary=None — the
    original, backward-compatible behavior — never asserting boundary gaps."""
    org = Organization(name="No System Boundary Org")
    async with session_scope() as s:
        s.add(org)
        await s.flush()
        proj = SSPProject(
            organization_id=org.id,
            system_id=None,
            customer_name="No System Boundary Org",
            metadata_json=_FULL_META,
        )
        s.add(proj)
        await s.flush()
        proj_id = proj.id

    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.get(f"/api/ssp/projects/{proj_id}/completeness")
        assert r.status_code == 200
        body = r.json()
        assert not any("boundary" in m.lower() for m in body["missing_sections"])
        assert not any("information types" in m.lower() for m in body["missing_sections"])
