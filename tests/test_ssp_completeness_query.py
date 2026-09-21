"""Characterization of ``GET /api/ssp/projects/{id}/completeness``.

The ~80 lines that gather ``ccf.ssp.completeness.assess``'s real inputs from
the database used to live only inside the route handler. Before extracting
them into a reusable, DB-backed service this module pins the endpoint's
*entire* response body — every field ``assess`` returns — for three shapes of
project:

* one **with** a linked ``System`` carrying a real boundary inventory, real
  ``ScoringControl`` ODP definitions, and real ``ControlImplementation`` ->
  ``Evidence`` linkage;
* one **without** a ``system_id`` at all (``boundary`` is ``None``, and the
  evidence join is skipped entirely);
* one whose ``system_id`` points at a **deleted** ``System`` row — the case
  ``api/routes/ssp.py`` comments on: nothing to reconcile against, so the
  categorization check must not be held against the SSP.

The fixtures are deliberately mid-range: each project scores strictly between
0 and 100 with a non-empty ``control_gaps`` list, several ``missing_sections``
and a partially-filled ``odp_summary``. A characterization test over a
degenerate fixture proves nothing.

``control_gaps`` is compared with the entries sorted by ``control_id``: the
completeness query issues its ``SSPControlEntry`` select with no ``ORDER BY``
(unlike ``GET /projects/{id}``, which orders by ``sort_order``), so the row
order Postgres happens to return is not part of the contract. Everything else
is compared by exact equality.
"""

from __future__ import annotations

from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import (
    Control,
    ControlImplementation,
    Evidence,
    InformationType,
    Interconnection,
    Organization,
    ScoringControl,
    SSPControlEntry,
    SSPProject,
    System,
    SystemComponent,
)

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


# A private control-id namespace so this module's ScoringControl rows (the ODP
# map the query builds is a GLOBAL select over scoring_controls) can never
# collide with, or be perturbed by, the real CMMC catalog another test module
# may have seeded into the shared database.
_NS = "ZZC"
_C1 = f"{_NS}.L2-9.9.1"  # complete, evidenced
_C2 = f"{_NS}.L2-9.9.2"  # [DRAFT]-marked narrative
_C3 = f"{_NS}.L2-9.9.3"  # "Implemented" with an implementation but no evidence
_C4 = f"{_NS}.L2-9.9.4"  # ODP placeholder narrative + one unfilled ODP
_C5 = f"{_NS}.L2-9.9.5"  # empty entry: no narrative/role/status/origination
_C6 = f"{_NS}.L2-9.9.6"  # complete, evidenced, ODP filled

# Front matter that is deliberately PARTIAL: System Owner named, ISSO and
# Authorizing Official missing -> 4 of 6 REQUIRED_METADATA present.
_PARTIAL_META: dict[str, Any] = {
    "system_type": "Cloud information system (CUI)",
    "fips199": {"overall": "moderate"},
    "authorization_boundary": "The tenant and its managed services.",
    "roles": {"system_owner": {"name": "Dana Owner"}},
}


def _entry(project_id: int, control_id: str, sort_order: int, **kw: Any) -> SSPControlEntry:
    return SSPControlEntry(
        project_id=project_id,
        control_id=control_id,
        nist_id="3.1.1",
        domain=_NS,
        title=f"Characterization control {control_id}",
        requirement="The organization does the thing.",
        sort_order=sort_order,
        **kw,
    )


async def _seed() -> dict[str, int]:
    """Seed org, system, boundary inventory, ODP definitions, evidence linkage
    and the three SSP projects. Returns the ids the tests and teardown need."""
    async with session_scope() as s:
        org = Organization(name="SSP Completeness Characterization Org")
        s.add(org)
        await s.flush()

        sysrow = System(
            organization_id=org.id,
            name="Characterization System",
            fips199_confidentiality="moderate",
        )
        s.add(sysrow)
        await s.flush()

        # Boundary: 2 components, 1 information type whose rollup agrees with
        # the system's FIPS-199 triad (so categorization reconciles), and 2
        # interconnections of which exactly 1 carries an agreement.
        s.add_all(
            [
                SystemComponent(
                    organization_id=org.id, system_id=sysrow.id, type="software", title="API"
                ),
                SystemComponent(
                    organization_id=org.id, system_id=sysrow.id, type="service", title="Queue"
                ),
                InformationType(
                    organization_id=org.id,
                    system_id=sysrow.id,
                    title="Contact Information",
                    confidentiality_impact="moderate",
                ),
                Interconnection(
                    organization_id=org.id,
                    system_id=sysrow.id,
                    remote_system_name="Partner With Agreement",
                    direction="bidirectional",
                    agreement_type="isa",
                    agreement_ref="ISA-2026-01",
                ),
                Interconnection(
                    organization_id=org.id,
                    system_id=sysrow.id,
                    remote_system_name="Partner Without Agreement",
                    direction="bidirectional",
                    agreement_type="none",
                    agreement_ref=None,
                ),
            ]
        )

        # ODP definitions live on ScoringControl, keyed by control_id.
        s.add_all(
            [
                ScoringControl(
                    control_id=_C4,
                    domain=_NS,
                    point_value="5",
                    title="Needs a frequency",
                    odp_definitions=[{"key": "freq", "label": "review frequency"}],
                ),
                ScoringControl(
                    control_id=_C6,
                    domain=_NS,
                    point_value="3",
                    title="Has a filled parameter",
                    odp_definitions=[{"key": "k1", "label": "retention window"}],
                ),
            ]
        )

        # Real catalog controls + implementations; only _C1 and _C6 get Evidence.
        controls = {
            cid: Control(identifier=cid, control_name=f"Characterization {cid}")
            for cid in (_C1, _C3, _C6)
        }
        s.add_all(controls.values())
        await s.flush()

        impls = {
            cid: ControlImplementation(
                system_id=sysrow.id, control_id=controls[cid].id, status="implemented"
            )
            for cid in (_C1, _C3, _C6)
        }
        s.add_all(impls.values())
        await s.flush()

        s.add_all(
            [
                Evidence(
                    implementation_id=impls[_C1].id,
                    kind="config_export",
                    title="MFA configuration export",
                ),
                Evidence(
                    implementation_id=impls[_C6].id,
                    kind="document",
                    title="Retention policy",
                ),
            ]
        )

        linked = SSPProject(
            organization_id=org.id,
            system_id=sysrow.id,
            customer_name="Characterization Co",
            system_name="Characterization System",
            metadata_json=_PARTIAL_META,
        )
        unlinked = SSPProject(
            organization_id=org.id,
            system_id=None,
            customer_name="Characterization Co (no system)",
            metadata_json=_PARTIAL_META,
        )
        dangling = SSPProject(
            organization_id=org.id,
            system_id=sysrow.id,  # repointed at a deleted id below
            customer_name="Characterization Co (deleted system)",
            metadata_json=_PARTIAL_META,
        )
        s.add_all([linked, unlinked, dangling])
        await s.flush()

        s.add_all(
            [
                # Complete: real narrative, named role, status backed by real
                # Evidence through the ControlImplementation join.
                _entry(
                    linked.id,
                    _C1,
                    1,
                    responsible_role="Dana Owner, System Owner",
                    implementation_status=["Implemented"],
                    control_origination=["Service Provider Corporate"],
                    part_narratives=[{"part": "a", "text": "The system enforces MFA."}],
                    odp_values={},
                ),
                # Narrative still carries the auto-composer's [DRAFT] marker.
                _entry(
                    linked.id,
                    _C2,
                    2,
                    responsible_role="Dana Owner, System Owner",
                    implementation_status=["Planned"],
                    control_origination=["Service Provider System Specific"],
                    part_narratives=[{"part": "a", "text": "[DRAFT] Sessions time out."}],
                    odp_values={},
                ),
                # Claims Implemented; has a ControlImplementation but no Evidence.
                _entry(
                    linked.id,
                    _C3,
                    3,
                    responsible_role="Dana Owner, System Owner",
                    implementation_status=["Implemented"],
                    control_origination=["Inherited"],
                    part_narratives=[{"part": "a", "text": "Audit records are retained."}],
                    odp_values={},
                ),
                # Unresolved ODP placeholder in the text AND an unfilled slot.
                _entry(
                    linked.id,
                    _C4,
                    4,
                    responsible_role="Dana Owner, System Owner",
                    implementation_status=["Planned"],
                    control_origination=["Inherited"],
                    part_narratives=[
                        {
                            "part": "a",
                            "text": "Reviews occur [Assignment: organization-defined frequency].",
                        }
                    ],
                    odp_values={"freq": None},
                ),
                # Entirely empty entry -> all four non-ODP gaps.
                _entry(
                    linked.id,
                    _C5,
                    5,
                    responsible_role=None,
                    implementation_status=[],
                    control_origination=[],
                    part_narratives=[],
                    odp_values={"window": "30 days"},
                ),
                # Complete, evidenced, with its ODP slot filled.
                _entry(
                    linked.id,
                    _C6,
                    6,
                    responsible_role="Dana Owner, System Owner",
                    implementation_status=["Partially Implemented"],
                    control_origination=["Configured by Customer"],
                    part_narratives=[{"part": "a", "text": "Records are kept for a year."}],
                    odp_values={"k1": "weekly"},
                ),
                # --- project with no system_id ---
                _entry(
                    unlinked.id,
                    _C1,
                    1,
                    responsible_role="Dana Owner, System Owner",
                    implementation_status=["Planned"],
                    control_origination=["Inherited"],
                    part_narratives=[{"part": "a", "text": "The system enforces MFA."}],
                    odp_values={"k1": "weekly"},
                ),
                # Even though _C3's system has no Evidence and _C1's does, the
                # evidence join is skipped wholesale when system_id is None --
                # so this "Implemented" entry is flagged regardless.
                _entry(
                    unlinked.id,
                    _C3,
                    2,
                    responsible_role="Dana Owner, System Owner",
                    implementation_status=["Implemented"],
                    control_origination=["Inherited"],
                    part_narratives=[{"part": "a", "text": "Audit records are retained."}],
                    odp_values={},
                ),
                # --- project whose system_id points at a deleted System ---
                _entry(
                    dangling.id,
                    _C1,
                    1,
                    responsible_role="Dana Owner, System Owner",
                    implementation_status=["Planned"],
                    control_origination=["Inherited"],
                    part_narratives=[{"part": "a", "text": "The system enforces MFA."}],
                    odp_values={"k1": "weekly"},
                ),
                _entry(
                    dangling.id,
                    _C3,
                    2,
                    responsible_role="Dana Owner, System Owner",
                    implementation_status=["Implemented"],
                    control_origination=["Inherited"],
                    part_narratives=[{"part": "a", "text": "Audit records are retained."}],
                    odp_values={},
                ),
            ]
        )
        await s.flush()

        ids = {
            "org": org.id,
            "system": sysrow.id,
            "linked": linked.id,
            "unlinked": unlinked.id,
            "dangling": dangling.id,
        }

    # A System deleted out from under a project SET NULLs ``system_id``, so the
    # dangling state the route guards against is not reachable through an
    # ordinary DELETE. Reproduce it exactly: point the project at an id no
    # System row has, with the FK trigger suppressed for this statement only
    # (``SET LOCAL`` reverts on commit).
    async with session_scope() as s:
        missing = (
            await s.execute(text("SELECT COALESCE(MAX(id), 0) + 100000 FROM ccf.systems"))
        ).scalar_one()
        await s.execute(text("SET LOCAL session_replication_role = 'replica'"))
        await s.execute(
            text("UPDATE ccf.ssp_projects SET system_id = :sid WHERE id = :pid"),
            {"sid": missing, "pid": ids["dangling"]},
        )
    ids["missing_system"] = int(missing)
    return ids


async def _cleanup(ids: dict[str, int]) -> None:
    async with session_scope() as s:
        await s.execute(
            text("DELETE FROM ccf.ssp_projects WHERE organization_id = :o"),
            {"o": ids["org"]},
        )
        await s.execute(
            text("DELETE FROM ccf.scoring_controls WHERE control_id LIKE :p"),
            {"p": f"{_NS}.%"},
        )
        await s.execute(
            text("DELETE FROM ccf.systems WHERE id = :s"), {"s": ids["system"]}
        )
        await s.execute(
            text("DELETE FROM ccf.controls WHERE identifier LIKE :p"), {"p": f"{_NS}.%"}
        )
        await s.execute(
            text("DELETE FROM ccf.organizations WHERE id = :o"), {"o": ids["org"]}
        )


def _normalize(body: dict[str, Any]) -> dict[str, Any]:
    """Sort ``control_gaps`` by control_id -- the underlying select has no
    ORDER BY, so row order is not part of the observable contract."""
    return {
        **body,
        "control_gaps": sorted(body["control_gaps"], key=lambda g: g["control_id"]),
    }


# --------------------------------------------------------------------------
# The pinned responses.
# --------------------------------------------------------------------------

# 6 controls, 2 complete (_C1, _C6) -> control_pct = 1/3.
# Front matter 4/6 present; boundary 3 of 4 checks pass (1 of 2 interconnections
# lacks an agreement) -> section_pct = (4/6 + 3/4) / 2.
# ODPs: 3 scaffolded, 1 unset -> section_pct = (that + 2/3) / 2 = 0.6875.
# score = 100 * (0.8 * 1/3 + 0.2 * 0.6875) = 40.4 (rounded to 1dp).
_EXPECTED_LINKED: dict[str, Any] = {
    "score": 40.4,
    "ready": False,
    "controls_total": 6,
    "controls_complete": 2,
    "missing_sections": [
        "ISSO",
        "Authorizing Official",
        "1 of 2 interconnections lack an agreement",
        "1 of 3 organization-defined parameters (ODPs) unset",
    ],
    "control_gaps": [
        {"control_id": _C2, "gaps": ["draft narrative — needs review"]},
        {"control_id": _C3, "gaps": ["implemented without evidence"]},
        {
            "control_id": _C4,
            "gaps": ["draft narrative — needs review", "1 unfilled parameter(s)"],
        },
        {
            "control_id": _C5,
            "gaps": [
                "no implementation narrative",
                "no responsible role",
                "no implementation status",
                "no control origination",
            ],
        },
    ],
    "odp_summary": {"total": 3, "unset": 1},
}

# 2 controls, 1 complete -> control_pct = 0.5. boundary is None, so section_pct
# is the bare front-matter ratio 4/6. One ODP, filled -> the ODP dimension is
# inert. score = 100 * (0.8 * 0.5 + 0.2 * 4/6) = 53.3.
_EXPECTED_UNLINKED: dict[str, Any] = {
    "score": 53.3,
    "ready": False,
    "controls_total": 2,
    "controls_complete": 1,
    "missing_sections": ["ISSO", "Authorizing Official"],
    "control_gaps": [{"control_id": _C3, "gaps": ["implemented without evidence"]}],
    "odp_summary": {"total": 1, "unset": 0},
}

# Same two entries, but system_id points at a row that no longer exists: the
# boundary summary comes back empty (0 components, 0 info types, 0
# interconnections) and -- the behaviour ssp.py comments on -- the missing
# System row means categorization_reconciles stays True rather than being held
# against the SSP. boundary_pct = 2/4; section_pct = (4/6 + 0.5) / 2.
# score = 100 * (0.8 * 0.5 + 0.2 * 0.58333...) = 51.7.
_EXPECTED_DANGLING: dict[str, Any] = {
    "score": 51.7,
    "ready": False,
    "controls_total": 2,
    "controls_complete": 1,
    "missing_sections": [
        "ISSO",
        "Authorizing Official",
        "No boundary components defined",
        "No information types categorized",
    ],
    "control_gaps": [{"control_id": _C3, "gaps": ["implemented without evidence"]}],
    "odp_summary": {"total": 1, "unset": 0},
}


@pytest.mark.asyncio
async def test_completeness_endpoint_response_is_pinned() -> None:
    """Record the whole response body for all three project shapes."""
    ids = await _seed()
    try:
        transport = ASGITransport(app=create_app())
        async with AsyncClient(transport=transport, base_url="http://t") as c:
            linked = await c.get(f"/api/ssp/projects/{ids['linked']}/completeness")
            unlinked = await c.get(f"/api/ssp/projects/{ids['unlinked']}/completeness")
            dangling = await c.get(f"/api/ssp/projects/{ids['dangling']}/completeness")

        assert linked.status_code == 200, linked.text
        assert unlinked.status_code == 200, unlinked.text
        assert dangling.status_code == 200, dangling.text

        assert _normalize(linked.json()) == _EXPECTED_LINKED
        assert _normalize(unlinked.json()) == _EXPECTED_UNLINKED
        assert _normalize(dangling.json()) == _EXPECTED_DANGLING
    finally:
        await _cleanup(ids)
