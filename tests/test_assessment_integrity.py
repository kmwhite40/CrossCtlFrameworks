"""Assessment integrity: defects found by holding Concord to the rules of
m365-docs-hub's Compliance Assessment page.

Nothing from that page's scoring was worth porting -- Concord's equivalents
are stronger -- but each of its rules pointed at a place Concord broke the
same rule: a partial implementation reported as unaddressed, a rejected
proposal that could be reopened and accepted, assessor work erased by a save
or an accept, a summary that defaulted a baseline and scored 0% over nothing,
an alert whose severity disagreed with the risk band.
"""

from __future__ import annotations

import itertools
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select

from ccf.analytics.framework_posture import framework_posture
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Control, ControlImplementation, Organization, System

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _moderate_system(session: Any, controls: list[str]) -> tuple[System, dict[str, int]]:
    """A Moderate system with the given catalog controls (Moderate implies High,
    so the shared catalog keeps nesting -- see test_attested_only_is_named)."""
    n = next(_SEQ)
    org = Organization(name=f"IntegrityOrg{n}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"IntegritySys{n}", baseline="moderate")
    session.add(sys_)
    await session.flush()
    ids: dict[str, int] = {}
    for identifier in controls:
        row = (
            await session.execute(select(Control).where(Control.identifier == identifier))
        ).scalars().first()
        if row is None:
            row = Control(identifier=identifier, sequence_control=identifier,
                          fisma_mod=True, fisma_high=True)
            session.add(row)
            await session.flush()
        else:
            row.fisma_mod = True
            row.fisma_high = True
        ids[identifier] = row.id
    await session.flush()
    return sys_, ids


@pytest.mark.asyncio
async def test_a_partial_implementation_is_documented_not_unaddressed() -> None:
    """``ADDRESSED_STATUSES`` named ``partially_implemented``, a status the enum
    does not have, so every partial implementation fell through to
    "unaddressed" on the 800-53 path while the 800-171 path counted it."""
    async with session_scope() as s:
        sys_, ids = await _moderate_system(s, ["AC-2", "AC-3"])
        s.add(ControlImplementation(system_id=sys_.id, control_id=ids["AC-2"], status="partial"))
        await s.flush()
        posture = await framework_posture(s, org_id=None, system_id=sys_.id)
    assert "AC-2" in posture["documented"]
    assert "AC-2" not in posture["unaddressed"]
    assert "AC-3" in posture["unaddressed"]


def test_every_status_the_posture_names_is_one_the_enum_has() -> None:
    """The class of the bug above, not the instance: a status set may only
    name values ``ControlImplementation.status`` can hold."""
    from ccf.analytics.framework_posture import ADDRESSED_STATUSES  # noqa: PLC0415

    enum_values = set(ControlImplementation.__table__.c.status.type.enums)
    assert set(ADDRESSED_STATUSES) <= enum_values, set(ADDRESSED_STATUSES) - enum_values


# --- the API save merges objective findings, as the page does ---------------


async def _result_with_projection() -> tuple[int, str]:
    from ccf.models import Assessment, AssessmentControlResult  # noqa: PLC0415

    async with session_scope() as s:
        n = next(_SEQ)
        org = Organization(name=f"IntegrityApiOrg{n}")
        s.add(org)
        await s.flush()
        sys_ = System(organization_id=org.id, name=f"IntegrityApiSys{n}")
        s.add(sys_)
        await s.flush()
        a = Assessment(system_id=sys_.id, name="A", kind="self")
        s.add(a)
        await s.flush()
        s.add(AssessmentControlResult(
            assessment_id=a.id, control_id="3.1.1", finding="satisfied",
            objective_findings=[
                {"label": "3.1.1[a]", "text": "users are identified", "finding": "satisfied",
                 "rationale": "the engine's reasoning", "cited_unit_ids": [7, 9],
                 "gaps": ["none"], "dissent": {"count": 0}},
                {"label": "3.1.1[b]", "text": "processes are identified",
                 "finding": "satisfied", "rationale": "kept"},
            ],
        ))
        await s.flush()
        return a.id, "3.1.1"


@pytest.mark.asyncio
async def test_a_put_changes_one_objective_and_keeps_the_rest_of_the_record() -> None:
    from httpx import ASGITransport, AsyncClient  # noqa: PLC0415

    from ccf.api.main import create_app  # noqa: PLC0415

    aid, cid = await _result_with_projection()
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        r = await c.put(
            f"/api/assessments/{aid}/controls/{cid}",
            json={"objective_findings": [{"label": "3.1.1[a]", "finding": "not_applicable"}]},
        )
        assert r.status_code == 200, r.text
        parts = {p["label"]: p for p in r.json()["objective_findings"]}
        bad = await c.put(
            f"/api/assessments/{aid}/controls/{cid}",
            json={"objective_findings": [{"label": "3.1.1[a]", "finding": "bogus"}]},
        )
        unknown = await c.put(
            f"/api/assessments/{aid}/controls/{cid}",
            json={"objective_findings": [{"label": "3.1.9[z]", "finding": "satisfied"}]},
        )
    a = parts["3.1.1[a]"]
    assert a["finding"] == "not_applicable"
    assert a["rationale"] == "the engine's reasoning" and a["cited_unit_ids"] == [7, 9]
    assert parts["3.1.1[b]"]["rationale"] == "kept"
    assert bad.status_code == 422 and unknown.status_code == 422


# --- the system summary: no assumed baseline, no number over nothing --------


@pytest.mark.asyncio
async def test_a_system_with_no_baseline_has_no_coverage_figure() -> None:
    from httpx import ASGITransport, AsyncClient  # noqa: PLC0415

    from ccf.api.main import create_app  # noqa: PLC0415

    async with session_scope() as s:
        org = Organization(name=f"IntegritySumOrg{next(_SEQ)}")
        s.add(org)
        await s.flush()
        sys_ = System(organization_id=org.id, name="no baseline")
        s.add(sys_)
        await s.flush()
        sid = sys_.id
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        body = (await c.get(f"/api/systems/{sid}/summary")).json()
    # It used to assume Moderate and report 0.0% coverage of it.
    assert body["baseline"] is None
    assert body["total_controls"] == 0
    assert body["coverage_pct"] is None


@pytest.mark.asyncio
async def test_the_summary_counts_baseline_controls_not_catalog_rows() -> None:
    from httpx import ASGITransport, AsyncClient  # noqa: PLC0415

    from ccf.analytics.framework_posture import baseline_controls  # noqa: PLC0415
    from ccf.api.main import create_app  # noqa: PLC0415

    async with session_scope() as s:
        # "SC-07a." is an objective row of SC-7: a catalog row, not a control.
        sys_, ids = await _moderate_system(s, ["SC-7", "SC-07a.", "SC-7(3)", "SC-8"])
        s.add(ControlImplementation(system_id=sys_.id, control_id=ids["SC-7"],
                                    status="implemented"))
        s.add(ControlImplementation(system_id=sys_.id, control_id=ids["SC-8"],
                                    status="partial"))
        await s.flush()
        expected_total = len(await baseline_controls(s, "moderate"))
        sid = sys_.id
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        body = (await c.get(f"/api/systems/{sid}/summary")).json()
    assert body["total_controls"] == expected_total
    assert body["implemented"] == 1 and body["partial"] == 1
    assert body["coverage_pct"] == round(100 * 1 / expected_total, 2)


# --- SPRS: one gap list; N/A is not a gap and not an implementation ----------


def test_gaps_separate_not_met_partial_and_not_assessed() -> None:
    from ccf.scoring.engine import gaps, score_system  # noqa: PLC0415

    matrix = [
        {"control_id": "A", "domain": "AC", "point_value": "5"},
        {"control_id": "B", "domain": "AC", "point_value": "3/5"},
        {"control_id": "C", "domain": "AC", "point_value": "1"},
        {"control_id": "D", "domain": "IA", "point_value": "3"},
        {"control_id": "E", "domain": "IA", "point_value": "1"},
        {"control_id": "F", "domain": "IA", "point_value": "1"},
    ]
    states = {"A": "not_implemented", "B": "partial", "C": "not_applicable",
              "E": "implemented", "F": "planned"}
    summary = score_system(matrix, states)
    rows = [{**m, "state": states.get(str(m["control_id"]), "not_assessed")} for m in matrix]
    got = {g["control_id"]: g for g in gaps(rows, recorded=states)}
    assert set(got) == {"A", "B", "D", "F"}  # C (N/A) and E (met) are not gaps
    assert got["A"]["gap"] == "not_met" and got["F"]["gap"] == "not_met"
    assert got["B"]["gap"] == "partial" and got["B"]["deduction"] == 3
    assert got["D"]["gap"] == "not_assessed" and got["D"]["unrecorded"] is True
    assert got["A"]["unrecorded"] is False
    assert summary.met_controls == 2 and summary.na_controls == 1


# --- profile-gap POA&Ms: keyed, not titled -----------------------------------


@pytest.mark.asyncio
async def test_a_renamed_gap_poam_is_not_filed_again_and_a_closed_one_can_be() -> None:
    from types import SimpleNamespace  # noqa: PLC0415

    from ccf.governance.automation import _seed_gap_poams  # noqa: PLC0415
    from ccf.models import POAM  # noqa: PLC0415

    gap = SimpleNamespace(control_id="AC.L2-3.1.1", title="Authorized access",
                          nist_id="3.1.1", point_value="5")
    derivation = {"AC.L2-3.1.1": {"responsibility": "customer"}}
    async with session_scope() as s:
        sys_, _ = await _moderate_system(s, [])
        assert await _seed_gap_poams(s, sys_.id, [gap], derivation) == 1  # type: ignore[list-item]
        await s.flush()
        poam = (await s.execute(select(POAM).where(POAM.system_id == sys_.id))).scalar_one()
        assert poam.due_on is not None and poam.source_ref
        poam.title = "Renamed by the ISSO"
        await s.flush()
        assert await _seed_gap_poams(s, sys_.id, [gap], derivation) == 0  # type: ignore[list-item]
        poam.status = "closed"
        await s.flush()
        # The gap is still there after the POA&M closed: it is raised again.
        assert await _seed_gap_poams(s, sys_.id, [gap], derivation) == 1  # type: ignore[list-item]
