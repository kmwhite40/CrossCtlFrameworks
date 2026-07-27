"""Boundary service layer — CRUD, summary, and categorization rollup/reconcile.

DB-touching CRUD tests mirror ``tests/test_ato.py``/``tests/test_boundary_models.py``
(module-scoped ``fresh_engine`` + ``_migrate`` autouse fixture + ``session_scope()``,
since this repo has no ``db_session`` fixture). The rollup/reconcile tests are pure
(no DB) — they build unsaved ORM objects via the local ``_it``/``_sys`` helpers.
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config

from ccf.boundary.service import create_component, list_components
from ccf.boundary.summary import categorization_rollup, reconcile_categorization
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import InformationType, Organization, System

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


def _it(
    conf: str | None = None, integ: str | None = None, avail: str | None = None
) -> InformationType:
    """An unsaved InformationType with the given C/I/A impacts."""
    return InformationType(
        title="Test Info Type",
        confidentiality_impact=conf,
        integrity_impact=integ,
        availability_impact=avail,
    )


def _sys(conf: str | None = None, integ: str | None = None, avail: str | None = None) -> System:
    """An unsaved System with the given fips199 triad."""
    return System(
        name="Test System",
        fips199_confidentiality=conf,
        fips199_integrity=integ,
        fips199_availability=avail,
    )


@pytest.mark.asyncio
async def test_create_component_then_list_roundtrip() -> None:
    org_id, sys_id = await _make_org_system("Boundary Service Org")

    async with session_scope() as s:
        created = await create_component(
            s,
            system_id=sys_id,
            org_id=org_id,
            data={"type": "software", "title": "API Gateway", "status": "operational"},
        )
        assert created.id is not None
        assert created.organization_id == org_id
        assert created.system_id == sys_id
        assert created.title == "API Gateway"

    async with session_scope() as s:
        rows = await list_components(s, sys_id)
        assert len(rows) == 1
        assert rows[0].title == "API Gateway"
        assert rows[0].system_id == sys_id


@pytest.mark.asyncio
async def test_create_component_ignores_client_supplied_org_and_system_id() -> None:
    org_id, sys_id = await _make_org_system("Boundary Service Org Tenancy")
    _other_org_id, other_sys_id = await _make_org_system("Boundary Service Org Other")

    async with session_scope() as s:
        created = await create_component(
            s,
            system_id=sys_id,
            org_id=org_id,
            data={
                "type": "software",
                "title": "Sneaky Component",
                "organization_id": 999999,
                "system_id": other_sys_id,
            },
        )
        # The explicit system_id/org_id params win — data's org/system ids are ignored.
        assert created.organization_id == org_id
        assert created.system_id == sys_id
        assert created.system_id != other_sys_id


def test_categorization_rollup_high_water_mark() -> None:
    its = [_it(conf="moderate"), _it(conf="high"), _it(conf="low")]
    rollup = categorization_rollup(its)
    assert rollup["confidentiality"] == "high"


def test_categorization_rollup_mixed_levels_independent() -> None:
    its = [
        _it(conf="low", integ="high", avail="moderate"),
        _it(conf="moderate", integ="low", avail=None),
    ]
    rollup = categorization_rollup(its)
    assert rollup == {
        "confidentiality": "moderate",
        "integrity": "high",
        "availability": "moderate",
    }


def test_categorization_rollup_empty_list_is_all_none() -> None:
    rollup = categorization_rollup([])
    assert rollup == {"confidentiality": None, "integrity": None, "availability": None}


def test_categorization_rollup_all_impacts_unset_is_none() -> None:
    rollup = categorization_rollup([_it(), _it()])
    assert rollup == {"confidentiality": None, "integrity": None, "availability": None}


def test_reconcile_flags_under_categorization() -> None:
    sysrow = _sys(conf="moderate")
    findings = reconcile_categorization(sysrow, [_it(conf="high")])
    assert any(
        f["level"] == "confidentiality" and f["kind"] == "under_categorized" for f in findings
    )
    finding = next(f for f in findings if f["level"] == "confidentiality")
    assert finding["rollup"] == "high"
    assert finding["system"] == "moderate"


def test_reconcile_flags_over_categorization() -> None:
    sysrow = _sys(integ="high")
    findings = reconcile_categorization(sysrow, [_it(integ="low")])
    assert any(f["level"] == "integrity" and f["kind"] == "over_categorized" for f in findings)


def test_reconcile_returns_empty_when_levels_agree() -> None:
    sysrow = _sys(conf="moderate", integ="moderate", avail="moderate")
    findings = reconcile_categorization(
        sysrow, [_it(conf="moderate", integ="moderate", avail="moderate")]
    )
    assert findings == []


def test_reconcile_skips_levels_with_no_data() -> None:
    # System has no fips199 triad set at all, and there are no info types either
    # -> nothing to compare, no findings, and the system is left untouched.
    sysrow = _sys()
    findings = reconcile_categorization(sysrow, [])
    assert findings == []
    assert sysrow.fips199_confidentiality is None
    assert sysrow.fips199_integrity is None
    assert sysrow.fips199_availability is None


def test_reconcile_never_mutates_system() -> None:
    sysrow = _sys(conf="low")
    reconcile_categorization(sysrow, [_it(conf="high")])
    assert sysrow.fips199_confidentiality == "low"
