"""``seed_80053_project`` — seeding ``SSPControlEntry`` rows from the 800-53B
baseline for a project's system.

Mirrors ``tests/test_ato.py`` for fixture style (``session_scope``,
``fresh_engine``, module-scoped ``_migrate``).
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select, text

from ccf.catalog.oscal import load_oscal_catalog
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, SSPControlEntry, SSPProject, System
from ccf.ssp.nist80053 import build_80053_entries
from ccf.ssp.seed import seed_80053_project

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _make_org_system_project(
    name: str,
    *,
    baseline: str | None = None,
    fips_confidentiality: str | None = None,
    fips_integrity: str | None = None,
    fips_availability: str | None = None,
) -> tuple[int, SSPProject]:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        sys = System(
            organization_id=org.id,
            name=f"{name} system",
            baseline=baseline,
            fips199_confidentiality=fips_confidentiality,
            fips199_integrity=fips_integrity,
            fips199_availability=fips_availability,
        )
        s.add(sys)
        await s.flush()
        project = SSPProject(
            organization_id=org.id,
            system_id=sys.id,
            customer_name=name,
            framework="nist-800-53r5",
        )
        s.add(project)
        await s.flush()
        return sys.id, project


@pytest.mark.asyncio
async def test_seed_80053_project_moderate_baseline() -> None:
    async with session_scope() as s:
        await s.execute(text("TRUNCATE ccf.ssp_control_entries CASCADE"))

    _sys_id, project = await _make_org_system_project(
        "Nist80053 Moderate Org", baseline="moderate"
    )

    catalog = load_oscal_catalog()
    expected_entries, _ = build_80053_entries(catalog, "moderate")
    expected_count = len(expected_entries)

    async with session_scope() as s:
        proj = await s.get(SSPProject, project.id)
        assert proj is not None
        inserted = await seed_80053_project(s, proj, catalog=catalog)
        assert inserted == expected_count

    async with session_scope() as s:
        rows = (
            (
                await s.execute(
                    select(SSPControlEntry).where(SSPControlEntry.project_id == project.id)
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == expected_count
        control_ids = {r.control_id for r in rows}
        assert "AC-2" in control_ids


@pytest.mark.asyncio
async def test_seed_80053_project_is_idempotent() -> None:
    async with session_scope() as s:
        await s.execute(text("TRUNCATE ccf.ssp_control_entries CASCADE"))

    _sys_id, project = await _make_org_system_project(
        "Nist80053 Idempotent Org", baseline="moderate"
    )
    catalog = load_oscal_catalog()

    async with session_scope() as s:
        proj = await s.get(SSPProject, project.id)
        assert proj is not None
        first = await seed_80053_project(s, proj, catalog=catalog)
        assert first > 0

    async with session_scope() as s:
        proj = await s.get(SSPProject, project.id)
        assert proj is not None
        second = await seed_80053_project(s, proj, catalog=catalog)
        assert second == 0

    async with session_scope() as s:
        total = (
            await s.execute(
                select(SSPControlEntry).where(SSPControlEntry.project_id == project.id)
            )
        ).scalars().all()
        assert len(total) == first


@pytest.mark.asyncio
async def test_seed_80053_project_fips_high_water_fallback() -> None:
    _sys_id, project = await _make_org_system_project(
        "Nist80053 FIPS High Org",
        baseline=None,
        fips_confidentiality="high",
    )
    catalog = load_oscal_catalog()
    expected_entries, _ = build_80053_entries(catalog, "high")
    expected_count = len(expected_entries)

    async with session_scope() as s:
        proj = await s.get(SSPProject, project.id)
        assert proj is not None
        inserted = await seed_80053_project(s, proj, catalog=catalog)
        assert inserted == expected_count


@pytest.mark.asyncio
async def test_seed_80053_project_no_baseline_raises() -> None:
    _sys_id, project = await _make_org_system_project(
        "Nist80053 No Baseline Org", baseline=None
    )
    catalog = load_oscal_catalog()

    async with session_scope() as s:
        proj = await s.get(SSPProject, project.id)
        assert proj is not None
        with pytest.raises(ValueError):
            await seed_80053_project(s, proj, catalog=catalog)
