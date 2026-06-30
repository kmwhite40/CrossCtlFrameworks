"""PostgreSQL row-level security enforces tenant isolation at the DB layer.

These tests bypass the application's ``.where()`` scoping entirely and query the
ORM directly under different ``ccf.tenant_id`` contexts, proving the isolation
holds even if a route forgets to scope.
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, func, select

from ccf.config import get_settings
from ccf.db import session_scope, set_session_tenant
from ccf.models import Organization, System

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _seed_two_orgs() -> tuple[int, int, int, int]:
    """Get-or-create two orgs each with one system; returns their ids."""
    async with session_scope() as s:  # unscoped (bypass) — full access
        out: list[int] = []
        for org_name, sys_name in (("RlsOrgA", "RlsSysA"), ("RlsOrgB", "RlsSysB")):
            org = (
                await s.execute(select(Organization).where(Organization.name == org_name))
            ).scalar_one_or_none() or Organization(name=org_name)
            if org.id is None:
                s.add(org)
                await s.flush()
            sys = (
                await s.execute(
                    select(System).where(
                        System.organization_id == org.id, System.name == sys_name
                    )
                )
            ).scalar_one_or_none() or System(organization_id=org.id, name=sys_name)
            if sys.id is None:
                s.add(sys)
                await s.flush()
            out += [org.id, sys.id]
        return out[0], out[1], out[2], out[3]


@pytest.mark.asyncio
async def test_rls_scopes_reads_and_blocks_cross_tenant_writes() -> None:
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")

    org_a, sys_a, org_b, sys_b = await _seed_two_orgs()

    # Tenant A sees only its own system, even with NO app-layer filter.
    async with session_scope() as s:
        await set_session_tenant(s, org_a)
        rows = (await s.execute(select(System.id))).scalars().all()
        assert sys_a in rows and sys_b not in rows
        # Direct fetch of B's row by id returns nothing under tenant A.
        assert (
            await s.execute(select(System).where(System.id == sys_b))
        ).scalar_one_or_none() is None

    # Tenant B is the mirror image.
    async with session_scope() as s:
        await set_session_tenant(s, org_b)
        rows = (await s.execute(select(System.id))).scalars().all()
        assert sys_b in rows and sys_a not in rows

    # Cross-tenant INSERT is rejected by the WITH CHECK clause.
    with pytest.raises(Exception):  # noqa: B017 - asyncpg/psycopg raise a DB error
        async with session_scope() as s:
            await set_session_tenant(s, org_a)
            s.add(System(organization_id=org_b, name="SmuggledIntoB"))
            await s.flush()

    # Unscoped (bypass) sees both orgs' systems.
    async with session_scope() as s:
        await set_session_tenant(s, None)
        total = (
            await s.execute(
                select(func.count(System.id)).where(System.id.in_([sys_a, sys_b]))
            )
        ).scalar_one()
        assert total == 2

    # cleanup the smuggle attempt if it ever slipped through
    async with session_scope() as s:
        await set_session_tenant(s, None)
        await s.execute(delete(System).where(System.name == "SmuggledIntoB"))
