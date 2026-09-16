"""RLS coverage for evidence's capability-parented predicate (0067 fix).

Migration 0067 made ``evidence.implementation_id`` nullable so evidence can be
parented to a :class:`~ccf.models_capability.Capability` instead, guarded by a
CHECK that at least one parent is set. But the table's ``tenant_isolation``
policy (migration 0010) predicated solely on
``implementation_id IN (SELECT ci.id FROM control_implementations ci JOIN
systems s ...)``. For a capability-parented row ``implementation_id IS NULL``,
so that predicate evaluates to UNKNOWN -- a real RLS-enforced scoped tenant
could neither see nor insert capability-parented evidence, even for its own
org. FORCE ROW LEVEL SECURITY still let an *unscoped* principal write such a
row, so this failed closed rather than leaking, but it made the very feature
0067 exists to enable inert in production.

0067's ``upgrade()`` now drops and recreates the ``evidence`` policy with an
additional ``capability_id IN (SELECT id FROM ccf.capabilities WHERE
organization_id = ccf.current_tenant())`` branch, applied to both ``USING``
and ``WITH CHECK``.

Every assertion below sets a *real* tenant via ``set_session_tenant`` --
``session_scope()``'s default (``current_tenant() IS NULL``) would
short-circuit the whole predicate to true and prove nothing about the fix.
"""

from __future__ import annotations

import itertools

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, select

from ccf.config import get_settings
from ccf.db import session_scope, set_session_tenant
from ccf.models import Control, ControlImplementation, Evidence, Organization, System
from ccf.models_capability import Capability

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _seed() -> dict[str, int]:
    """Two throwaway orgs, each with a system, a control implementation (the
    pre-existing evidence parent shape), and a capability (the new one)."""
    n = next(_SEQ)
    async with session_scope() as s:  # unscoped (bypass) -- full access
        org_a = Organization(name=f"RlsEvCapOrgA-{n}")
        org_b = Organization(name=f"RlsEvCapOrgB-{n}")
        s.add_all([org_a, org_b])
        await s.flush()

        sys_a = System(organization_id=org_a.id, name=f"RlsEvCapSysA-{n}")
        sys_b = System(organization_id=org_b.id, name=f"RlsEvCapSysB-{n}")
        control = Control(
            identifier=f"RLS-EVCAP-{n}", control_name="RLS Evidence Capability Test"
        )
        s.add_all([sys_a, sys_b, control])
        await s.flush()

        impl_a = ControlImplementation(system_id=sys_a.id, control_id=control.id)
        impl_b = ControlImplementation(system_id=sys_b.id, control_id=control.id)
        cap_a = Capability(organization_id=org_a.id, key=f"rls-evcap-a-{n}", title="Cap A")
        cap_b = Capability(organization_id=org_b.id, key=f"rls-evcap-b-{n}", title="Cap B")
        s.add_all([impl_a, impl_b, cap_a, cap_b])
        await s.flush()

        return {
            "org_a": org_a.id,
            "org_b": org_b.id,
            "impl_a": impl_a.id,
            "impl_b": impl_b.id,
            "cap_a": cap_a.id,
            "cap_b": cap_b.id,
        }


@pytest.mark.asyncio
async def test_capability_parented_evidence_scoped_to_owning_tenant() -> None:
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")

    ids = await _seed()
    evidence_id: int | None = None
    impl_evidence_id: int | None = None
    try:
        # Tenant A can INSERT a capability-parented row belonging to its own
        # org, and then READ IT BACK, with no app-layer filter at all.
        async with session_scope() as s:
            await set_session_tenant(s, ids["org_a"])
            row = Evidence(
                capability_id=ids["cap_a"], kind="config_export", title="RlsEvCapEvidenceA"
            )
            s.add(row)
            await s.flush()
            evidence_id = row.id

            fetched = (
                await s.execute(select(Evidence).where(Evidence.id == evidence_id))
            ).scalar_one_or_none()
            assert fetched is not None, (
                "tenant A could not read back its own capability-parented evidence row -- "
                "the evidence RLS policy is still implementation-only"
            )

        # Tenant B must not see tenant A's capability-parented row.
        async with session_scope() as s:
            await set_session_tenant(s, ids["org_b"])
            fetched = (
                await s.execute(select(Evidence).where(Evidence.id == evidence_id))
            ).scalar_one_or_none()
            assert fetched is None, "tenant B can see tenant A's capability-parented evidence"

        # Tenant B cannot smuggle a row onto tenant A's capability either --
        # WITH CHECK must reject it, not just USING hide it.
        with pytest.raises(Exception):  # noqa: B017 - asyncpg/psycopg raise a DB error
            async with session_scope() as s:
                await set_session_tenant(s, ids["org_b"])
                s.add(
                    Evidence(
                        capability_id=ids["cap_a"],
                        kind="config_export",
                        title="RlsEvCapSmuggled",
                    )
                )
                await s.flush()

        # The pre-existing implementation-parented behaviour must still hold:
        # own org can insert-and-read, the other org sees nothing.
        async with session_scope() as s:
            await set_session_tenant(s, ids["org_a"])
            impl_row = Evidence(
                implementation_id=ids["impl_a"], kind="config_export", title="RlsEvCapImplA"
            )
            s.add(impl_row)
            await s.flush()
            impl_evidence_id = impl_row.id

            fetched = (
                await s.execute(select(Evidence).where(Evidence.id == impl_evidence_id))
            ).scalar_one_or_none()
            assert fetched is not None, "tenant A could not read back its own evidence"

        async with session_scope() as s:
            await set_session_tenant(s, ids["org_b"])
            fetched = (
                await s.execute(select(Evidence).where(Evidence.id == impl_evidence_id))
            ).scalar_one_or_none()
            assert fetched is None, (
                "tenant B can see tenant A's implementation-parented evidence"
            )
    finally:
        async with session_scope() as s:
            await set_session_tenant(s, None)
            await s.execute(
                delete(Evidence).where(
                    Evidence.title.in_(
                        ["RlsEvCapEvidenceA", "RlsEvCapSmuggled", "RlsEvCapImplA"]
                    )
                )
            )
