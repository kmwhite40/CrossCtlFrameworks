"""Pin migration 0114: approvals stored with no organization take their entity's.

Round-trips 0114 against the shared database (downgrade to 0113, seed, upgrade).
"""

from __future__ import annotations

import uuid

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import POAM, Approval, Organization, Risk, SSPProject, System

pytestmark = pytest.mark.usefixtures("fresh_engine")


def _cfg() -> Config:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    return cfg


@pytest.mark.asyncio
async def test_migration_0114_gives_each_orphan_approval_its_entitys_org() -> None:
    cfg = _cfg()
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "0113_ssp_edit_reopens_approval")
    try:
        tag = uuid.uuid4().hex[:8]
        async with session_scope() as s:
            org = Organization(name=f"m0114-{tag}")
            s.add(org)
            await s.flush()
            sysm = System(organization_id=org.id, name=f"m0114 {tag}")
            s.add(sysm)
            await s.flush()
            poam = POAM(system_id=sysm.id, title="W")
            enterprise = Risk(organization_id=org.id, title="Enterprise, no system")
            plan = SSPProject(organization_id=org.id, customer_name=f"c {tag}")
            s.add_all([poam, enterprise, plan])
            await s.flush()
            ids = {"poam": poam.id, "risk": enterprise.id, "ssp_project": plan.id}
            for kind, eid in ids.items():
                s.add(Approval(entity_type=kind, entity_id=str(eid), state="approved"))
            org_id = org.id
    finally:
        command.upgrade(cfg, "head")
    async with session_scope() as s:
        found = {
            a.entity_type: a.organization_id
            for a in (
                await s.execute(
                    select(Approval).where(
                        Approval.entity_id.in_([str(i) for i in ids.values()]),
                        Approval.entity_type.in_(list(ids)),
                    )
                )
            ).scalars()
            if str(ids[a.entity_type]) == a.entity_id
        }
    assert found == dict.fromkeys(ids, org_id)
