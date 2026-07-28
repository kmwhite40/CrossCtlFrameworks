"""``SSPProject.framework`` selector (NIST-80053-01, migration 0054).

Confirms the new ``framework`` column defaults to ``cmmc-800-171`` (today's
behavior, unchanged for existing/new projects that don't opt in) and that an
explicit ``nist-800-53r5`` value persists.
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, SSPProject

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.mark.asyncio
async def test_framework_defaults_to_cmmc_800_171() -> None:
    async with session_scope() as s:
        org = Organization(name="Framework Default Org")
        s.add(org)
        await s.flush()
        project = SSPProject(organization_id=org.id, customer_name="Acme Co")
        s.add(project)
        await s.flush()
        assert project.framework == "cmmc-800-171"


@pytest.mark.asyncio
async def test_framework_persists_nist_80053r5() -> None:
    async with session_scope() as s:
        org = Organization(name="Framework NIST Org")
        s.add(org)
        await s.flush()
        project = SSPProject(
            organization_id=org.id,
            customer_name="Acme Co",
            framework="nist-800-53r5",
        )
        s.add(project)
        await s.flush()
        assert project.framework == "nist-800-53r5"
