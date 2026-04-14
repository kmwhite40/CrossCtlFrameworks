"""End-to-end ingestion test against a real Postgres.

Requires Postgres reachable via CCF_DATABASE_URL_SYNC (CI uses a service
container; locally start `docker compose up -d db` and create `ccf_test`).
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from ccf.config import get_settings
from ccf.etl import ingest_workbook
from ccf.models import Base, Control, Framework, FrameworkMapping, Worksheet


@pytest.fixture(scope="session", autouse=True)
def apply_migrations() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")


@pytest.mark.asyncio
async def test_ingest_mini_workbook(mini_workbook: Path) -> None:
    engine = create_async_engine(str(get_settings().database_url))
    Session = async_sessionmaker(engine, expire_on_commit=False)

    async with Session() as session:
        run = await ingest_workbook(session, mini_workbook)
        await session.commit()
        assert run.status == "succeeded"

    async with Session() as session:
        ctl_count = (await session.execute(select(func.count(Control.id)))).scalar_one()
        map_count = (await session.execute(select(func.count(FrameworkMapping.id)))).scalar_one()
        fw_count = (await session.execute(select(func.count(Framework.id)))).scalar_one()
        sheets = (await session.execute(select(Worksheet))).scalars().all()

        assert ctl_count == 3
        assert map_count >= 9  # 3 controls × 3 mapping columns
        assert fw_count >= 20  # seeded framework catalog
        assert any(w.name == "Data Dictionary" for w in sheets)

        # tsvector populated
        row = (await session.execute(
            select(Control).where(Control.identifier == "AC-01")
        )).scalar_one()
        assert row.search_vector is not None
        assert row.audit_payload  # raw payload preserved

    await engine.dispose()
