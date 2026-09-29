"""End-to-end ingestion test against a real Postgres.

Requires Postgres reachable via CCF_DATABASE_URL_SYNC (CI uses a service
container; locally start `docker compose up -d db` and create `ccf_test`).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ccf.config import get_settings
from ccf.etl import ingest_workbook
from ccf.models import Control, Framework, FrameworkMapping, Worksheet


@pytest.fixture(scope="module", autouse=True)
def clean_catalog_tables() -> None:
    """Empty the catalog this module counts, without resetting the database.

    These tests assert exact totals (``ctl_count == 3``), so they need the
    catalog empty. They used to get that by downgrading the whole schema to
    ``base`` and re-upgrading, from a **session-scoped** fixture — mid-session,
    which is precisely what ``conftest.clean_migrated_db`` warns against in its
    own docstring: it wipes data every module that already ran depends on, and
    two modules doing it raced into a ``pg_type`` collision recreating
    ``ccf.ingestion_runs``.

    Deleting the four tables this module actually counts gives the same
    determinism with a blast radius of four tables instead of the database.
    ``Framework`` is deliberately left alone: ``fw_count >= 20`` asserts on the
    catalog the migrations seed, which a truncate would destroy and nothing
    would put back.
    """
    engine = create_engine(str(get_settings().database_url_sync))
    with engine.begin() as conn:
        # Order matters only in so far as the FKs allow; CASCADE covers the
        # dependents (implementations, mappings) without naming each one here
        # and going stale when a new dependent is added.
        conn.execute(
            text(
                "TRUNCATE ccf.controls, ccf.framework_mappings, ccf.worksheets, "
                "ccf.ingestion_runs RESTART IDENTITY CASCADE"
            )
        )
    engine.dispose()


@pytest.mark.asyncio
async def test_ingest_mini_workbook(mini_workbook: Path) -> None:
    engine = create_async_engine(str(get_settings().database_url))
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with session_factory() as session:
        run = await ingest_workbook(session, mini_workbook)
        await session.commit()
        assert run.status == "succeeded"

    async with session_factory() as session:
        ctl_count = (await session.execute(select(func.count(Control.id)))).scalar_one()
        map_count = (await session.execute(select(func.count(FrameworkMapping.id)))).scalar_one()
        fw_count = (await session.execute(select(func.count(Framework.id)))).scalar_one()
        sheets = (await session.execute(select(Worksheet))).scalars().all()

        assert ctl_count == 3
        assert map_count >= 9  # 3 controls x 3 mapping columns
        assert fw_count >= 20  # seeded framework catalog
        assert any(w.name == "Data Dictionary" for w in sheets)

        # tsvector populated
        row = (
            await session.execute(select(Control).where(Control.identifier == "AC-01"))
        ).scalar_one()
        assert row.search_vector is not None
        assert row.audit_payload  # raw payload preserved

    await engine.dispose()
