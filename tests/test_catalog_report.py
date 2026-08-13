"""Persistence for advisory catalog reconciliation reports (Task 5).

Covers ``run_and_store`` (reads controls/mappings, runs ``reconcile``, persists
a ``CatalogIntegrityReport`` row without mutating reference tables),
``latest_report``, and ``render_text``.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import func, select, text

from ccf.catalog.report import latest_report, render_text, run_and_store
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Control, FrameworkMapping

FIX = Path(__file__).parent / "fixtures" / "oscal_mini"

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def test_run_and_store_persists_report() -> None:
    # The shared test DB accumulates controls across tests; this test asserts an
    # exact controls_checked, so start from a clean controls table.
    async with session_scope() as s:
        await s.execute(text("TRUNCATE ccf.controls CASCADE"))
    async with session_scope() as s:
        s.add(
            Control(
                identifier="row-1",
                control_number="AC-2",
                control_name="Account Management",
                description="Manage system accounts.",
                fisma_mod=True,
            )
        )
        s.add(Control(identifier="row-2", control_number="SC-99"))  # unknown
        await s.flush()

        report = await run_and_store(s, oscal_dir=FIX)
        assert report.controls_checked == 2
        assert report.findings_total >= 1
        assert any(f["canonical_id"] == "SC-99" for f in report.findings)
        assert report.oscal_version == "5.2.0"

        got = await latest_report(s)
        assert got is not None
        assert got.id == report.id
        assert "OSCAL" in render_text(got)


async def test_run_and_store_does_not_mutate_controls():
    # Advisory-only guarantee: reconciliation must never change controls/mappings.
    async with session_scope() as s:
        s.add(Control(identifier="adv-1", control_number="AC-2", control_name="Account Management"))
        await s.flush()
        c_count = select(func.count()).select_from(Control)
        m_count = select(func.count()).select_from(FrameworkMapping)
        before_c = (await s.execute(c_count)).scalar_one()
        before_m = (await s.execute(m_count)).scalar_one()
        await run_and_store(s, oscal_dir=FIX)
        after_c = (await s.execute(c_count)).scalar_one()
        after_m = (await s.execute(m_count)).scalar_one()
    assert before_c == after_c
    assert before_m == after_m
