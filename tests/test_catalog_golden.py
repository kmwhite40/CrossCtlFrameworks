"""Golden end-to-end test (Task 8): ingest a fixture workbook through the real
pipeline and assert the tail-called catalog reconciliation (Task 6) produced
a correct, persisted ``CatalogIntegrityReport`` against the REAL bundled OSCAL
catalog (no fixture catalog override) — the full path a real ingest exercises.
"""

from __future__ import annotations

from pathlib import Path

import openpyxl
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text

from ccf.catalog.report import latest_report
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.etl.pipeline import ingest_workbook

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _build_workbook(path: Path) -> None:
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "SP.800-53Ar5_assessment"
    headers = [
        "family",
        "identifier",
        "sort-as",
        "control-name",
        "Security Control Description",
        "Security Control Discussion",
        "NIST SP 800-53 Rev. 5 related controls",
        "assessment-objective",
        "EXAMINE",
        "INTERVIEW",
        "TEST",
        "FISMA Low",
        "FISMA Mod",
        "FISMA High",
        "NIST SP 800-53R5  Control",
        "ISO 27001 Mapping",
    ]
    ws.append(headers)
    rows = [
        [
            "(AC) ACCESS CONTROL",
            "AC-2-obj1",
            "AC-02-00-00",
            "Account Management",
            "Identify and select account types...",
            "Discussion text",
            "AC-3",
            "Determine if:",
            "config",
            "admins",
            "test",
            "",
            "X",
            "",
            "AC-2",
            "A.9.2.1",
        ],
        [
            "(SC) SYSTEM AND COMMUNICATIONS PROTECTION",
            "SC-99-obj1",
            "SC-99-00-00",
            "Bogus",
            "A control that does not exist.",
            "Discussion text",
            "",
            "Determine if:",
            "config",
            "admins",
            "test",
            "",
            "",
            "",
            "SC-99",
            "",
        ],
        [
            "(AC) ACCESS CONTROL",
            "cmmc-1",
            "cmmc-1",
            "Cmmc practice",
            "A CMMC practice, not an 800-53 control.",
            "Discussion text",
            "",
            "Determine if:",
            "",
            "",
            "",
            "",
            "",
            "",
            "AC.L2-3.1.1",
            "",
        ],
    ]
    for r in rows:
        ws.append(r)
    wb.save(path)


async def test_ingest_produces_reconciliation_report(tmp_path: Path) -> None:
    wb_path = tmp_path / "golden.xlsx"
    _build_workbook(wb_path)

    # The shared test DB isn't truncated between tests; a prior test may have left
    # control_implementations referencing controls, which would make ingest's
    # `DELETE FROM controls` FK-fail. Clear controls + dependents first so this
    # e2e stands on its own regardless of ordering.
    async with session_scope() as s:
        await s.execute(text("TRUNCATE ccf.controls CASCADE"))

    async with session_scope() as s:
        await ingest_workbook(s, wb_path)

    async with session_scope() as s:
        report = await latest_report(s)

    assert report is not None
    if report.controls_checked != 3:  # pragma: no cover - debug aid, not a weakened assertion
        print("crosswalk:", report.crosswalk)
        print("summary:", report.summary)
    # 3 distinct control_numbers: AC-2 (evaluated), SC-99 (unknown), AC.L2-3.1.1 (unparseable)
    assert report.controls_checked == 3
    assert report.not_evaluated == 2
    # invariant always holds
    assert report.controls_checked == len(report.summary["evaluated_ids"]) + report.not_evaluated
    # the unknown control surfaces as a finding
    assert any(f["canonical_id"] == "SC-99" for f in report.findings)
    # crosswalk maps every distinct raw control_number
    assert report.crosswalk.get("AC-2") == "AC-2"
    assert report.crosswalk.get("AC.L2-3.1.1") is None
