"""The .ods is mixed-generation despite its name; only Rev. 5 rows load."""
import pytest
from sqlalchemy import select

from ccf.cci.overlay import DEFAULT_CCI_ODS, read_overlay_ods
from ccf.cci.service import load_cci_list, load_cci_overlay
from ccf.db import session_scope
from ccf.models_cci import CciAssessmentOverlay, CciItemRow


@pytest.fixture(scope="module")
def rows():
    return read_overlay_ods(DEFAULT_CCI_ODS)


def test_only_rev5_spelled_rows_are_returned(rows) -> None:
    # 2,616 of the file's 3,626 rows are Rev. 5 spelling (AC-01); the other
    # 1,010 are Rev. 4 (AC-1) and are a second copy of the same CCIs.
    assert len(rows) == 2616
    assert all(r.control_number[3].isdigit() and r.control_number[2] == "-" for r in rows)


def test_rev4_spelled_control_numbers_are_excluded(rows) -> None:
    assert not any(r.control_number == "AC-1" for r in rows)
    assert any(r.control_number == "AC-01" for r in rows)


def test_a_row_carries_its_emass_identifier_and_procedure(rows) -> None:
    # Two rows share ap_acronym "AC-01a" (CCI-000002 and CCI-002107); the
    # sheet leaves eMASS Identifier blank for CCI-000002, so pick the row
    # that actually has one rather than assuming the first match does.
    row = next(r for r in rows if r.ap_acronym == "AC-01a" and r.emass_identifier)
    assert row.cci.startswith("CCI-")
    assert row.emass_identifier
    assert row.assessment_procedure


@pytest.mark.asyncio
async def test_overlay_attaches_only_to_known_ccis_and_names_its_source(
    clean_migrated_db,
) -> None:
    try:
        async with session_scope() as s:
            await load_cci_list(s)
        async with session_scope() as s:
            written = await load_cci_overlay(s)
        assert written > 0
        async with session_scope() as s:
            rows = (await s.execute(select(CciAssessmentOverlay).limit(5))).scalars().all()
        assert rows
        assert all(r.source == "derived:All Rev. 5 CCIs.ods" for r in rows)
    finally:
        # cleanup: other modules count rows in shared tables. ON DELETE
        # CASCADE on cci_assessment_overlay.cci_id removes overlay rows when
        # their parent item is deleted.
        async with session_scope() as s:
            items = (await s.execute(select(CciItemRow))).scalars().all()
            for item in items:
                await s.delete(item)
