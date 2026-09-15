"""The .ods is mixed-generation despite its name; only Rev. 5 rows load."""
import pytest
from sqlalchemy import func, select

from ccf.cci import service as service_module
from ccf.cci.overlay import DEFAULT_CCI_ODS, OverlayRow, read_overlay_ods
from ccf.cci.service import load_cci_list, load_cci_overlay
from ccf.db import session_scope
from ccf.models_cci import CciAssessmentOverlay, CciItemRow


@pytest.fixture(scope="module")
def rows():
    return read_overlay_ods(DEFAULT_CCI_ODS)


def test_only_rev5_spelled_rows_are_returned(rows) -> None:
    # 2,362 of the file's 3,626 rows are genuinely Rev. 5. Zero-padded control
    # spelling (AC-01 vs AC-1) only discriminates single-digit controls -- a
    # two-digit control like AC-10 is spelled identically in both revisions,
    # so spelling alone lets 254 Rev. 4/STIG rows through disguised as Rev. 5.
    # The Assessment Procedures wording ("Determine if...") is the reliable
    # discriminator; see overlay.py's module docstring for the measured
    # evidence that it subsumes the spelling test.
    assert len(rows) == 2362
    assert all(r.control_number[3].isdigit() and r.control_number[2] == "-" for r in rows)


def test_rev4_spelled_control_numbers_are_excluded(rows) -> None:
    assert not any(r.control_number == "AC-1" for r in rows)
    assert any(r.control_number == "AC-01" for r in rows)


def test_no_duplicate_control_ap_cci_triples(rows) -> None:
    # The invariant that actually matters: exactly one generation is
    # returned. A bare row count can be hit by the wrong rows (as the
    # spelling-only filter proved: 2,616 rows, but 51 of the underlying
    # triples were duplicated between generations with conflicting text).
    triples = [(r.control_number, r.ap_acronym, r.cci) for r in rows]
    assert len(triples) == len(set(triples))


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


@pytest.mark.asyncio
async def test_overlay_reload_is_idempotent(clean_migrated_db) -> None:
    try:
        async with session_scope() as s:
            await load_cci_list(s)
        async with session_scope() as s:
            first = await load_cci_overlay(s)
        # A second run must not raise a uq_cci_overlay violation and must
        # leave the table at the same row count -- load_cci_overlay deletes
        # any existing (cci_id, ap_acronym) row before re-inserting it.
        async with session_scope() as s:
            second = await load_cci_overlay(s)
        assert second == first
        async with session_scope() as s:
            count = (
                await s.execute(select(func.count()).select_from(CciAssessmentOverlay))
            ).scalar()
        assert count == first
    finally:
        async with session_scope() as s:
            items = (await s.execute(select(CciItemRow))).scalars().all()
            for item in items:
                await s.delete(item)


@pytest.mark.asyncio
async def test_overlay_row_for_unknown_cci_is_skipped_not_inserted(
    clean_migrated_db, monkeypatch
) -> None:
    try:
        async with session_scope() as s:
            await load_cci_list(s)

        # A row for a CCI the authority list does not contain -- must be
        # skipped, never inserted, regardless of what the derived file says.
        fake_rows = [
            OverlayRow(
                cci="CCI-999999",
                control_number="ZZ-99",
                ap_acronym="ZZ-99a",
                emass_identifier="ZZ-1",
                assessment_procedure="Determine if the fixture works.",
                assessment_methods="Examine: fixture.",
            )
        ]
        monkeypatch.setattr(service_module, "read_overlay_ods", lambda path: fake_rows)

        async with session_scope() as s:
            written = await load_cci_overlay(s)
        assert written == 0

        async with session_scope() as s:
            count = (
                await s.execute(
                    select(func.count())
                    .select_from(CciAssessmentOverlay)
                    .where(CciAssessmentOverlay.ap_acronym == "ZZ-99a")
                )
            ).scalar()
        assert count == 0
    finally:
        async with session_scope() as s:
            items = (await s.execute(select(CciItemRow))).scalars().all()
            for item in items:
                await s.delete(item)
