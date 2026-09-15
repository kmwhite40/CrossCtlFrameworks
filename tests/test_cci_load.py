"""Loading the real list is idempotent and content-addressed."""
import pytest
from sqlalchemy import func, select

from ccf.cci.service import load_cci_list
from ccf.db import session_scope
from ccf.models_cci import CciControlRef, CciItemRow

pytestmark = pytest.mark.asyncio


async def test_load_writes_every_item_and_reference(clean_migrated_db) -> None:
    try:
        async with session_scope() as s:
            result = await load_cci_list(s)
        assert result.version == "2026-07-14"
        assert result.items_created == 5149
        assert result.refs_written == 10216
        assert result.refs_unresolved == 1  # CCI-005020 -> SI-18 b 1
        async with session_scope() as s:
            count = (await s.execute(select(func.count()).select_from(CciItemRow))).scalar()
            assert count == 5149
    finally:
        # cleanup: other modules count rows in shared tables. ON DELETE
        # CASCADE on cci_control_refs.cci_id removes references when their
        # parent item is deleted.
        async with session_scope() as s:
            rows = (await s.execute(select(CciItemRow))).scalars().all()
            for row in rows:
                await s.delete(row)


async def test_second_load_of_the_same_file_is_a_no_op(clean_migrated_db) -> None:
    try:
        async with session_scope() as s:
            await load_cci_list(s)
        async with session_scope() as s:
            again = await load_cci_list(s)
        assert again.skipped_unchanged is True
        assert again.items_created == 0
        assert again.items_updated == 0
    finally:
        async with session_scope() as s:
            rows = (await s.execute(select(CciItemRow))).scalars().all()
            for row in rows:
                await s.delete(row)


async def test_reverse_index_is_populated(clean_migrated_db) -> None:
    try:
        async with session_scope() as s:
            await load_cci_list(s)
            # Joined explicitly rather than walking CciControlRef.item: a lazy
            # relationship load outside the awaited query raises MissingGreenlet
            # under async SQLAlchemy, and expire_on_commit=False does not help.
            rows = (
                await s.execute(
                    select(CciItemRow.cci, CciControlRef.oscal_part_id)
                    .join(CciControlRef, CciControlRef.cci_id == CciItemRow.id)
                    .where(
                        CciControlRef.canonical_control == "AC-1",
                        CciControlRef.revision == "5",
                    )
                )
            ).all()
        assert {cci for cci, _ in rows} >= {"CCI-000002", "CCI-002107"}
        assert any(part == "ac-1_smt.a.1.a" for _, part in rows)
    finally:
        async with session_scope() as s:
            rows2 = (await s.execute(select(CciItemRow))).scalars().all()
            for row in rows2:
                await s.delete(row)
