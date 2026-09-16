"""The CCI tables exist, are global, and enforce their keys."""
import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from ccf.db import session_scope
from ccf.models_cci import CciControlRef, CciItemRow

pytestmark = pytest.mark.asyncio


async def test_an_item_and_its_references_round_trip(clean_migrated_db) -> None:
    async with session_scope() as s:
        item = CciItemRow(
            cci="CCI-999001",
            status="draft",
            type="technical",
            definition="test-only row",
            source_version="test",
            source_sha256="0" * 64,
        )
        s.add(item)
        await s.flush()
        s.add(
            CciControlRef(
                cci_id=item.id,
                revision="5",
                raw_index="AC-1 a 1 (a)",
                canonical_control="AC-1",
                oscal_control_id="ac-1",
                oscal_part_id="ac-1_smt.a.1.a",
            )
        )
    try:
        async with session_scope() as s:
            got = (
                await s.execute(
                    select(CciControlRef).where(CciControlRef.canonical_control == "AC-1")
                )
            ).scalars().all()
            assert any(r.raw_index == "AC-1 a 1 (a)" for r in got)
    finally:
        # cleanup: other modules count rows in shared tables. Runs whether the
        # assertion above passed or failed -- ON DELETE CASCADE on
        # cci_control_refs.cci_id removes the reference row when its parent
        # item is deleted, so deleting the item alone is enough.
        async with session_scope() as s:
            stale = (
                await s.execute(select(CciItemRow).where(CciItemRow.cci == "CCI-999001"))
            ).scalars().all()
            for row in stale:
                await s.delete(row)


async def test_cci_is_unique(clean_migrated_db) -> None:
    try:
        async with session_scope() as s:
            s.add(
                CciItemRow(
                    cci="CCI-999002", status="draft", type="policy",
                    definition="a", source_version="test", source_sha256="0" * 64,
                )
            )
        with pytest.raises(IntegrityError):
            async with session_scope() as s:
                s.add(
                    CciItemRow(
                        cci="CCI-999002", status="draft", type="policy",
                        definition="b", source_version="test", source_sha256="0" * 64,
                    )
                )
    finally:
        # cleanup: runs even if uniqueness were NOT enforced -- the exact
        # regression this test exists to catch, where pytest.raises itself
        # raises Failed and would otherwise skip everything below it.
        async with session_scope() as s:
            rows = (
                await s.execute(select(CciItemRow).where(CciItemRow.cci == "CCI-999002"))
            ).scalars().all()
            for row in rows:
                await s.delete(row)
