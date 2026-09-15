"""Loading the real list is idempotent and content-addressed."""
from pathlib import Path

import pytest
from sqlalchemy import func, select

from ccf.cci.reader import DEFAULT_CCI_HTML
from ccf.cci.service import load_cci_list
from ccf.db import session_scope
from ccf.models_cci import CciControlRef, CciItemRow

pytestmark = pytest.mark.asyncio

#: CCI-000001's definition, verbatim from the committed file. Modified below
#: to prove an item-level change is picked up and stored.
_ORIGINAL_DEFINITION = (
    "The organization develops an access control policy that addresses purpose, "
    "scope, roles, responsibilities, management commitment, coordination among "
    "organizational entities, and compliance."
)

#: One whole reference row belonging to a DIFFERENT CCI (CCI-000004). Removed
#: below to prove wholesale reference replacement actually drops a row rather
#: than merely adding new ones.
_REMOVED_REFERENCE_ROW = (
    '      <tr>\n'
    '        <td class="header"></td>\n'
    '        <td colspan="3">NIST:  '
    '<a href="http://csrc.nist.gov/publications/PubsSPs.html">'
    "NIST SP 800-53A (v1)</a>:  AC-1.1 (iv and v)</td>\n"
    "      </tr>\n"
)


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


async def test_changed_content_updates_items_and_replaces_references(
    tmp_path: Path,
    clean_migrated_db,
) -> None:
    """A reload with different bytes updates every item and drops removed refs.

    The other tests here either load into an empty table (all-created) or
    reload byte-identical content (short-circuited by the skipped_unchanged
    check before either pass runs). Neither exercises the update-existing +
    wholesale-replace-references path, which is exactly what the two-pass
    flush restructuring could get wrong. This test builds a modified copy of
    the real file -- one CCI's definition changed, a different CCI's
    reference dropped -- and loads that.
    """
    original = DEFAULT_CCI_HTML.read_text(encoding="utf-8")
    assert original.count(_ORIGINAL_DEFINITION) == 1
    assert original.count(_REMOVED_REFERENCE_ROW) == 1
    modified = original.replace(
        _ORIGINAL_DEFINITION, _ORIGINAL_DEFINITION + " (TEST-MODIFIED)"
    ).replace(_REMOVED_REFERENCE_ROW, "")
    tmp_html = tmp_path / "CCI List modified.html"
    tmp_html.write_text(modified, encoding="utf-8")

    try:
        async with session_scope() as s:
            await load_cci_list(s)  # baseline: the real, committed file

        async with session_scope() as s:
            second = await load_cci_list(s, path=tmp_html)

        assert second.skipped_unchanged is False
        assert second.items_created == 0
        assert second.items_updated == 5149

        async with session_scope() as s:
            edited = (
                await s.execute(
                    select(CciItemRow).where(CciItemRow.cci == "CCI-000001")
                )
            ).scalar_one()
            assert edited.definition == _ORIGINAL_DEFINITION + " (TEST-MODIFIED)"

            trimmed = (
                await s.execute(
                    select(CciItemRow).where(CciItemRow.cci == "CCI-000004")
                )
            ).scalar_one()
            refs = (
                await s.execute(
                    select(CciControlRef).where(CciControlRef.cci_id == trimmed.id)
                )
            ).scalars().all()
            # The real file gives CCI-000004 three references (v3, v4,
            # 800-53A); the modified copy drops the 800-53A one.
            assert len(refs) == 2
            assert not any(
                r.revision == "800-53A" and r.raw_index == "AC-1.1 (iv and v)"
                for r in refs
            )
    finally:
        async with session_scope() as s:
            rows3 = (await s.execute(select(CciItemRow))).scalars().all()
            for row in rows3:
                await s.delete(row)
