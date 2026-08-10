"""Context expansion — block, table row, section, and window strategies."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from ccf.db import session_scope
from ccf.models import Organization
from ccf.models_prep import PrepLine, PrepScreen, PrepUnit
from ccf.prep import pipeline
from ccf.prep.expand import expand_line, run_stage_expand

pytestmark = pytest.mark.usefixtures("fresh_engine")


def _line(**kw: object) -> PrepLine:
    base: dict[str, object] = {"run_id": 1, "organization_id": 1, "content": "x"}
    line = PrepLine(**{**base, **kw})
    line.id = int(kw.get("line_number", 1))  # type: ignore[arg-type]
    return line


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return int(org.id)


def test_table_cell_expands_to_its_row_with_headers_inherited() -> None:
    siblings = [
        _line(line_number=1, content="Activity", table_id="t1", row_index=0, col_index=0,
              block_type="table_cell"),
        _line(line_number=2, content="Review Frequency", table_id="t1", row_index=0,
              col_index=1, block_type="table_cell"),
        _line(line_number=3, content="Privileged account review", table_id="t1", row_index=1,
              col_index=0, block_type="table_cell", cell_label="Activity"),
        _line(line_number=4, content="Quarterly", table_id="t1", row_index=1, col_index=1,
              block_type="table_cell", cell_label="Review Frequency"),
    ]
    result = expand_line(siblings[3], siblings, window=4)
    assert result.strategy == "table_row"
    # Both cells in the row, each labelled by its column header.
    assert "Activity: Privileged account review" in result.content
    assert "Review Frequency: Quarterly" in result.content
    assert sorted(result.source_line_ids) == [3, 4]
    assert result.table_coordinates == {"table_id": "t1", "row_index": 1, "col_index": 1}


def test_paragraph_expands_to_a_bounded_window_within_its_section() -> None:
    siblings = [
        _line(line_number=n, content=f"Sentence {n}.", section_path="AC > Accounts",
              block_type="paragraph")
        for n in range(1, 8)
    ]
    result = expand_line(siblings[3], siblings, window=2)
    assert result.strategy == "window"
    assert sorted(result.source_line_ids) == [2, 3, 4, 5, 6]
    assert "Sentence 4." in result.content


def test_window_does_not_cross_a_section_boundary() -> None:
    siblings = [
        _line(line_number=1, content="Access text.", section_path="AC", block_type="paragraph"),
        _line(line_number=2, content="Trigger text.", section_path="AC", block_type="paragraph"),
        _line(line_number=3, content="Audit text.", section_path="AU", block_type="paragraph"),
    ]
    result = expand_line(siblings[1], siblings, window=3)
    assert 3 not in result.source_line_ids


def test_window_does_not_cross_a_page_boundary() -> None:
    siblings = [
        _line(line_number=1, content="Page one text.", page_number=1, block_type="paragraph"),
        _line(line_number=2, content="Trigger text.", page_number=1, block_type="paragraph"),
        _line(line_number=3, content="Page two text.", page_number=2, block_type="paragraph"),
    ]
    result = expand_line(siblings[1], siblings, window=3)
    assert 3 not in result.source_line_ids
    assert result.page_numbers == [1]


def test_window_on_headerless_lines_is_bounded_by_window_size_only() -> None:
    """``parsers/text.py`` — and therefore every ``PolicyVersion`` — never sets
    ``page_number`` beyond ``1`` or ``section_path`` at all, so the window's
    page/section guard is vacuously true for every sibling on a headerless
    source and the window ends up bounded solely by ``window``. Two unrelated
    policy chunks can fold into one unit as a result. That is documented,
    accepted behaviour (see the module docstring), not a bug — this test pins
    it down as an asserted property so a future change to the guard has to
    change this test too, instead of silently altering the guarantee.
    """
    siblings = [
        _line(line_number=1, content="Chunk one, sentence one."),
        _line(line_number=2, content="Chunk one, sentence two."),
        _line(line_number=3, content="Chunk one, sentence three."),
        _line(line_number=4, content="Chunk two, sentence one."),
        _line(line_number=5, content="Chunk two, sentence two."),
    ]
    result = expand_line(siblings[2], siblings, window=2)
    assert result.strategy == "window"
    assert sorted(result.source_line_ids) == [1, 2, 3, 4, 5]
    # No page_number or section_path was set on any line, so nothing separates
    # these two unrelated chunks — the window folds both together.
    assert "Chunk one" in result.content
    assert "Chunk two" in result.content


def test_isolated_line_falls_back_to_itself() -> None:
    only = _line(line_number=1, content="Standalone statement.", block_type="paragraph")
    result = expand_line(only, [only], window=4)
    assert result.strategy == "line"
    assert result.source_line_ids == [1]


def test_token_count_is_estimated_and_positive() -> None:
    only = _line(line_number=1, content="A statement worth about ten tokens here.",
                 block_type="paragraph")
    assert expand_line(only, [only], window=4).token_count > 0


async def test_expand_stage_builds_units_only_for_lines_above_threshold() -> None:
    org_id = await _org("prep-expand")
    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        run.stage_parse = "complete"
        run.stage_screen = "complete"
        keep = PrepLine(run_id=run.id, organization_id=org_id, line_number=1,
                        content="Multifactor authentication is required for admins.",
                        block_type="paragraph")
        drop = PrepLine(run_id=run.id, organization_id=org_id, line_number=2,
                        content="The quick brown fox jumped.", block_type="paragraph")
        s.add_all([keep, drop])
        await s.flush()
        s.add(PrepScreen(line_id=keep.id, run_id=run.id, organization_id=org_id,
                         relevance_score=0.9, candidate_controls=["IA-2"], above_threshold=True))
        s.add(PrepScreen(line_id=drop.id, run_id=run.id, organization_id=org_id,
                         relevance_score=0.0, candidate_controls=[], above_threshold=False))
        await s.flush()

        built = await run_stage_expand(s, run)
        assert built == 1
        assert run.units_built == 1
        assert run.stage_expand == "complete"
        units = (
            await s.execute(select(PrepUnit).where(PrepUnit.run_id == run.id))
        ).scalars().all()
        assert len(units) == 1
        assert units[0].trigger_line_id == keep.id
        assert units[0].source_kind == "policy_version"


async def test_expand_stage_populates_the_search_vector_via_trigger() -> None:
    """The tsvector must be maintained by the DB trigger, not application code."""
    org_id = await _org("prep-expand-tsv")
    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        run.stage_parse = run.stage_screen = "complete"
        line = PrepLine(run_id=run.id, organization_id=org_id, line_number=1,
                        content="Backups are written to offsite storage nightly.",
                        block_type="paragraph")
        s.add(line)
        await s.flush()
        s.add(PrepScreen(line_id=line.id, run_id=run.id, organization_id=org_id,
                         relevance_score=0.5, candidate_controls=["CP-9"], above_threshold=True))
        await s.flush()
        await run_stage_expand(s, run)
        unit = (
            await s.execute(select(PrepUnit).where(PrepUnit.run_id == run.id))
        ).scalar_one()
        await s.refresh(unit)
        assert unit.search_vector is not None
