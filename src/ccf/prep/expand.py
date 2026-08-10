"""Context expansion — turning a trigger line into an assessable passage.

A screened line is a pointer, not evidence. "Quarterly" is meaningless without
the column header above it; a procedure step is meaningless without the steps
around it. This stage grows each trigger line into the smallest passage that
stands on its own, preferring the tightest bound that still carries meaning:

1. the same table row, with every cell labelled by its column header
2. a bounded window of neighbouring lines within the same page and section
3. the trigger line alone

Windows never cross a page or section boundary. Splicing text from two sections
into one unit would produce a citation that points at a passage no reader can
find, which is worse than a narrower unit.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..logging import get_logger
from ..models_prep import PrepLine, PrepRun, PrepScreen, PrepUnit

log = get_logger(__name__)

#: Rough token estimate. Exact tokenisation would need the target model's
#: tokeniser; this is only used to bound prompt size, so an approximation is fine.
_CHARS_PER_TOKEN = 4


@dataclass(slots=True)
class ExpansionResult:
    """One expanded passage plus the provenance needed to cite it."""

    trigger_line_id: int
    source_line_ids: list[int]
    content: str
    page_numbers: list[int]
    section_path: str | None
    table_coordinates: dict[str, Any] | None
    token_count: int
    strategy: str


def _estimate_tokens(text: str) -> int:
    return max(1, len(text) // _CHARS_PER_TOKEN)


def _render_cell(line: PrepLine) -> str:
    """Label a cell with its column header, which is what makes it legible."""
    return f"{line.cell_label}: {line.content}" if line.cell_label else line.content


def _build(
    trigger: PrepLine, members: list[PrepLine], strategy: str, content: str
) -> ExpansionResult:
    pages = sorted({m.page_number for m in members if m.page_number is not None})
    coordinates = (
        {
            "table_id": trigger.table_id,
            "row_index": trigger.row_index,
            "col_index": trigger.col_index,
        }
        if trigger.table_id is not None
        else None
    )
    return ExpansionResult(
        trigger_line_id=trigger.id,
        source_line_ids=[m.id for m in members],
        content=content,
        page_numbers=pages,
        section_path=trigger.section_path,
        table_coordinates=coordinates,
        token_count=_estimate_tokens(content),
        strategy=strategy,
    )


def expand_line(trigger: PrepLine, siblings: list[PrepLine], *, window: int) -> ExpansionResult:
    """Grow ``trigger`` into the tightest passage that still stands alone."""
    if trigger.table_id is not None and trigger.row_index is not None:
        row = [
            line
            for line in siblings
            if line.table_id == trigger.table_id and line.row_index == trigger.row_index
        ]
        if len(row) > 1:
            row.sort(key=lambda line: (line.col_index if line.col_index is not None else 0))
            return _build(trigger, row, "table_row", " | ".join(_render_cell(x) for x in row))

    ordered = sorted(siblings, key=lambda line: line.line_number)
    try:
        position = next(
            index for index, line in enumerate(ordered) if line.id == trigger.id
        )
    except StopIteration:  # pragma: no cover — trigger is always among its siblings
        return _build(trigger, [trigger], "line", trigger.content)

    neighbours = ordered[max(0, position - window) : position + window + 1]
    members = [
        line
        for line in neighbours
        if line.page_number == trigger.page_number
        and line.section_path == trigger.section_path
    ]
    if len(members) > 1:
        return _build(trigger, members, "window", " ".join(x.content for x in members))

    return _build(trigger, [trigger], "line", trigger.content)


async def run_stage_expand(session: AsyncSession, run: PrepRun) -> int:
    """Build a unit for every above-threshold line. Returns the count built."""
    run.stage_expand = "running"

    # Idempotent: clear prior output so a resumed run cannot double-write.
    await session.execute(delete(PrepUnit).where(PrepUnit.run_id == run.id))

    all_lines = (
        await session.execute(
            select(PrepLine).where(PrepLine.run_id == run.id).order_by(PrepLine.line_number)
        )
    ).scalars().all()
    triggers = (
        await session.execute(
            select(PrepLine)
            .join(PrepScreen, PrepScreen.line_id == PrepLine.id)
            .where(PrepScreen.run_id == run.id, PrepScreen.above_threshold.is_(True))
            .order_by(PrepLine.line_number)
        )
    ).scalars().all()

    window = int(run.config_snapshot.get("expand_window", 4))
    system_id = await _system_id_for(session, run)

    built = 0
    for trigger in triggers:
        result = expand_line(trigger, list(all_lines), window=window)
        session.add(
            PrepUnit(
                run_id=run.id,
                organization_id=run.organization_id,
                trigger_line_id=result.trigger_line_id,
                source_line_ids=result.source_line_ids,
                content=result.content,
                page_numbers=result.page_numbers,
                section_path=result.section_path,
                table_coordinates=result.table_coordinates,
                token_count=result.token_count,
                system_id=system_id,
                source_kind=run.source_kind,
            )
        )
        built += 1

    run.units_built = built
    run.stage_expand = "complete"
    await session.flush()
    log.info("prep.expand_complete", run_id=run.id, units=built, window=window)
    return built


async def _system_id_for(session: AsyncSession, run: PrepRun) -> int | None:
    """Denormalise the owning system onto units so retrieval filters without a join."""
    if run.source_kind != "evidence_version":
        return None
    from .sources import SourceMissing, resolve_source  # noqa: PLC0415 — avoids a cycle

    try:
        return (await resolve_source(session, run.source_kind, run.source_id)).system_id
    except SourceMissing:
        return None
