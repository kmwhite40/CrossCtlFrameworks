"""Stage orchestration for the evidence preparation pipeline.

Stages run in :data:`PREP_STAGES` order and each persists its full output before
the next begins, so a failure is recoverable: :func:`next_stage` returns the
first stage that is not ``complete`` and :func:`advance` restarts there rather
than re-parsing a document that already parsed cleanly.

Every stage is idempotent — it deletes its own prior output before writing — so a
resumed or retried run cannot double-write. That property is what makes retry
safe without a distributed transaction.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..logging import get_logger
from ..models_prep import PREP_STAGES, PrepLine, PrepRun
from .parsers import UnsupportedMediaType, dispatch
from .sources import SourceMissing, resolve_source

log = get_logger(__name__)

#: The signature every registered stage runner must satisfy. Tasks 9-13 each add
#: one more entry to :data:`_STAGE_RUNNERS` with this shape.
StageRunner = Callable[[AsyncSession, PrepRun], Awaitable[int]]


def next_stage(run: PrepRun) -> str | None:
    """Return the first stage that is not ``complete``, or ``None`` if all are."""
    for stage in PREP_STAGES:
        if getattr(run, f"stage_{stage}") not in ("complete", "skipped"):
            return stage
    return None


async def create_run(
    session: AsyncSession, *, organization_id: int, source_kind: str, source_id: int
) -> PrepRun:
    """Open a run, snapshotting the thresholds in force so re-runs are comparable."""
    settings = get_settings()
    snapshot: dict[str, Any] = {
        "screen_threshold": settings.prep_screen_threshold,
        "expand_window": settings.prep_expand_window,
        "embed_provider": settings.prep_embed_provider,
        "embed_model": settings.prep_embed_model,
        "embed_dimensions": settings.prep_embed_dimensions,
    }
    run = PrepRun(
        organization_id=organization_id,
        source_kind=source_kind,
        source_id=source_id,
        status="pending",
        config_snapshot=snapshot,
    )
    session.add(run)
    await session.flush()
    return run


def _fail(run: PrepRun, stage: str, message: str) -> None:
    run.status = "failed"
    setattr(run, f"stage_{stage}", "failed")
    run.error_stage = stage
    run.error = message
    log.warning("prep.stage_failed", run_id=run.id, stage=stage, error=message)


async def run_stage_parse(session: AsyncSession, run: PrepRun) -> int:
    """Parse the source into ``prep_lines``. Returns the number of lines persisted."""
    run.status = "running"
    run.stage_parse = "running"

    try:
        source = await resolve_source(session, run.source_kind, run.source_id)
    except SourceMissing as exc:
        run.status = "orphaned"
        run.stage_parse = "skipped"
        run.error = str(exc)
        log.info("prep.source_missing", run_id=run.id, reason=str(exc))
        return 0

    run.media_type = source.media_type
    try:
        parsed = dispatch(source.data, source.filename, source.media_type)
    except UnsupportedMediaType as exc:
        # A known coverage gap (image OCR, Visio), not an error: recording it as
        # ``unsupported`` keeps it visible and reportable rather than noise in
        # the failure counts.
        run.status = "unsupported"
        run.stage_parse = "skipped"
        run.error = str(exc)
        log.info("prep.unsupported_media_type", run_id=run.id, reason=str(exc))
        return 0

    if parsed.error is not None:
        _fail(run, "parse", parsed.error)
        return 0

    # Idempotent: clear prior output so a resumed run cannot double-write.
    await session.execute(delete(PrepLine).where(PrepLine.run_id == run.id))

    count = 0
    for record in parsed.iter_lines():
        session.add(
            PrepLine(
                run_id=run.id,
                organization_id=source.organization_id,
                line_number=record.line_number,
                page_number=record.page_number,
                section_path=record.section_path,
                block_id=record.block_id,
                block_type=record.block_type,
                table_id=record.table_id,
                row_index=record.row_index,
                col_index=record.col_index,
                cell_label=record.cell_label,
                content=record.content,
            )
        )
        count += 1

    run.parser_name = parsed.parser_name
    run.lines_parsed = count
    run.stage_parse = "complete"
    await session.flush()
    log.info("prep.parse_complete", run_id=run.id, lines=count, parser=parsed.parser_name)
    return count


async def load_run(session: AsyncSession, run_id: int) -> PrepRun | None:
    return (
        await session.execute(select(PrepRun).where(PrepRun.id == run_id))
    ).scalar_one_or_none()


#: Stage implementations are registered here as later tasks add them, keeping
#: :func:`advance` free of a growing if/elif ladder.
_STAGE_RUNNERS: dict[str, StageRunner] = {"parse": run_stage_parse}


async def advance(session: AsyncSession, run: PrepRun) -> PrepRun:
    """Run every stage not yet complete, in order, stopping on failure."""
    while (stage := next_stage(run)) is not None:
        runner = _STAGE_RUNNERS.get(stage)
        if runner is None:
            # Stage not yet implemented — leave the run resumable rather than
            # marking it complete on work that never ran.
            log.info("prep.stage_not_implemented", run_id=run.id, stage=stage)
            break
        await runner(session, run)
        if run.status in ("failed", "unsupported", "orphaned"):
            return run
    if next_stage(run) is None:
        run.status = "complete"
    await session.flush()
    return run
