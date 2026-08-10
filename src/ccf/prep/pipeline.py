"""Stage orchestration for the evidence preparation pipeline.

Stages run in :data:`PREP_STAGES` order and each persists its full output before
the next begins, so a failure is recoverable: :func:`next_stage` returns the
first stage that is not ``complete`` and :func:`advance` restarts there rather
than re-parsing a document that already parsed cleanly.

Every stage is idempotent — it deletes its own prior output *before deciding its
outcome*, not only on the path that succeeds — so a run that previously parsed
successfully and is later re-run to a different outcome (source deleted, format
now unsupported, a genuine parse failure) never leaves stale rows or stale
``lines_parsed``/``parser_name`` behind. That property, held unconditionally, is
what makes retry and Task 15's crash recovery safe without a distributed
transaction.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, overload

from sqlalchemy import delete, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..logging import get_logger
from ..models_prep import PREP_STAGES, PrepLine, PrepRun
from .classify import run_stage_classify
from .embed import run_stage_embed
from .expand import run_stage_expand
from .parsers import UnsupportedMediaType, dispatch
from .screen import run_stage_screen
from .sources import SourceMissing, resolve_source

log = get_logger(__name__)

#: The signature every registered stage runner must satisfy. Tasks 9-13 each add
#: one more entry to :data:`_STAGE_RUNNERS` with this shape.
StageRunner = Callable[[AsyncSession, PrepRun], Awaitable[int]]


@overload
def _sanitize_text(value: str) -> str: ...
@overload
def _sanitize_text(value: str | None) -> str | None: ...
def _sanitize_text(value: str | None) -> str | None:
    """Strip NUL bytes before they reach a Postgres ``text`` column.

    ``\\x00`` is valid UTF-8, so ``decode_text``'s ``errors="replace"`` (and
    every other parser) passes it straight through untouched — none of the five
    parsers reject it, and nothing sets ``ParsedDocument.error`` for it. But
    Postgres's ``text`` type cannot store a NUL byte at all: it fails at
    ``flush()`` with ``CharacterNotInRepertoireError``. This is reachable on
    ordinary evidence — a truncated export, a null-padded fixed-width dump,
    binary content misidentified as text — not a contrived input.

    Sanitizing once here, at the boundary where parsed text becomes persisted
    text, covers all five parsers without duplicating the check in each one.
    Other C0 control characters (tab, newline, ...) are legal in a Postgres
    ``text`` column and may be meaningful in the source, so only NUL is
    stripped.
    """
    if value is None:
        return None
    return value.replace("\x00", "") if "\x00" in value else value


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
    # Idempotent from the first statement, not only on the success path: a run
    # that previously parsed successfully and is now re-run to orphaned,
    # unsupported, or failed must not keep its stale lines or stale counts.
    run.lines_parsed = 0
    run.parser_name = None
    await session.execute(delete(PrepLine).where(PrepLine.run_id == run.id))
    await session.flush()

    try:
        source = await resolve_source(session, run.source_kind, run.source_id)
    except SourceMissing as exc:
        run.status = "orphaned"
        run.stage_parse = "skipped"
        run.error = str(exc)
        await session.flush()
        log.info("prep.source_missing", run_id=run.id, reason=str(exc))
        return 0

    # Reconcile to the source's *true* organization the moment it is actually
    # known, rather than trusting whatever organization_id the run was opened
    # with. jobs.enqueue() already refuses a mismatch before a run is even
    # created, so in the normal path this is a no-op -- but every downstream
    # stage (screen/expand/classify/embed) tags its own output with
    # run.organization_id, and relying on the enqueue-time check alone to keep
    # that correct forever is fragile: a future caller of create_run that
    # skips enqueue() (direct pipeline use, a new entry point, a bug) would
    # silently reopen the split this line closes structurally. Parse is the
    # one stage that actually resolves the source, so it is the one place
    # that can make this authoritative rather than assumed.
    run.organization_id = source.organization_id
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
        await session.flush()
        log.info("prep.unsupported_media_type", run_id=run.id, reason=str(exc))
        return 0

    if parsed.error is not None:
        _fail(run, "parse", parsed.error)
        await session.flush()
        return 0

    lines = [
        PrepLine(
            run_id=run.id,
            organization_id=source.organization_id,
            line_number=record.line_number,
            page_number=record.page_number,
            section_path=_sanitize_text(record.section_path),
            block_id=record.block_id,
            block_type=record.block_type,
            table_id=record.table_id,
            row_index=record.row_index,
            col_index=record.col_index,
            cell_label=_sanitize_text(record.cell_label),
            content=_sanitize_text(record.content),
        )
        for record in parsed.iter_lines()
    ]

    try:
        # A savepoint isolates the write: if it fails (a value that slips past
        # ``_sanitize_text``, an out-of-range integer, any other constraint
        # violation), only these inserts roll back — the outer transaction, and
        # `run` itself, stay usable for the caller. A plain ``session.rollback()``
        # in the except clause below would instead discard the whole
        # transaction, including work the caller did before calling this stage.
        async with session.begin_nested():
            session.add_all(lines)
            await session.flush()
    except SQLAlchemyError as exc:
        _fail(run, "parse", f"failed to persist parsed lines: {exc}")
        await session.flush()
        return 0

    run.parser_name = parsed.parser_name
    run.lines_parsed = len(lines)
    run.stage_parse = "complete"
    await session.flush()
    log.info(
        "prep.parse_complete", run_id=run.id, lines=len(lines), parser=parsed.parser_name
    )
    return len(lines)


async def load_run(session: AsyncSession, run_id: int) -> PrepRun | None:
    return (
        await session.execute(select(PrepRun).where(PrepRun.id == run_id))
    ).scalar_one_or_none()


#: Stage implementations are registered here as later tasks add them, keeping
#: :func:`advance` free of a growing if/elif ladder.
_STAGE_RUNNERS: dict[str, StageRunner] = {
    "parse": run_stage_parse,
    "screen": run_stage_screen,
    "expand": run_stage_expand,
    "classify": run_stage_classify,
    "embed": run_stage_embed,
}


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
