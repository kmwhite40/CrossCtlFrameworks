"""First-pass relevance screening against Concord's own 800-53A catalog.

The pipeline cannot afford to reason over every line of every document, so a
cheap gate decides what reaches the model. Concord's ETL already loads the full
catalog into ``ccf.controls`` with a GIN-indexed ``search_vector`` covering the
control name, description and assessment objective — so screening is a ranked
full-text join against data the platform already owns. There is no keyword
dictionary to write, and the screen tracks catalog updates automatically on the
next workbook ingest.

Screening is deliberately inclusive. A false positive costs one classification
call and is corrected downstream; a false negative silently removes evidence from
every assessment that would have cited it. The threshold lives in the run's
``config_snapshot`` rather than live settings, so changing the default cannot
retroactively reinterpret a run already in flight.
"""

from __future__ import annotations

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..logging import get_logger
from ..models import Control
from ..models_prep import PrepLine, PrepRun, PrepScreen

log = get_logger(__name__)

#: Candidate controls recorded per line. Enough to give the classifier real
#: choice without turning the prompt into a catalog dump.
_MAX_CANDIDATES = 5

#: Lines shorter than this carry no usable signal ("Yes", "N/A", a page number)
#: and would otherwise match noisily against short control names.
_MIN_CONTENT_CHARS = 12


async def score_line(
    session: AsyncSession, *, content: str, limit: int = _MAX_CANDIDATES
) -> list[tuple[str, float]]:
    """Rank catalog controls against one line, best first.

    ``websearch_to_tsquery`` ANDs bare terms together, which is the wrong
    semantics here: a one-sentence line naming several concepts ("Administrators
    must use multifactor authentication") only matches a control whose search
    vector happens to contain every one of those words, including filler like
    "must" and "use" that a control name or description would never repeat.
    Screening needs the opposite bias — a line should surface a control it
    *partially* overlaps with, since a false negative here silently drops
    evidence for good. So the query is built by OR-ing together the line's own
    lexemes (after the same english-config stemming/stopword pass the catalog's
    ``search_vector`` was built with), and ranked with ``ts_rank_cd`` — cover
    density weights matching terms that cluster together, which separates a
    genuine topical match from a coincidental single-word overlap far better
    than ``ts_rank``'s scale does for documents this short.
    """
    if len(content.strip()) < _MIN_CONTENT_CHARS:
        return []
    lexemes = func.array_to_string(
        func.tsvector_to_array(func.to_tsvector("english", content)), " | "
    )
    query = func.to_tsquery("english", lexemes)
    rank = func.ts_rank_cd(Control.search_vector, query)
    rows = (
        await session.execute(
            select(Control.identifier, rank.label("rank"))
            .where(Control.search_vector.op("@@")(query))
            .order_by(rank.desc())
            .limit(limit)
        )
    ).all()
    return [(str(identifier), float(value)) for identifier, value in rows]


async def run_stage_screen(session: AsyncSession, run: PrepRun) -> int:
    """Screen every parsed line. Returns the count above threshold."""
    run.stage_screen = "running"
    threshold = float(run.config_snapshot.get("screen_threshold", 0.0))

    # Idempotent: clear prior output so a resumed run cannot double-write.
    await session.execute(delete(PrepScreen).where(PrepScreen.run_id == run.id))

    lines = (
        (
            await session.execute(
                select(PrepLine).where(PrepLine.run_id == run.id).order_by(PrepLine.line_number)
            )
        )
        .scalars()
        .all()
    )

    above = 0
    for line in lines:
        ranked = await score_line(session, content=line.content)
        score = ranked[0][1] if ranked else 0.0
        is_above = bool(ranked) and score >= threshold
        above += int(is_above)
        session.add(
            PrepScreen(
                line_id=line.id,
                run_id=run.id,
                organization_id=run.organization_id,
                relevance_score=score,
                candidate_controls=[identifier for identifier, _ in ranked],
                above_threshold=is_above,
                method="catalog_fts",
            )
        )

    run.lines_above_threshold = above
    run.stage_screen = "complete"
    await session.flush()
    log.info(
        "prep.screen_complete",
        run_id=run.id,
        lines=len(lines),
        above_threshold=above,
        threshold=threshold,
    )
    return above
