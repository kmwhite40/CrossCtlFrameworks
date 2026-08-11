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

import re

from sqlalchemy import delete, func, select
from sqlalchemy.exc import SQLAlchemyError
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


#: ``ts_rank_cd``'s normalization bitmask: 32 rescales the raw (unbounded)
#: cover-density score into ``rank/(rank+1)`` — i.e. 0..1. This is a strictly
#: monotonic transform: it cannot change any ranking or top-N decision. Its
#: only purpose is making ``prep_screen_threshold`` a comparable, bounded
#: number instead of an unbounded raw score whose useful range depends on
#: catalog size and term weighting. (The actual precision fix here is the
#: ``control_name`` filter and the base-control collapse below — see
#: ``score_line``'s docstring.)
_RANK_NORMALIZATION = 32

#: Strips an enhancement suffix from a control identifier: ``AC-06(02)`` ->
#: ``AC-06``. Matches every identifier in ``ccf.controls`` that has a
#: populated ``control_name`` except a handful (~13 of 1,206) belonging to a
#: differently-shaped cross-mapped framework (e.g. ``GR-1.a``); those have no
#: parenthesized suffix to strip, so the regex is a no-op on them and they
#: collapse to themselves, same as a base control would.
_BASE_CONTROL_PATTERN = r"\(.*$"

#: The NIST-style "family-number" shape once any enhancement suffix has been
#: stripped: letters, a hyphen, digits only (``AC-2``, ``AC-02``, ``CP-9``).
#: CMMC-style identifiers (``AC.L2-3.1.1``) have a dot before the hyphen and
#: dotted segments after it, so this never matches them -- they fall through
#: :func:`normalize_control_identifier` unchanged.
_PADDED_FAMILY_PATTERN = re.compile(r"^([A-Za-z]+)-0*(\d+)$")


def normalize_control_identifier(identifier: str) -> str:
    """Fold a control identifier to Concord's canonical, unpadded tag form.

    The real ingested catalog is not consistently formatted: zero-padded
    (``AC-02``), unpadded (``CP-9``), and CMMC-style (``AC.L2-3.1.1``) forms
    all coexist in ``ccf.controls.identifier`` (confirmed live against the
    test catalog). ``EvidenceObject.control_id`` documents Concord's own
    canonical tag as unpadded (``models_evidence.py``: "tag (e.g. AC-2)"), so
    that is the form this folds to.

    Without this, a value stored verbatim from the catalog (e.g. ``AC-02``,
    written by :func:`score_line` below into ``PrepScreen.candidate_controls``
    and carried through unchanged into
    ``PrepClassification.control_identifiers``) is unreachable by a caller
    spelling the same control ``AC-2`` -- silently: ``@>`` containment and
    ``==`` are exact-string operations, so a mismatch produces zero results,
    not an error.

    Strips any parenthesized enhancement suffix first (the same scope as
    :data:`_BASE_CONTROL_PATTERN`), then, only for the plain
    ``LETTERS-DIGITS`` shape, strips leading zeros from the numeric segment.
    CMMC-style identifiers never match that shape and pass through unchanged
    apart from the suffix strip -- there is no padding convention to
    reconcile for them, and folding their dotted segments would risk
    collapsing two genuinely different requirements into one identifier.

    ``retriever.py`` imports this function directly (the same object, not a
    re-implementation) so the two modules' idea of "the same control" cannot
    drift apart the way ``_BASE_CONTROL_PATTERN``-only stripping already
    proved it could for padding.
    """
    base = re.sub(_BASE_CONTROL_PATTERN, "", identifier).strip()
    match = _PADDED_FAMILY_PATTERN.match(base)
    if match is None:
        return base
    family, number = match.groups()
    return f"{family}-{number}"


def control_identifier_spellings(identifier: str) -> list[str]:
    """Every spelling of ``identifier`` that ``PrepClassification.control_identifiers``
    could actually contain, for an exact-match lookup (Postgres's jsonb ``@>``)
    against data that may not have been written through
    :func:`normalize_control_identifier`.

    :func:`score_line` normalizes everything it writes going forward, but that
    is a write-side guarantee, not a read-side one: rows written before this
    normalization existed, or by any future write path that bypasses it,
    still hold whatever spelling the catalog used verbatim (``AC-02``, not
    ``AC-2``). A read that only checks the canonical spelling would still
    silently miss those rows -- normalizing one side of an exact-match
    comparison is not sufficient when the other side isn't guaranteed
    normalized too. So this returns every spelling worth checking:
    the canonical (unpadded) form, and the two-digit zero-padded form (the
    padding width observed in the real catalog -- ``AC-01``, ``AC-02``,
    ``AC-99``). For a CMMC-style or otherwise non-family-number identifier,
    where there is no padding convention to reconcile, this returns exactly
    the one (suffix-stripped) form.
    """
    base = re.sub(_BASE_CONTROL_PATTERN, "", identifier).strip()
    match = _PADDED_FAMILY_PATTERN.match(base)
    if match is None:
        return [base]
    family, number = match.groups()
    return sorted({base, f"{family}-{number}", f"{family}-{number.zfill(2)}"})


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

    Two refinements were added after measuring this query against the real,
    fully-ingested catalog (~5,400 rows: ~1,200 base/enhancement controls, the
    rest fine-grained per-assessment-objective and per-ODP fragments) rather
    than a handful of hand-picked fixture rows:

    * **Candidates are restricted to rows with a populated ``control_name``,
      which is where essentially all of the precision gain over the first cut
      of this query came from.** The catalog's granular per-AO/per-ODP rows
      (e.g. ``IA-02(06)_ODP[03]``) share a control's identifier prefix but
      carry no addressable name of their own and mostly generic procedural
      language ("Determine if: ..."). Left in, ~4,224 of them compete on
      roughly the same terms as every other line in the catalog and drown out
      the ~1,200 base/enhancement rows that Task 12's classifier can actually
      act on and cite. Excluding them is a precision fix, not a recall one —
      it does not remove any control a classifier could be handed downstream.
      (Normalizing the score, below, does *not* contribute to this — it is a
      monotonic rescaling and reorders nothing.)
    * **Candidates are collapsed to one row per base control before
      truncating to ``limit``.** Even after the ``control_name`` filter, a
      control with many enhancements (e.g. AC-06's ten) can occupy every slot
      in the candidate window with its own enhancements, pushing the base
      control itself out — measured directly: AC-06 ranked 27th and IR-06
      ranked 9th for unambiguous sentences before this fix, both outside
      ``_MAX_CANDIDATES``. Grouping by the identifier with any parenthesized
      enhancement suffix stripped, and keeping each group's best score, means
      one family can supply at most one of the five slots, so a
      well-represented family doesn't crowd out a different, equally-relevant
      one — or itself.
    * **The score is normalized (bitmask 32).** Raw ``ts_rank_cd`` is
      unbounded and scales with how much matching text a document has, not
      with topical relevance, so a fixed threshold meaningful against a
      three-row test fixture is meaningless at catalog scale. This is purely
      a rescaling for a stable, comparable ``prep_screen_threshold`` — it
      changes no ranking decision on its own.
    """
    if len(content.strip()) < _MIN_CONTENT_CHARS:
        return []
    lexemes = func.array_to_string(
        func.tsvector_to_array(func.to_tsvector("english", content)), " | "
    )
    query = func.to_tsquery("english", lexemes)
    rank = func.ts_rank_cd(Control.search_vector, query, _RANK_NORMALIZATION)
    base_control = func.regexp_replace(Control.identifier, _BASE_CONTROL_PATTERN, "")
    per_row = (
        select(base_control.label("base"), rank.label("rank"))
        .where(Control.search_vector.op("@@")(query))
        .where(Control.control_name.isnot(None))
        .where(Control.control_name != "")
    ).subquery()
    best_per_base = func.max(per_row.c.rank).label("rank")
    rows = (
        await session.execute(
            select(per_row.c.base, best_per_base)
            .group_by(per_row.c.base)
            .order_by(best_per_base.desc())
            .limit(limit)
        )
    ).all()
    # The SQL grouping above already collapsed enhancement suffixes; folding
    # padding here too means every value this function ever returns -- and
    # therefore everything downstream that copies it verbatim
    # (``PrepScreen.candidate_controls``, then ``PrepClassification.
    # control_identifiers``) -- is in Concord's one canonical form, regardless
    # of how the source catalog row happened to be spelled.
    #
    # Folding padding *after* the SQL-level grouping means two distinct
    # catalog spellings of the same control (e.g. a padded "AC-02" row and an
    # unpadded "AC-2" row -- the base-control-collapse grouping above has no
    # way to know those are the same control, since it only strips enhancement
    # suffixes) can normalize to the same identifier here. Deduplicating and
    # keeping the stronger match, rather than returning the same control
    # twice, is what the base-control collapse already promises for
    # enhancement suffixes -- this extends that same guarantee to padding.
    normalized: dict[str, float] = {}
    for base, value in rows:
        identifier = normalize_control_identifier(str(base))
        score = float(value)
        if identifier not in normalized or score > normalized[identifier]:
            normalized[identifier] = score
    return sorted(normalized.items(), key=lambda pair: pair[1], reverse=True)[:limit]


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
    skipped = 0
    for line in lines:
        try:
            # A savepoint isolates this line's query: OR-ing every lexeme of
            # one oversized or pathologically dense line into a single
            # to_tsquery can blow past Postgres's own limits --
            # StatementTooComplexError (stack depth, reproduced live around
            # 30,000 distinct lexemes) or "string is too long for tsvector"
            # (around 1MB) -- and nothing upstream caps PrepLine.content
            # length. Without the savepoint, that error aborts the whole
            # transaction: every PrepScreen row already added earlier in this
            # loop would be lost, the run would die instead of finishing, and
            # (via jobs.run_once) the failure would strand the rest of a
            # claimed batch too. The same pattern pipeline.run_stage_parse
            # already uses for exactly this reason.
            async with session.begin_nested():
                ranked = await score_line(session, content=line.content)
        except SQLAlchemyError as exc:
            skipped += 1
            ranked = []
            log.warning(
                "prep.screen_line_skipped",
                run_id=run.id,
                line_id=line.id,
                line_number=line.line_number,
                error=str(exc),
            )
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
        skipped=skipped,
    )
    return above
