"""Hybrid retrieval over prepared evidence units.

Neither backend is sufficient alone. Embeddings handle paraphrase — "reviewed
every three months" against "quarterly review" — but treat control identifiers,
hostnames and product names as near-noise, because those tokens carry almost no
distributional meaning. Lexical search is exact on precisely those tokens and
blind to paraphrase. Reciprocal-rank fusion combines the two rankings without
needing their scores to be on comparable scales, which they are not.

Retrieval degrades rather than fails: if the embedding provider is unavailable,
results come back lexical-only with ``vector_rank`` unset, because a narrower
answer is worth more than an error to a caller assembling evidence for a control.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..ai import gateway
from ..ai.providers.base import ProviderError
from ..config import get_settings
from ..logging import get_logger
from ..models_prep import PrepClassification, PrepEmbedding, PrepUnit
from .screen import control_identifier_spellings

log = get_logger(__name__)

#: RRF damping constant. 60 is the value from the original Cormack et al. work
#: and is deliberately large relative to the result-set size, which keeps any
#: single backend from dominating on rank-1 alone.
_RRF_K = 60

#: How deep each backend ranks before fusion. Wider than the returned limit so a
#: unit ranked mid-list by both still has a chance to win on combined score.
_CANDIDATE_DEPTH = 50


@dataclass(slots=True)
class RetrievedUnit:
    """One retrieved passage with everything needed to cite it."""

    unit_id: int
    content: str
    score: float
    page_numbers: list[int]
    section_path: str | None
    table_coordinates: dict[str, Any] | None
    source_kind: str | None
    control_identifiers: list[str]
    evidence_strength: str | None
    lexical_rank: int | None
    vector_rank: int | None


def fuse(lexical: list[int], vector: list[int], *, k: int = _RRF_K) -> list[tuple[int, float]]:
    """Reciprocal-rank fusion of two ranked id lists, best first."""
    scores: dict[int, float] = {}
    for ranking in (lexical, vector):
        for position, unit_id in enumerate(ranking, start=1):
            scores[unit_id] = scores.get(unit_id, 0.0) + 1.0 / (k + position)
    return sorted(scores.items(), key=lambda pair: pair[1], reverse=True)


def _base_filters(
    stmt: Any, *, org_id: int, system_id: int | None, source_kind: str | None
) -> Any:
    stmt = stmt.where(PrepUnit.organization_id == org_id)
    if system_id is not None:
        stmt = stmt.where(PrepUnit.system_id == system_id)
    if source_kind is not None:
        stmt = stmt.where(PrepUnit.source_kind == source_kind)
    return stmt


async def _lexical_ids(
    session: AsyncSession,
    *,
    org_id: int,
    query_text: str,
    system_id: int | None,
    source_kind: str | None,
) -> list[int]:
    query = func.websearch_to_tsquery("english", query_text)
    rank = func.ts_rank(PrepUnit.search_vector, query)
    stmt = select(PrepUnit.id).where(PrepUnit.search_vector.op("@@")(query))
    stmt = _base_filters(stmt, org_id=org_id, system_id=system_id, source_kind=source_kind)
    rows = (await session.execute(stmt.order_by(rank.desc()).limit(_CANDIDATE_DEPTH))).all()
    return [int(r[0]) for r in rows]


async def _vector_ids(
    session: AsyncSession,
    *,
    org_id: int,
    query_text: str,
    system_id: int | None,
    source_kind: str | None,
) -> list[int]:
    try:
        response = await gateway.embed(
            session, org_id, texts=[query_text], purpose="prep.retrieve"
        )
    except (gateway.GatewayError, ProviderError) as exc:
        # Only a genuine provider-availability fault degrades to lexical-only;
        # anything else (e.g. a bug indexing a malformed response) must raise,
        # not be silently misreported as "provider unavailable".
        log.warning("prep.retrieve_vector_unavailable", org_id=org_id, error=str(exc))
        return []
    vector = response.vectors[0]
    distance = PrepEmbedding.embedding.cosine_distance(vector)
    stmt = select(PrepUnit.id).join(PrepEmbedding, PrepEmbedding.unit_id == PrepUnit.id)
    stmt = _base_filters(stmt, org_id=org_id, system_id=system_id, source_kind=source_kind)
    rows = (await session.execute(stmt.order_by(distance).limit(_CANDIDATE_DEPTH))).all()
    return [int(r[0]) for r in rows]


async def _tagged_ids(
    session: AsyncSession,
    *,
    org_id: int,
    control_identifier: str,
    system_id: int | None,
    source_kind: str | None,
) -> list[int]:
    """Units the classifier explicitly tagged with this control, best-effort
    deduplicated and ordered.

    The screen stage collapses candidates to base control identifiers (e.g.
    "AC-6(2)" -> "AC-6"), so ``PrepClassification.control_identifiers`` only
    ever holds base identifiers. The real ingested catalog is not
    consistently formatted -- "AC-02", "CP-9" and CMMC-style identifiers all
    coexist, confirmed live -- and ``score_line`` only normalizes what it
    writes *going forward*; it does not rewrite rows a prior run already
    persisted, nor any future write path that bypasses it. A read that only
    normalized the caller's identifier and compared it against whatever
    spelling happens to be stored would still silently miss a differently-
    spelled but equivalent stored value. So this checks containment against
    every spelling :func:`screen.control_identifier_spellings` considers
    equivalent (unpadded, two-digit zero-padded, and the identifier's own
    suffix-stripped form), ORed together -- both directions (``AC-2`` finds
    ``AC-02``-tagged evidence and vice versa) hold regardless of which
    spelling is actually on disk.

    Bounded and deterministically ordered: unbounded and unordered before this
    fix, so a tagged set larger than what actually influences the final
    ranking was a sequential scan on every call, and -- once bounded -- an
    ORDER BY is required too, or which rows survive the LIMIT would depend on
    Postgres's unspecified row order and could vary call to call. ``DISTINCT``
    guards against a unit matching more than one spelling (or a future schema
    change allowing more than one classification per unit per run) from
    double-counting ``tagged_boost`` below.
    """
    spellings = control_identifier_spellings(control_identifier)
    stmt = (
        select(PrepUnit.id)
        .distinct()
        .join(PrepClassification, PrepClassification.unit_id == PrepUnit.id)
        .where(
            or_(
                *(
                    PrepClassification.control_identifiers.op("@>")([spelling])
                    for spelling in spellings
                )
            )
        )
    )
    stmt = _base_filters(stmt, org_id=org_id, system_id=system_id, source_kind=source_kind)
    rows = (
        await session.execute(stmt.order_by(PrepUnit.id).limit(_CANDIDATE_DEPTH))
    ).all()
    return [int(r[0]) for r in rows]


async def retrieve(
    session: AsyncSession,
    *,
    org_id: int,
    control_identifier: str,
    query_text: str | None = None,
    system_id: int | None = None,
    source_kind: str | None = None,
    limit: int | None = None,
) -> list[RetrievedUnit]:
    """Retrieve prepared units supporting a control, best first."""
    top_n = limit if limit is not None else get_settings().ai_max_context_docs
    text_query = query_text or control_identifier

    lexical = await _lexical_ids(
        session, org_id=org_id, query_text=text_query,
        system_id=system_id, source_kind=source_kind,
    )
    vector = await _vector_ids(
        session, org_id=org_id, query_text=text_query,
        system_id=system_id, source_kind=source_kind,
    )

    # Units the classifier tagged with this control are a third retrieval
    # signal alongside lexical and vector: an explicit classification is
    # meaningful evidence that a similarity score alone would not capture.
    # The original, unstripped identifier is still used as lexical/vector
    # query text above, since "AC-6(2)" is a meaningful exact-match token
    # there -- only the tagged-boost lookup normalizes it (see _tagged_ids).
    tagged_ids = await _tagged_ids(
        session, org_id=org_id, control_identifier=control_identifier,
        system_id=system_id, source_kind=source_kind,
    )

    # A tagged unit contributes to its score the same way a rank-1 hit from
    # either other backend would. This composes with RRF rather than
    # overriding it — a tagged unit is boosted, but a genuinely superior
    # untagged match (e.g. ranked first by both other backends) can still
    # outrank a tagged unit that neither backend favored, which a strict
    # tagged-first sort tier would not allow.
    fused = dict(fuse(lexical=lexical, vector=vector))
    tagged_boost = 1.0 / (_RRF_K + 1)
    for unit_id in tagged_ids:
        fused[unit_id] = fused.get(unit_id, 0.0) + tagged_boost

    # Tiebreak by unit_id (ascending) is deliberate, not incidental: two units
    # can land on the identical fused score (most commonly two tagged-only
    # units that neither the lexical nor vector backend ranked at all, so they
    # share exactly ``tagged_boost``), and without a secondary key here the
    # order among them would depend on ``fused``'s dict-insertion order --
    # itself downstream of the tagged-set query above, which has no ordering
    # guarantee of its own without an explicit ORDER BY. A citation-bearing
    # compliance product cannot have "the same query returns different
    # evidence on two consecutive calls" as an observable behavior.
    ordered = sorted(fused.items(), key=lambda pair: (-pair[1], pair[0]))[:top_n]
    if not ordered:
        return []

    lexical_positions = {unit_id: i + 1 for i, unit_id in enumerate(lexical)}
    vector_positions = {unit_id: i + 1 for i, unit_id in enumerate(vector)}

    unit_ids = [unit_id for unit_id, _ in ordered]
    hydrate_stmt = (
        select(PrepUnit, PrepClassification)
        .outerjoin(PrepClassification, PrepClassification.unit_id == PrepUnit.id)
        .where(PrepUnit.id.in_(unit_ids))
    )
    # Defense in depth: unit_ids above only ever comes from the three scoped
    # candidate paths, but the point where evidence is actually handed to a
    # caller should not depend on that staying true forever.
    hydrate_stmt = _base_filters(
        hydrate_stmt, org_id=org_id, system_id=system_id, source_kind=source_kind
    )
    rows = (await session.execute(hydrate_stmt)).all()
    by_id = {int(unit.id): (unit, classification) for unit, classification in rows}

    results: list[RetrievedUnit] = []
    for unit_id, score in ordered:
        found = by_id.get(unit_id)
        if found is None:
            continue
        unit, classification = found
        results.append(
            RetrievedUnit(
                unit_id=unit_id,
                content=unit.content,
                score=score,
                page_numbers=[int(p) for p in (unit.page_numbers or [])],
                section_path=unit.section_path,
                table_coordinates=unit.table_coordinates,
                source_kind=unit.source_kind,
                control_identifiers=(
                    [str(c) for c in classification.control_identifiers]
                    if classification is not None
                    else []
                ),
                evidence_strength=(
                    classification.evidence_strength if classification is not None else None
                ),
                lexical_rank=lexical_positions.get(unit_id),
                vector_rank=vector_positions.get(unit_id),
            )
        )
    return results
