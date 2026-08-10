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

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..ai import gateway
from ..config import get_settings
from ..logging import get_logger
from ..models_prep import PrepClassification, PrepEmbedding, PrepUnit

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
    except Exception as exc:  # degrade to lexical, never fail the caller
        log.info("prep.retrieve_vector_unavailable", org_id=org_id, error=str(exc))
        return []
    vector = response.vectors[0]
    distance = PrepEmbedding.embedding.cosine_distance(vector)
    stmt = select(PrepUnit.id).join(PrepEmbedding, PrepEmbedding.unit_id == PrepUnit.id)
    stmt = _base_filters(stmt, org_id=org_id, system_id=system_id, source_kind=source_kind)
    rows = (await session.execute(stmt.order_by(distance).limit(_CANDIDATE_DEPTH))).all()
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

    # Units the classifier tagged with this control rank first regardless of
    # text similarity: an explicit classification is a stronger signal than any
    # similarity score, and this is what makes retrieval control-aware rather
    # than merely semantic. Note: the screen stage collapses candidates to base
    # control identifiers (e.g. "AC-6(2)" -> "AC-6"), so this boost only fires
    # for base identifiers — an enhancement-level ``control_identifier`` passed
    # here will never match.
    tagged_stmt = (
        select(PrepUnit.id)
        .join(PrepClassification, PrepClassification.unit_id == PrepUnit.id)
        .where(PrepClassification.control_identifiers.op("@>")([control_identifier]))
    )
    tagged_stmt = _base_filters(
        tagged_stmt, org_id=org_id, system_id=system_id, source_kind=source_kind
    )
    tagged = [int(r[0]) for r in (await session.execute(tagged_stmt)).all()]

    fused = fuse(lexical=lexical, vector=vector)
    tagged_set = set(tagged)
    # Boost, not filter: an untagged unit can still be the best evidence when
    # classification was conservative.
    ordered = sorted(
        fused,
        key=lambda pair: (pair[0] in tagged_set, pair[1]),
        reverse=True,
    )[:top_n]
    if not ordered:
        return []

    lexical_positions = {unit_id: i + 1 for i, unit_id in enumerate(lexical)}
    vector_positions = {unit_id: i + 1 for i, unit_id in enumerate(vector)}

    unit_ids = [unit_id for unit_id, _ in ordered]
    rows = (
        await session.execute(
            select(PrepUnit, PrepClassification)
            .outerjoin(PrepClassification, PrepClassification.unit_id == PrepUnit.id)
            .where(PrepUnit.id.in_(unit_ids))
        )
    ).all()
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
