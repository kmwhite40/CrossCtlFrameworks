"""Vector embedding of prepared units.

Batched because per-unit round trips dominate wall-clock on any real corpus, and
dimension-validated because pgvector columns are fixed width: a provider or model
change that alters the vector length must fail loudly at the stage boundary
rather than write truncated vectors that silently poison retrieval.

``model_name`` is recorded per row so a corpus embedded across a model change is
detectable — mixing two embedding spaces in one index degrades ranking in ways
that are very hard to diagnose after the fact.
"""

from __future__ import annotations

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..ai import gateway
from ..config import get_settings
from ..logging import get_logger
from ..models_prep import PREP_EMBEDDING_DIM, PrepEmbedding, PrepRun, PrepUnit

log = get_logger(__name__)


class DimensionMismatch(ValueError):  # noqa: N818 -- name fixed by the interface contract
    """The provider returned vectors of an unexpected width."""


async def run_stage_embed(session: AsyncSession, run: PrepRun) -> int:
    """Embed every unit in the run. Returns the count embedded."""
    run.stage_embed = "running"

    # Idempotent: clear prior output so a resumed run cannot double-write.
    await session.execute(delete(PrepEmbedding).where(PrepEmbedding.run_id == run.id))

    units = (
        await session.execute(
            select(PrepUnit).where(PrepUnit.run_id == run.id).order_by(PrepUnit.id)
        )
    ).scalars().all()
    if not units:
        run.units_embedded = 0
        run.stage_embed = "complete"
        await session.flush()
        return 0

    settings = get_settings()
    batch_size = max(1, settings.prep_worker_batch_size)
    expected = int(run.config_snapshot.get("embed_dimensions", settings.prep_embed_dimensions))

    embedded = 0
    for start in range(0, len(units), batch_size):
        batch = units[start : start + batch_size]
        try:
            response = await gateway.embed(
                session,
                run.organization_id,
                texts=[unit.content for unit in batch],
                purpose="prep.embed",
            )
            for vector in response.vectors:
                if len(vector) != expected or len(vector) != PREP_EMBEDDING_DIM:
                    raise DimensionMismatch(
                        f"provider returned {len(vector)}-dimension vectors; "
                        f"schema requires {PREP_EMBEDDING_DIM}"
                    )
        except Exception as exc:  # any fault leaves the run resumable, not raised
            # A mid-run failure (provider fault or dimension mismatch) must not
            # leave rows for whichever batches already succeeded this attempt
            # while the run's own counter and status say otherwise: clear that
            # partial output and zero the counter so persisted rows agree with
            # `units_embedded` at every point after this returns. The session
            # factory runs with autoflush disabled (src/ccf/db.py), so the
            # embeddings added in earlier iterations of this loop are still
            # pending — flush first so the delete actually finds and removes
            # them, rather than deleting zero rows and then flushing the
            # "orphaned" partial inserts back in afterward.
            await session.flush()
            await session.execute(
                delete(PrepEmbedding).where(PrepEmbedding.run_id == run.id)
            )
            run.units_embedded = 0
            run.status = "failed"
            run.stage_embed = "failed"
            run.error_stage = "embed"
            run.error = f"embedding failed: {exc}"
            await session.flush()
            log.warning("prep.embed_failed", run_id=run.id, error=str(exc))
            return 0

        for unit, vector in zip(batch, response.vectors, strict=True):
            session.add(
                PrepEmbedding(
                    unit_id=unit.id,
                    run_id=run.id,
                    organization_id=run.organization_id,
                    model_name=response.model,
                    embedding=vector,
                )
            )
            embedded += 1

    run.units_embedded = embedded
    run.stage_embed = "complete"
    await session.flush()
    log.info("prep.embed_complete", run_id=run.id, units=embedded)
    return embedded
