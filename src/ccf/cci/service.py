"""Load and query DISA CCI reference data."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..catalog.oscal import OscalCatalog, load_oscal_catalog
from ..logging import get_logger
from ..models_cci import CciControlRef, CciItemRow
from .reader import DEFAULT_CCI_HTML, read_cci_html
from .resolve import catalog_index, resolve_reference

log = get_logger(__name__)

#: How many items' worth of reference rows to buffer between flushes in the
#: second pass. Flushing every item (as a naive port of the per-item loop
#: would) makes a 5,149-item / 10,216-reference load slow -- one round trip
#: per item just to learn its new primary key. Splitting the work into two
#: passes (upsert all items, flush once to assign ids, then attach references
#: in batches) cuts round trips by roughly three orders of magnitude with
#: identical results.
_FLUSH_BATCH_SIZE = 500


@dataclass(frozen=True)
class LoadResult:
    version: str
    source_sha256: str
    items_created: int
    items_updated: int
    refs_written: int
    refs_unresolved: int
    skipped_unchanged: bool


async def load_cci_list(
    session: AsyncSession,
    *,
    path: Path | None = None,
    catalog: OscalCatalog | None = None,
) -> LoadResult:
    """Upsert the CCI list. Re-loading identical content writes nothing."""
    parsed = read_cci_html(path or DEFAULT_CCI_HTML)
    existing = {
        row.cci: row for row in (await session.execute(select(CciItemRow))).scalars().all()
    }
    if existing and all(r.source_sha256 == parsed.source_sha256 for r in existing.values()):
        return LoadResult(
            version=parsed.version,
            source_sha256=parsed.source_sha256,
            items_created=0,
            items_updated=0,
            refs_written=0,
            refs_unresolved=0,
            skipped_unchanged=True,
        )

    control_ids, part_ids = catalog_index(catalog or load_oscal_catalog())
    created = updated = refs = unresolved = 0

    # Pass 1: upsert every item's scalar fields, then flush once so every row
    # (new or existing) has a settled primary key before pass 2 needs it.
    rows: dict[str, CciItemRow] = {}
    for item in parsed.items:
        row = existing.get(item.cci)
        if row is None:
            row = CciItemRow(cci=item.cci)
            session.add(row)
            created += 1
        else:
            updated += 1
        row.status = item.status
        row.type = item.type
        row.contributor = item.contributor
        row.published_date = item.published_date
        row.definition = item.definition
        row.source_version = parsed.version
        row.source_sha256 = parsed.source_sha256
        rows[item.cci] = row

    await session.flush()

    # References are replaced wholesale: a revision that drops a reference
    # must not leave the old edge behind. Deleting for every item up front
    # (rather than per item, immediately before that item's inserts) is
    # equivalent here -- the id sets are disjoint -- and is one round trip.
    cci_ids = [row.id for row in rows.values()]
    if cci_ids:
        await session.execute(delete(CciControlRef).where(CciControlRef.cci_id.in_(cci_ids)))

    # Pass 2: attach references now that every row.id is known, flushing in
    # batches rather than once per item.
    for i, item in enumerate(parsed.items, start=1):
        row = rows[item.cci]
        for ref in item.references:
            # Only Rev. 5 has a catalog here, so only Rev. 5 gets the real
            # part_ids to check the reference's item against -- passing an
            # empty set for every other revision guarantees oscal_part_id
            # comes back null by construction (not a failed lookup) without
            # spending a real catalog membership check on a result that
            # would be discarded anyway. canonical_control / oscal_control_id
            # are unaffected: both are derived from control_ids alone, which
            # every revision still receives.
            resolved = resolve_reference(
                ref.raw_index,
                control_ids=control_ids,
                part_ids=part_ids if ref.revision == "5" else frozenset(),
            )
            if ref.revision == "5" and resolved.oscal_part_id is None:
                unresolved += 1
            session.add(
                CciControlRef(
                    cci_id=row.id,
                    revision=ref.revision,
                    raw_index=ref.raw_index,
                    canonical_control=resolved.canonical_control,
                    oscal_control_id=resolved.oscal_control_id,
                    oscal_part_id=resolved.oscal_part_id,
                )
            )
            refs += 1

        if i % _FLUSH_BATCH_SIZE == 0:
            await session.flush()

    await session.flush()
    log.info(
        "cci.loaded",
        version=parsed.version,
        created=created,
        updated=updated,
        refs=refs,
        unresolved=unresolved,
    )
    return LoadResult(
        version=parsed.version,
        source_sha256=parsed.source_sha256,
        items_created=created,
        items_updated=updated,
        refs_written=refs,
        refs_unresolved=unresolved,
        skipped_unchanged=False,
    )
