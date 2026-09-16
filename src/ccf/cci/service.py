"""Load and query DISA CCI reference data."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..catalog.oscal import OscalCatalog, load_oscal_catalog
from ..logging import get_logger
from ..models_cci import CciAssessmentOverlay, CciControlRef, CciItemRow
from .overlay import DEFAULT_CCI_ODS, OVERLAY_SOURCE, read_overlay_ods
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
            # would be discarded anyway.
            #
            # canonical_control / oscal_control_id are NOT unaffected: they
            # are matched against control_ids, which is always Rev. 5's set
            # regardless of ref.revision. For a Rev. 5 reference that is
            # verified; for any other revision it is the only catalog this
            # platform holds, so it is a best-effort cross-revision estimate
            # that can silently report a base control when the reference
            # names an enhancement, or null when the control was withdrawn
            # since the cited revision. `resolved.status` records which case
            # applied -- see `ccf.cci.resolve.ResolutionStatus` -- and is
            # persisted below so a caller can tell a verified Rev. 5 answer
            # apart from an unverified older-revision guess.
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
                    resolution_status=resolved.status.value,
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


async def load_cci_overlay(session: AsyncSession, *, path: Path | None = None) -> int:
    """Attach derived Rev. 5 assessment metadata to CCIs already loaded.

    A row whose CCI is not in the list is skipped rather than inventing an
    item: the authority decides which CCIs exist.
    """
    ids = {
        cci: pk
        for cci, pk in (
            await session.execute(select(CciItemRow.cci, CciItemRow.id))
        ).all()
    }
    written = 0
    seen: set[tuple[int, str]] = set()
    for row in read_overlay_ods(path or DEFAULT_CCI_ODS):
        pk = ids.get(row.cci)
        if pk is None:
            continue
        key = (pk, row.ap_acronym)
        if key in seen:
            continue
        seen.add(key)
        await session.execute(
            delete(CciAssessmentOverlay).where(
                CciAssessmentOverlay.cci_id == pk,
                CciAssessmentOverlay.ap_acronym == row.ap_acronym,
            )
        )
        session.add(
            CciAssessmentOverlay(
                cci_id=pk,
                ap_acronym=row.ap_acronym,
                emass_identifier=row.emass_identifier,
                assessment_procedure=row.assessment_procedure,
                assessment_methods=row.assessment_methods,
                source=OVERLAY_SOURCE,
            )
        )
        written += 1
    await session.flush()
    return written


@dataclass(frozen=True)
class CciCoverage:
    cci: str
    status: str
    type: str
    definition: str
    raw_index: str
    oscal_part_id: str | None


async def ccis_for_control(
    session: AsyncSession, canonical_control: str, *, revision: str = "5"
) -> list[CciCoverage]:
    """Which CCIs decompose this control, in the given revision."""
    rows = (
        await session.execute(
            select(CciItemRow, CciControlRef)
            .join(CciControlRef, CciControlRef.cci_id == CciItemRow.id)
            .where(
                CciControlRef.canonical_control == canonical_control,
                CciControlRef.revision == revision,
            )
            .order_by(CciItemRow.cci, CciControlRef.raw_index)
        )
    ).all()
    return [
        CciCoverage(
            cci=item.cci,
            status=item.status,
            type=item.type,
            definition=item.definition,
            raw_index=ref.raw_index,
            oscal_part_id=ref.oscal_part_id,
        )
        for item, ref in rows
    ]


async def controls_for_cci(
    session: AsyncSession, cci: str, *, revision: str = "5"
) -> list[str]:
    """The P5 seam: a scanner finding names a CCI and nothing else.

    Returns canonical control ids, de-duplicated and ordered. Empty for an
    unknown CCI -- an unrecognised identifier in a scan file is data, not an
    error.

    ``revision="5"`` answers are verified against the platform's own OSCAL
    catalog. Any other revision is answered against that same Rev. 5
    catalog, because it is the only one the platform holds -- a control
    whose id is unchanged since the cited revision still resolves correctly,
    but a control renamed, merged, or withdrawn since then resolves to
    nothing, and a reference naming an enhancement this parser could not
    confirm reports the base control instead (see
    ``CciControlRef.resolution_status`` / ``ccf.cci.resolve.ResolutionStatus``
    for the row-level detail this function does not surface). Callers that
    need the trustworthy answer should pass ``revision="5"``; callers that
    accept a best-effort cross-revision estimate may pass another revision.
    """
    rows = (
        await session.execute(
            select(CciControlRef.canonical_control)
            .join(CciItemRow, CciControlRef.cci_id == CciItemRow.id)
            .where(
                CciItemRow.cci == cci,
                CciControlRef.revision == revision,
                CciControlRef.canonical_control.is_not(None),
            )
        )
    ).scalars().all()
    return sorted({r for r in rows if r})
