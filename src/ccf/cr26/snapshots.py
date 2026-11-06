"""Snapshots of Certification Data aligned to Ongoing Certification Reports.

FedRAMP CDS-CSO-HAD: *"Providers MUST supply snapshots of FedRAMP
Certification Data aligned to Ongoing Certification Reports to all necessary
parties; these snapshots MUST be available for the duration of FedRAMP
Certification."*

A snapshot is taken by :func:`take_for_ocr` whenever a **valid** OCR is stored
(``cr26.store.put_document`` calls it, so the seeder and the API's PUT both
reach it). It holds every schema-valid deliverable of the system as it stands
at that moment, the OCR included, and names what was withheld as invalid.

Snapshots are **content-addressed**: identified by the digest of what they
hold, so re-filing identical content stores no second copy, while changed
deliverables under an unchanged OCR do produce a new snapshot. Every valid
OCR stored also appends a **filing**; the snapshot filed most recently in a
report period is that period's current one, and any other is ``superseded``
-- so a revert (A, then a corrected B, then A again) reads A as current.
All three tables are append-only in the database (migration 0111).

Served to grant holders by :func:`list_for_grant` and :func:`get_document`, in
the portal's certification-data API, with the same digests and the same
Markdown rendering as live documents.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import set_session_tenant
from ..models import System
from ..models_cr26 import (
    CertificationSnapshot,
    CertificationSnapshotDocument,
    CertificationSnapshotFiling,
    Cr26Document,
)
from ..models_portal import ExternalAccessGrant

RULE_ID = "CDS-CSO-HAD"
#: Snapshots per listing page, and the most a caller may ask for.
PAGE = 50
MAX_PAGE = 500


def _period_date(value: Any) -> date | None:
    """The OCR's period bound. Schema-valid OCRs carry ISO dates; anything else
    is recorded as unknown rather than failing the filing it rides on."""
    try:
        return date.fromisoformat(str(value)[:10]) if value else None
    except ValueError:
        return None


def _digest(document: Any) -> str:
    from ..portal.certification import digest  # noqa: PLC0415 — portal imports cr26

    return digest(document)


def content_digest(entries: list[tuple[str, str | None, str]]) -> str:
    """Over the sorted ``(kind, document_key, sha256)`` of what a snapshot
    holds. Migration 0111 computes the same thing for its backfill."""
    return _digest(sorted([list(e) for e in entries], key=lambda e: (e[0], e[1] or "")))


async def take_for_ocr(
    session: AsyncSession,
    *,
    system: System,
    ocr: Cr26Document,
    actor: str | None,
) -> CertificationSnapshot | None:
    """File this valid OCR: snapshot what is current unless an identical
    snapshot exists, and record the filing either way.

    The unique constraint on ``(system_id, content_sha256)`` decides between
    "new" and "existing", so concurrent filings of the same content cannot
    both copy it.
    """
    if ocr.kind != "ocr" or not ocr.is_valid:
        return None
    period = (ocr.document or {}).get("reportPeriod") or {}
    deliverables = (
        (
            await session.execute(
                select(Cr26Document)
                .where(Cr26Document.system_id == system.id, Cr26Document.kind != "common")
                .order_by(Cr26Document.kind, Cr26Document.document_key)
            )
        )
        .scalars()
        .all()
    )
    included = [d for d in deliverables if d.is_valid]
    shas = {d.id: _digest(d.document) for d in included}
    content = content_digest([(d.kind, d.document_key, shas[d.id]) for d in included])
    snapshot_id = (
        await session.execute(
            insert(CertificationSnapshot)
            .values(
                organization_id=system.organization_id,
                system_id=system.id,
                ocr_period_from=_period_date(period.get("from")),
                ocr_period_to=_period_date(period.get("to")),
                ocr_sha256=_digest(ocr.document),
                content_sha256=content,
                basis="ocr_filed",
                taken_by=actor,
                withheld_invalid=[
                    {"kind": d.kind, "document_key": d.document_key}
                    for d in deliverables
                    if not d.is_valid
                ],
            )
            .on_conflict_do_nothing(constraint="uq_cert_snapshots_system_content")
            .returning(CertificationSnapshot.id)
        )
    ).scalar_one_or_none()
    if snapshot_id is None:
        snapshot_id = (
            await session.execute(
                select(CertificationSnapshot.id).where(
                    CertificationSnapshot.system_id == system.id,
                    CertificationSnapshot.content_sha256 == content,
                )
            )
        ).scalar_one()
    else:
        for d in included:
            session.add(
                CertificationSnapshotDocument(
                    snapshot_id=snapshot_id,
                    organization_id=system.organization_id,
                    system_id=system.id,
                    kind=d.kind,
                    document_key=d.document_key,
                    document=d.document,
                    sha256=shas[d.id],
                    ruleset_version=d.ruleset_version,
                    schema_version=d.schema_version,
                    updated_at=d.updated_at,
                )
            )
    session.add(
        CertificationSnapshotFiling(
            snapshot_id=snapshot_id, organization_id=system.organization_id, filed_by=actor
        )
    )
    await session.flush()
    return await session.get(CertificationSnapshot, snapshot_id)


# ── serving ────────────────────────────────────────────────────────────────


def _base(snapshot_id: int) -> str:
    return f"/api/portal/certification-data/snapshots/{snapshot_id}"


def _doc_summary(doc: Any) -> dict[str, Any]:
    """From a snapshot document -- or a row of just its summary columns."""
    from ..portal.certification import KIND_TITLES  # noqa: PLC0415

    path = f"{_base(doc.snapshot_id)}/{doc.kind}"
    if doc.document_key is not None:
        path += f"?key={doc.document_key}"
    sep = "&" if "?" in path else "?"
    return {
        "kind": doc.kind,
        "title": KIND_TITLES.get(doc.kind, doc.kind),
        "document_key": doc.document_key,
        "sha256": doc.sha256,
        "updated_at": doc.updated_at,
        "json_url": path,
        "markdown_url": f"{path}{sep}format=md",
    }


async def list_for_grant(
    session: AsyncSession,
    grant: ExternalAccessGrant,
    *,
    limit: int = PAGE,
    offset: int = 0,
) -> dict[str, Any]:
    """The grant's live shared systems' snapshots, most recently filed first.

    A snapshot is ``current`` when it is the one filed most recently in its
    report period, and ``superseded`` otherwise. Only summary columns are
    read: no document body is loaded to list them.
    """
    from ..portal.certification import shared_system_ids  # noqa: PLC0415

    await set_session_tenant(session, grant.organization_id)
    limit = max(1, min(int(limit), MAX_PAGE))
    offset = max(0, int(offset))
    systems = shared_system_ids(grant)
    empty: dict[str, Any] = {"snapshots": [], "total": 0, "limit": limit, "offset": offset}
    if not systems:
        return empty
    S, F = CertificationSnapshot, CertificationSnapshotFiling  # noqa: N806
    last = (
        select(F.snapshot_id, func.max(F.filed_at).label("last_filed_at"))
        .group_by(F.snapshot_id)
        .subquery()
    )
    newest_in_period = func.max(last.c.last_filed_at).over(
        partition_by=(S.system_id, S.ocr_period_from, S.ocr_period_to)
    )
    ranked = (
        select(
            S,
            System.name.label("system_name"),
            last.c.last_filed_at,
            (last.c.last_filed_at == newest_in_period).label("current"),
        )
        .join(System, System.id == S.system_id)
        .join(last, last.c.snapshot_id == S.id)
        .where(
            S.system_id.in_(systems),
            S.organization_id == grant.organization_id,
            System.deleted_at.is_(None),
        )
        .subquery()
    )
    total = (await session.execute(select(func.count()).select_from(ranked))).scalar_one()
    rows = (
        await session.execute(
            select(ranked)
            .order_by(ranked.c.last_filed_at.desc(), ranked.c.id.desc())
            .limit(limit)
            .offset(offset)
        )
    ).all()
    if not rows:
        return {**empty, "total": total}
    D = CertificationSnapshotDocument  # noqa: N806
    docs = (
        await session.execute(
            select(D.snapshot_id, D.kind, D.document_key, D.sha256, D.updated_at)
            .where(D.snapshot_id.in_([r.id for r in rows]))
            .order_by(D.kind, D.document_key)
        )
    ).all()
    by_snapshot: dict[int, list[dict[str, Any]]] = {}
    for d in docs:
        by_snapshot.setdefault(d.snapshot_id, []).append(_doc_summary(d))
    return {
        "snapshots": [
            {
                "id": r.id,
                "system_id": r.system_id,
                "system": r.system_name,
                "report_period": {"from": r.ocr_period_from, "to": r.ocr_period_to},
                "ocr_sha256": r.ocr_sha256,
                "content_sha256": r.content_sha256,
                "basis": r.basis,
                "taken_at": r.taken_at,
                "last_filed_at": r.last_filed_at,
                "current": bool(r.current),
                "superseded": not r.current,
                # A count, as the live listing gives: which drafts were held
                # back (an incident report's key, say) is not the grantee's.
                "withheld_invalid": len(r.withheld_invalid or []),
                "documents": by_snapshot.get(r.id, []),
            }
            for r in rows
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


async def get_document(
    session: AsyncSession,
    grant: ExternalAccessGrant,
    *,
    snapshot_id: int,
    kind: str,
    document_key: str | None,
) -> tuple[CertificationSnapshotDocument, CertificationSnapshot, str] | None:
    """One document from one snapshot, or ``None`` when the grant cannot see
    it -- out of scope, a deleted system, or missing all answer the same."""
    from ..portal.certification import shared_system_ids  # noqa: PLC0415

    await set_session_tenant(session, grant.organization_id)
    row = (
        await session.execute(
            select(CertificationSnapshotDocument, CertificationSnapshot, System.name)
            .join(
                CertificationSnapshot,
                CertificationSnapshot.id == CertificationSnapshotDocument.snapshot_id,
            )
            .join(System, System.id == CertificationSnapshot.system_id)
            .where(
                CertificationSnapshot.id == snapshot_id,
                CertificationSnapshot.organization_id == grant.organization_id,
                System.deleted_at.is_(None),
                CertificationSnapshotDocument.kind == kind,
                CertificationSnapshotDocument.document_key.is_(None)
                if document_key is None
                else CertificationSnapshotDocument.document_key == document_key,
            )
        )
    ).first()
    if row is None or row[1].system_id not in shared_system_ids(grant):
        return None
    return row[0], row[1], row[2]


def envelope(
    doc: CertificationSnapshotDocument, snapshot: CertificationSnapshot, system_name: str
) -> dict[str, Any]:
    return {
        **_doc_summary(doc),
        "snapshot_id": snapshot.id,
        "system_id": snapshot.system_id,
        "system": system_name,
        "report_period": {"from": snapshot.ocr_period_from, "to": snapshot.ocr_period_to},
        "taken_at": snapshot.taken_at,
        "basis": snapshot.basis,
        "document": doc.document,
    }
