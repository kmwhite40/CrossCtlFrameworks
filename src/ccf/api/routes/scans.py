"""Vulnerability-scan ingestion → automated POA&M reconciliation.

Upload a Nessus/Tenable ``.nessus`` XML, AWS Inspector JSON, or generic/Qualys
CSV export for a system; findings are normalized and reconciled into the POA&M
register (open / update / reopen / auto-close), with a provenance record.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...governance import bus
from ...ingest import parse_scan, reconcile_findings
from ...models import ScanIngestion, System
from ..auth_deps import get_principal, org_systems_subq
from ..deps import get_session

router = APIRouter(prefix="/api/scans", tags=["scans"])

# Guard against decompression/entity-expansion abuse on upload.
_MAX_SCAN_BYTES = 64 * 1024 * 1024  # 64 MiB


async def _require_system(session: AsyncSession, system_id: int, principal: Principal) -> System:
    sys = (
        await session.execute(select(System).where(System.id == system_id))
    ).scalar_one_or_none()
    if sys is None or (principal.org_id is not None and sys.organization_id != principal.org_id):
        raise HTTPException(404, "system not found")
    return sys


@router.post("/ingest", status_code=201)
async def ingest_scan(
    system_id: int = Form(...),
    scanner: str = Form("auto"),
    file: UploadFile | None = None,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Ingest a scan export and reconcile it into the system's POA&Ms."""
    await _require_system(session, system_id, principal)
    if file is None:
        raise HTTPException(400, "a scan file upload is required")
    data = await file.read()
    if not data:
        raise HTTPException(400, "uploaded scan file is empty")
    if len(data) > _MAX_SCAN_BYTES:
        raise HTTPException(413, "scan file exceeds 64 MiB limit")

    try:
        resolved, findings = parse_scan(scanner, data, file.filename)
    except ValueError as e:
        raise HTTPException(422, str(e)) from e

    result = await reconcile_findings(
        session, system_id=system_id, scanner=resolved, findings=findings
    )

    ingestion = ScanIngestion(
        organization_id=principal.org_id,
        system_id=system_id,
        scanner=resolved,
        filename=file.filename,
        findings_total=result.findings_total,
        poams_created=result.created,
        poams_updated=result.updated,
        poams_reopened=result.reopened,
        poams_closed=result.closed,
        summary=result.as_dict(),
    )
    session.add(ingestion)
    await session.flush()
    await bus.emit(
        session,
        verb="ingested",
        entity_type="scan_ingestion",
        entity_id=ingestion.id,
        summary=(
            f"{resolved} scan: {result.findings_total} findings → "
            f"{result.created} new, {result.reopened} reopened, {result.closed} closed POA&Ms"
        ),
        org_id=principal.org_id,
        actor=principal.email,
    )
    if result.created or result.reopened:
        await bus.notify(
            session,
            category="scan",
            title=f"{resolved} scan opened {result.created + result.reopened} POA&M(s)",
            body=(
                f"System {system_id}: {result.created} new and {result.reopened} reopened "
                f"weaknesses from {file.filename or 'upload'}."
            ),
            org_id=principal.org_id,
            severity="warning",
            entity_type="scan_ingestion",
            entity_id=ingestion.id,
        )
    await session.commit()
    return {"id": ingestion.id, "scanner": resolved, **result.as_dict()}


@router.get("/ingestions")
async def list_ingestions(
    system_id: int | None = None,
    limit: int = 50,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    stmt = select(ScanIngestion).order_by(ScanIngestion.id.desc()).limit(min(limit, 200))
    if principal.org_id is not None:
        stmt = stmt.where(ScanIngestion.system_id.in_(org_systems_subq(principal)))
    if system_id is not None:
        stmt = stmt.where(ScanIngestion.system_id == system_id)
    rows = (await session.execute(stmt)).scalars().all()
    return [
        {
            "id": r.id,
            "system_id": r.system_id,
            "scanner": r.scanner,
            "filename": r.filename,
            "findings_total": r.findings_total,
            "poams_created": r.poams_created,
            "poams_updated": r.poams_updated,
            "poams_reopened": r.poams_reopened,
            "poams_closed": r.poams_closed,
            "created_at": r.created_at,
            "summary": r.summary,
        }
        for r in rows
    ]
