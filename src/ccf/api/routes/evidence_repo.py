"""Hardened evidence repository API — versioned objects, review, download.

Mounted at ``/api/evidence-repo`` so it sits alongside (not on top of) the existing
implementation-scoped ``/api/evidence`` intake. Objects are versioned and
content-addressed; approval sets an immutable (WORM-ready) lock; downloads are
recorded as access events.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ...auth import Principal
from ...evidence import service
from ...models_evidence import EvidenceObject
from ..auth_deps import get_principal
from ..deps import get_session

router = APIRouter(prefix="/api/evidence-repo", tags=["evidence-repository"])

_MAX_BYTES = 50 * 1024 * 1024  # 50 MiB per version


class ObjectIn(BaseModel):
    title: str
    description: str | None = None
    system_id: int | None = None
    control_id: str | None = None
    framework: str | None = None
    owner: str | None = None
    expires_on: date | None = None


class ReviewIn(BaseModel):
    decision: str = Field(..., pattern=r"^(approved|rejected)$")
    note: str | None = None


def _version_out(v: Any) -> dict[str, Any]:
    return {
        "id": v.id,
        "version": v.version,
        "sha256": v.sha256,
        "media_type": v.media_type,
        "size_bytes": v.size_bytes,
        "filename": v.filename,
        "storage_backend": v.storage_backend,
        "uploaded_by": v.uploaded_by,
        "created_at": v.created_at,
    }


def _detail(obj: EvidenceObject) -> dict[str, Any]:
    return {
        **service.object_summary(obj),
        "description": obj.description,
        "versions": [_version_out(v) for v in (obj.versions or [])],
        "reviews": [
            {"id": r.id, "decision": r.decision, "reviewer": r.reviewer, "note": r.note,
             "version_id": r.version_id, "reviewed_at": r.reviewed_at}
            for r in (obj.reviews or [])
        ],
    }


async def _require_object(
    session: AsyncSession, oid: int, principal: Principal
) -> EvidenceObject:
    obj = (
        await session.execute(
            select(EvidenceObject)
            .options(selectinload(EvidenceObject.versions), selectinload(EvidenceObject.reviews))
            .where(EvidenceObject.id == oid)
        )
    ).scalar_one_or_none()
    if obj is None or (principal.org_id is not None and obj.organization_id != principal.org_id):
        raise HTTPException(404, "evidence object not found")
    return obj


@router.get("")
async def list_objects(
    status: str | None = None,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    stmt = (
        select(EvidenceObject)
        .options(selectinload(EvidenceObject.versions))
        .order_by(EvidenceObject.id.desc())
    )
    if principal.org_id is not None:
        stmt = stmt.where(EvidenceObject.organization_id == principal.org_id)
    if status:
        stmt = stmt.where(EvidenceObject.status == status)
    return [service.object_summary(o) for o in (await session.execute(stmt)).scalars().all()]


@router.post("", status_code=201)
async def create_object(
    body: ObjectIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    obj = await service.create_object(session, org_id=principal.org_id, **body.model_dump())
    await session.commit()
    obj = await _require_object(session, obj.id, principal)
    return _detail(obj)


@router.get("/{oid}")
async def get_object(
    oid: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    return _detail(await _require_object(session, oid, principal))


@router.post("/{oid}/versions", status_code=201)
async def add_version(
    oid: int,
    file: UploadFile,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    obj = await _require_object(session, oid, principal)
    data = await file.read()
    if not data:
        raise HTTPException(400, "uploaded file is empty")
    if len(data) > _MAX_BYTES:
        raise HTTPException(413, "evidence exceeds 50 MiB limit")
    try:
        version = await service.add_version(
            session, obj, data=data, filename=file.filename,
            media_type=file.content_type, uploaded_by=principal.email,
        )
    except service.EvidenceError as e:
        raise HTTPException(409, str(e)) from e
    await session.commit()
    return _version_out(version)


@router.post("/{oid}/submit")
async def submit(
    oid: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    obj = await _require_object(session, oid, principal)
    try:
        await service.submit_object(session, obj)
    except service.EvidenceError as e:
        raise HTTPException(409, str(e)) from e
    await session.commit()
    obj = await _require_object(session, oid, principal)
    return _detail(obj)


@router.post("/{oid}/review")
async def review(
    oid: int,
    body: ReviewIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    obj = await _require_object(session, oid, principal)
    await service.review_object(
        session, obj, decision=body.decision, reviewer=principal.email, note=body.note
    )
    await session.commit()
    obj = await _require_object(session, oid, principal)
    return _detail(obj)


@router.get("/{oid}/download")
async def download(
    oid: int,
    version: int | None = None,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> StreamingResponse:
    obj = await _require_object(session, oid, principal)
    try:
        ver, data = await service.read_version(session, obj, version_id=version)
    except service.EvidenceError as e:
        raise HTTPException(404, str(e)) from e
    await service.record_access(
        session, obj, version_id=ver.id, actor=principal.email, action="download"
    )
    await session.commit()
    filename = ver.filename or f"evidence-{obj.id}-v{ver.version}"
    return StreamingResponse(
        iter([data]),
        media_type=ver.media_type or "application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
