"""Evidence collection + artifact store API.

Automated collectors (or the config-capture connectors) push proof of a control
here: either a file (multipart) or a reference URI. Files are content-addressed
in the artifact store and linked to control-implementation evidence.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, UploadFile
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...governance import artifacts as artifact_engine
from ...models import Artifact
from ..auth_deps import get_principal
from ..deps import get_session

router = APIRouter(tags=["evidence-intake"])


@router.post("/api/evidence/collect", status_code=201)
async def collect(
    *,
    implementation_id: int = Form(...),
    title: str = Form(...),
    kind: str = Form("config_export"),
    uri: str | None = Form(None),
    collected_on: date | None = Form(None),
    expires_on: date | None = Form(None),
    file: UploadFile | None = None,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Collect evidence for a control implementation, optionally storing a file."""
    content = await file.read() if file is not None else None
    try:
        ev, artifact = await artifact_engine.collect_evidence(
            session,
            implementation_id=implementation_id,
            title=title,
            kind=kind,
            content=content,
            filename=file.filename if file else None,
            media_type=file.content_type if file else None,
            uri=uri,
            collected_on=collected_on,
            expires_on=expires_on,
            org_id=principal.org_id,
            uploaded_by=principal.email,
        )
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    await session.commit()
    return {
        "evidence_id": ev.id,
        "artifact_id": artifact.id if artifact else None,
        "sha256": artifact.sha256 if artifact else None,
    }


@router.get("/api/artifacts")
async def list_artifacts(
    limit: int = 100,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    stmt = select(Artifact).order_by(Artifact.id.desc()).limit(min(limit, 500))
    if principal.org_id is not None:
        stmt = stmt.where(Artifact.organization_id == principal.org_id)
    rows = (await session.execute(stmt)).scalars().all()
    return [
        {
            "id": a.id,
            "filename": a.filename,
            "media_type": a.media_type,
            "size_bytes": a.size_bytes,
            "sha256": a.sha256,
            "created_at": a.created_at,
        }
        for a in rows
    ]


@router.get("/api/artifacts/{artifact_id}/download")
async def download(
    artifact_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> Response:
    a = (
        await session.execute(select(Artifact).where(Artifact.id == artifact_id))
    ).scalar_one_or_none()
    if a is None or a.content is None:
        raise HTTPException(404, "artifact not found")
    return Response(
        content=a.content,
        media_type=a.media_type or "application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{a.filename}"'},
    )
