"""SSP authoring + document generation API.

Workflow: create a project for a customer/system → entries are auto-seeded from
the scoring matrix → edit per-control content (responsible role, status,
origination, per-part narratives) → generate the FedRAMP Appendix A ``.docx``.
Projects persist, so a customer's SSP can be reopened and re-generated.
"""

from __future__ import annotations

import asyncio
from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from slugify import slugify
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...models import SSPControlEntry, SSPProject, System
from ...ssp import constants
from ...ssp.generator import generate_ssp_docx
from ...ssp.platforms import PLATFORMS, normalize_platform
from ...ssp.seed import entry_to_dict, seed_project_entries
from ..deps import get_session

router = APIRouter(prefix="/api/ssp", tags=["ssp"])

DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


class ProjectCreate(BaseModel):
    customer_name: str
    system_id: int | None = None
    system_name: str | None = None
    platform: str = "m365"
    title: str = "System Security Plan (SSP)"
    version: str = "0.1"
    prepared_by: str | None = None
    document_date: date | None = None


class ProjectUpdate(BaseModel):
    customer_name: str | None = None
    system_name: str | None = None
    platform: str | None = None
    title: str | None = None
    version: str | None = None
    prepared_by: str | None = None
    document_date: date | None = None
    status: str | None = None


class EntryUpdate(BaseModel):
    responsible_role: str | None = None
    implementation_status: list[str] | None = None
    control_origination: list[str] | None = None
    part_narratives: list[dict[str, str]] | None = None


class ProjectOut(BaseModel):
    id: int
    system_id: int | None
    customer_name: str
    system_name: str | None
    platform: str
    title: str
    version: str
    prepared_by: str | None
    document_date: date | None
    status: str

    model_config = {"from_attributes": True}


async def _require_project(session: AsyncSession, project_id: int) -> SSPProject:
    proj = (
        await session.execute(select(SSPProject).where(SSPProject.id == project_id))
    ).scalar_one_or_none()
    if proj is None:
        raise HTTPException(404, "SSP project not found")
    return proj


@router.get("/options")
async def options() -> dict[str, Any]:
    """Vocabulary for the editor (status + origination check-all-that-apply)."""
    return {
        "implementation_status": list(constants.IMPLEMENTATION_STATUS_OPTIONS),
        "control_origination": list(constants.CONTROL_ORIGINATION_OPTIONS),
        "origination_definitions": [
            {"name": n, "definition": d} for n, d in constants.ORIGINATION_DEFINITIONS
        ],
        "platforms": [{"code": c, "label": label} for c, label in PLATFORMS.items()],
    }


@router.get("/projects", response_model=list[ProjectOut])
async def list_projects(session: AsyncSession = Depends(get_session)) -> list[ProjectOut]:
    rows = (
        (await session.execute(select(SSPProject).order_by(SSPProject.created_at.desc())))
        .scalars()
        .all()
    )
    return [ProjectOut.model_validate(r) for r in rows]


@router.post("/projects", response_model=ProjectOut, status_code=201)
async def create_project(
    body: ProjectCreate, session: AsyncSession = Depends(get_session)
) -> ProjectOut:
    system_name = body.system_name
    if body.system_id is not None:
        sys = (
            await session.execute(select(System).where(System.id == body.system_id))
        ).scalar_one_or_none()
        if sys is None:
            raise HTTPException(404, "system not found")
        system_name = system_name or sys.name

    proj = SSPProject(
        system_id=body.system_id,
        customer_name=body.customer_name,
        system_name=system_name,
        platform=normalize_platform(body.platform),
        title=body.title,
        version=body.version,
        prepared_by=body.prepared_by,
        document_date=body.document_date,
    )
    session.add(proj)
    await session.flush()
    await seed_project_entries(session, proj)
    await session.refresh(proj)
    return ProjectOut.model_validate(proj)


@router.get("/projects/{project_id}")
async def get_project(
    project_id: int, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    proj = await _require_project(session, project_id)
    entries = (
        (
            await session.execute(
                select(SSPControlEntry)
                .where(SSPControlEntry.project_id == project_id)
                .order_by(SSPControlEntry.sort_order)
            )
        )
        .scalars()
        .all()
    )
    return {
        "project": ProjectOut.model_validate(proj).model_dump(),
        "entries": [entry_to_dict(e) for e in entries],
    }


@router.patch("/projects/{project_id}", response_model=ProjectOut)
async def update_project(
    project_id: int, body: ProjectUpdate, session: AsyncSession = Depends(get_session)
) -> ProjectOut:
    proj = await _require_project(session, project_id)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(proj, k, normalize_platform(v) if k == "platform" else v)
    await session.commit()
    await session.refresh(proj)
    return ProjectOut.model_validate(proj)


@router.delete("/projects/{project_id}", status_code=204)
async def delete_project(project_id: int, session: AsyncSession = Depends(get_session)) -> None:
    proj = await _require_project(session, project_id)
    await session.delete(proj)
    await session.commit()


@router.post("/projects/{project_id}/reseed")
async def reseed_project(
    project_id: int,
    overwrite: bool = False,
    platform: str | None = None,
    session: AsyncSession = Depends(get_session),
) -> dict[str, int | str]:
    """Regenerate sample statements, optionally switching the target platform."""
    proj = await _require_project(session, project_id)
    if platform is not None:
        proj.platform = normalize_platform(platform)
        await session.flush()
    touched = await seed_project_entries(
        session, proj, overwrite=overwrite, platform=proj.platform
    )
    return {"touched": touched, "platform": proj.platform}


@router.put("/projects/{project_id}/entries/{control_id}")
async def update_entry(
    project_id: int,
    control_id: str,
    body: EntryUpdate,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    await _require_project(session, project_id)
    entry = (
        await session.execute(
            select(SSPControlEntry)
            .where(SSPControlEntry.project_id == project_id)
            .where(SSPControlEntry.control_id == control_id)
        )
    ).scalar_one_or_none()
    if entry is None:
        raise HTTPException(404, "control entry not found in project")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(entry, k, v)
    await session.commit()
    await session.refresh(entry)
    return entry_to_dict(entry)


@router.get("/projects/{project_id}/document", response_model=None)
async def generate_document(
    project_id: int, session: AsyncSession = Depends(get_session)
) -> StreamingResponse:
    """Generate and download the SSP ``.docx`` for this customer's project."""
    proj = await _require_project(session, project_id)
    entries = (
        (
            await session.execute(
                select(SSPControlEntry)
                .where(SSPControlEntry.project_id == project_id)
                .order_by(SSPControlEntry.sort_order)
            )
        )
        .scalars()
        .all()
    )
    project_meta = {
        "customer_name": proj.customer_name,
        "system_name": proj.system_name,
        "platform": PLATFORMS.get(proj.platform, proj.platform),
        "title": proj.title,
        "version": proj.version,
        "prepared_by": proj.prepared_by,
        "document_date": proj.document_date.strftime("%m/%d/%Y") if proj.document_date else "",
    }
    # python-docx is synchronous CPU work — keep it off the event loop.
    data = await asyncio.to_thread(
        generate_ssp_docx, project_meta, [entry_to_dict(e) for e in entries]
    )
    slug = slugify(f"{proj.customer_name}-ssp-appendix-a-v{proj.version}") or "ssp"
    return StreamingResponse(
        iter([data]),
        media_type=DOCX_MIME,
        headers={"Content-Disposition": f'attachment; filename="{slug}.docx"'},
    )
