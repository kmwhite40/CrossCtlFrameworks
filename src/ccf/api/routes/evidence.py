"""Evidence CRUD — attach artifacts to control implementations."""
from __future__ import annotations

from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...models import Evidence
from ...schemas import EvidenceOut
from ..deps import get_session

router = APIRouter(prefix="/api/evidence", tags=["evidence"])


class EvidenceCreate(BaseModel):
    implementation_id: int
    kind: str = Field(..., pattern=r"^(document|screenshot|config_export|attestation|scan_result|ticket|link|other)$")
    title: str
    uri: str | None = None
    collected_on: date | None = None
    expires_on: date | None = None
    hash_sha256: str | None = None
    metadata_json: dict[str, Any] = Field(default_factory=dict)


@router.get("", response_model=list[EvidenceOut])
async def list_evidence(
    session: AsyncSession = Depends(get_session),
    implementation_id: int | None = None,
) -> list[EvidenceOut]:
    stmt = select(Evidence).order_by(Evidence.created_at.desc())
    if implementation_id is not None:
        stmt = stmt.where(Evidence.implementation_id == implementation_id)
    rows = (await session.execute(stmt)).scalars().all()
    return [EvidenceOut.model_validate(r) for r in rows]


@router.post("", response_model=EvidenceOut, status_code=201)
async def create_evidence(
    body: EvidenceCreate,
    session: AsyncSession = Depends(get_session),
) -> EvidenceOut:
    obj = Evidence(**body.model_dump(exclude_none=False))
    session.add(obj)
    await session.commit()
    await session.refresh(obj)
    return EvidenceOut.model_validate(obj)


@router.delete("/{eid}", status_code=204)
async def delete_evidence(
    eid: int, session: AsyncSession = Depends(get_session)
) -> None:
    obj = (await session.execute(select(Evidence).where(Evidence.id == eid))).scalar_one_or_none()
    if obj is None:
        raise HTTPException(404, "evidence not found")
    await session.delete(obj)
    await session.commit()
