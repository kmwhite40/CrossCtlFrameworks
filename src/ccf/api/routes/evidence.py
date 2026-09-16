"""Evidence CRUD — attach artifacts to control implementations."""

from __future__ import annotations

from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...models import ControlImplementation, Evidence, System
from ...models_capability import Capability
from ...schemas import EvidenceOut
from ..auth_deps import get_principal, org_systems_subq
from ..deps import get_session

router = APIRouter(prefix="/api/evidence", tags=["evidence"])


async def _impl_in_scope(
    session: AsyncSession, implementation_id: int | None, principal: Principal
) -> bool:
    if principal.org_id is None:
        return True
    if implementation_id is None:
        # Capability-parented evidence (0067) has no implementation; the caller
        # must scope it through the capability instead. Refusing here rather
        # than returning True keeps this helper from silently authorising a
        # row it cannot actually see.
        return False
    ok = (
        await session.execute(
            select(ControlImplementation.id)
            .join(System, System.id == ControlImplementation.system_id)
            .where(
                ControlImplementation.id == implementation_id,
                System.organization_id == principal.org_id,
            )
        )
    ).scalar_one_or_none()
    return ok is not None


async def _cap_in_scope(
    session: AsyncSession, capability_id: int, principal: Principal
) -> bool:
    if principal.org_id is None:
        return True
    ok = (
        await session.execute(
            select(Capability.id).where(
                Capability.id == capability_id,
                Capability.organization_id == principal.org_id,
            )
        )
    ).scalar_one_or_none()
    return ok is not None


async def _evidence_in_scope(
    session: AsyncSession, obj: Evidence, principal: Principal
) -> bool:
    """Scope one evidence row through whichever parent it actually has.

    Since 0067 evidence may hang off a capability instead of a control
    implementation, so scoping only via ``implementation_id`` would let a
    capability-parented row escape the tenant check entirely.
    """
    if obj.implementation_id is not None:
        return await _impl_in_scope(session, obj.implementation_id, principal)
    if obj.capability_id is not None:
        return await _cap_in_scope(session, obj.capability_id, principal)
    return False  # the CHECK constraint makes this unreachable


class EvidenceCreate(BaseModel):
    # Optional since 0067: evidence may hang off a capability instead of a
    # control implementation. create_evidence enforces the same at-least-one
    # rule the DB CHECK enforces, as a 422 rather than a raised IntegrityError.
    implementation_id: int | None = None
    capability_id: int | None = None
    kind: str = Field(
        ...,
        pattern=r"^(document|screenshot|config_export|attestation|scan_result|ticket|link|other)$",
    )
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
    principal: Principal = Depends(get_principal),
) -> list[EvidenceOut]:
    stmt = select(Evidence).order_by(Evidence.created_at.desc())
    if principal.org_id is not None:
        # Outer joins: a row may be parented to a control implementation, a
        # capability, or (pre-0067) always the former — an inner join on
        # implementation_id alone would drop capability-parented rows the
        # tenant authored. See _evidence_in_scope for the same either-parent
        # scoping used by delete.
        stmt = (
            stmt.outerjoin(
                ControlImplementation, ControlImplementation.id == Evidence.implementation_id
            )
            .outerjoin(Capability, Capability.id == Evidence.capability_id)
            .where(
                or_(
                    ControlImplementation.system_id.in_(org_systems_subq(principal)),
                    Capability.organization_id == principal.org_id,
                )
            )
        )
    if implementation_id is not None:
        stmt = stmt.where(Evidence.implementation_id == implementation_id)
    rows = (await session.execute(stmt)).scalars().all()
    return [EvidenceOut.model_validate(r) for r in rows]


@router.post("", response_model=EvidenceOut, status_code=201)
async def create_evidence(
    body: EvidenceCreate,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> EvidenceOut:
    if body.implementation_id is None and body.capability_id is None:
        raise HTTPException(422, "evidence requires implementation_id or capability_id")
    if body.implementation_id is not None and not await _impl_in_scope(
        session, body.implementation_id, principal
    ):
        raise HTTPException(404, "control implementation not found")
    if body.capability_id is not None and not await _cap_in_scope(
        session, body.capability_id, principal
    ):
        raise HTTPException(404, "capability not found")
    obj = Evidence(**body.model_dump(exclude_none=False))
    session.add(obj)
    await session.commit()
    await session.refresh(obj)
    return EvidenceOut.model_validate(obj)


@router.delete("/{eid}", status_code=204)
async def delete_evidence(
    eid: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> None:
    obj = (await session.execute(select(Evidence).where(Evidence.id == eid))).scalar_one_or_none()
    if obj is None or not await _evidence_in_scope(session, obj, principal):
        raise HTTPException(404, "evidence not found")
    await session.delete(obj)
    await session.commit()
