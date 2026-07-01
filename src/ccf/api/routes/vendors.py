"""Vendor / third-party risk management (TPRM) API."""

from __future__ import annotations

from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...governance import bus
from ...models import Vendor
from ..auth_deps import get_principal
from ..deps import get_session

router = APIRouter(prefix="/api/vendors", tags=["vendors"])


class VendorIn(BaseModel):
    name: str
    description: str | None = None
    service_type: str | None = None
    criticality: str = "medium"
    status: str = "active"
    risk_rating: str | None = None
    contact_email: str | None = None
    authorization: str | None = None
    review_frequency: str | None = None
    last_reviewed_on: date | None = None
    next_review_on: date | None = None
    linked_controls: list[str] = []


class VendorUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    service_type: str | None = None
    criticality: str | None = None
    status: str | None = None
    risk_rating: str | None = None
    contact_email: str | None = None
    authorization: str | None = None
    review_frequency: str | None = None
    last_reviewed_on: date | None = None
    next_review_on: date | None = None
    linked_controls: list[str] | None = None


def _out(v: Vendor) -> dict[str, Any]:
    return {
        "id": v.id,
        "name": v.name,
        "description": v.description,
        "service_type": v.service_type,
        "criticality": v.criticality,
        "status": v.status,
        "risk_rating": v.risk_rating,
        "contact_email": v.contact_email,
        "authorization": v.authorization,
        "review_frequency": v.review_frequency,
        "last_reviewed_on": v.last_reviewed_on,
        "next_review_on": v.next_review_on,
        "linked_controls": list(v.linked_controls or []),
    }


@router.get("")
async def list_vendors(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    stmt = select(Vendor).order_by(Vendor.name)
    if principal.org_id is not None:
        stmt = stmt.where(Vendor.organization_id == principal.org_id)
    return [_out(v) for v in (await session.execute(stmt)).scalars().all()]


@router.post("", status_code=201)
async def create_vendor(
    body: VendorIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    v = Vendor(organization_id=principal.org_id, **body.model_dump())
    session.add(v)
    await session.flush()
    await bus.emit(
        session,
        verb="created",
        entity_type="vendor",
        entity_id=v.id,
        summary=f"Vendor onboarded: {v.name}",
        org_id=principal.org_id,
        actor=principal.email,
    )
    await session.commit()
    return _out(v)


@router.patch("/{vendor_id}")
async def update_vendor(
    vendor_id: int,
    body: VendorUpdate,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    v = (await session.execute(select(Vendor).where(Vendor.id == vendor_id))).scalar_one_or_none()
    if v is None:
        raise HTTPException(404, "vendor not found")
    for k, val in body.model_dump(exclude_none=True).items():
        setattr(v, k, val)
    await session.commit()
    return _out(v)
