"""Policy management API — policies, versions, and attestations."""

from __future__ import annotations

from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...governance import bus
from ...models import Policy, PolicyAttestation, PolicyVersion
from ..auth_deps import get_principal
from ..deps import get_session

router = APIRouter(prefix="/api/policies", tags=["policies"])


class PolicyIn(BaseModel):
    name: str
    description: str | None = None
    category: str | None = None
    owner_user_id: int | None = None
    status: str = "draft"
    review_frequency: str | None = None
    next_review_on: date | None = None
    linked_controls: list[str] = []


class VersionIn(BaseModel):
    version: str
    body: str | None = None
    uri: str | None = None
    effective_on: date | None = None


class AttestIn(BaseModel):
    user_id: int | None = None
    attestor: str | None = None
    note: str | None = None


def _out(p: Policy) -> dict[str, Any]:
    return {
        "id": p.id,
        "name": p.name,
        "description": p.description,
        "category": p.category,
        "owner_user_id": p.owner_user_id,
        "status": p.status,
        "review_frequency": p.review_frequency,
        "next_review_on": p.next_review_on,
        "linked_controls": list(p.linked_controls or []),
    }


@router.get("")
async def list_policies(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    stmt = select(Policy).order_by(Policy.name)
    if principal.org_id is not None:
        stmt = stmt.where(Policy.organization_id == principal.org_id)
    return [_out(p) for p in (await session.execute(stmt)).scalars().all()]


@router.post("", status_code=201)
async def create_policy(
    body: PolicyIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    p = Policy(organization_id=principal.org_id, **body.model_dump())
    session.add(p)
    await session.flush()
    await bus.emit(
        session,
        verb="created",
        entity_type="policy",
        entity_id=p.id,
        summary=f"Policy created: {p.name}",
        org_id=principal.org_id,
        actor=principal.email,
    )
    await session.commit()
    return _out(p)


@router.get("/{policy_id}")
async def get_policy(
    policy_id: int,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    p = (await session.execute(select(Policy).where(Policy.id == policy_id))).scalar_one_or_none()
    if p is None:
        raise HTTPException(404, "policy not found")
    versions = (
        (
            await session.execute(
                select(PolicyVersion)
                .where(PolicyVersion.policy_id == policy_id)
                .order_by(PolicyVersion.id.desc())
            )
        )
        .scalars()
        .all()
    )
    return {
        **_out(p),
        "versions": [
            {"id": v.id, "version": v.version, "effective_on": v.effective_on, "uri": v.uri}
            for v in versions
        ],
    }


@router.post("/{policy_id}/versions", status_code=201)
async def add_version(
    policy_id: int,
    body: VersionIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    p = (await session.execute(select(Policy).where(Policy.id == policy_id))).scalar_one_or_none()
    if p is None:
        raise HTTPException(404, "policy not found")
    v = PolicyVersion(policy_id=policy_id, **body.model_dump())
    session.add(v)
    await session.flush()
    await bus.emit(
        session,
        verb="updated",
        entity_type="policy",
        entity_id=p.id,
        summary=f"Policy '{p.name}' version {v.version} published",
        org_id=principal.org_id,
        actor=principal.email,
    )
    await session.commit()
    return {"id": v.id, "version": v.version}


@router.post("/versions/{version_id}/attest", status_code=201)
async def attest(
    version_id: int,
    body: AttestIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    v = (
        await session.execute(select(PolicyVersion).where(PolicyVersion.id == version_id))
    ).scalar_one_or_none()
    if v is None:
        raise HTTPException(404, "policy version not found")
    a = PolicyAttestation(policy_version_id=version_id, **body.model_dump())
    session.add(a)
    await session.flush()
    await bus.emit(
        session,
        verb="attested",
        entity_type="policy_version",
        entity_id=version_id,
        summary=f"Policy version {v.version} attested by {body.attestor or body.user_id}",
        org_id=principal.org_id,
        actor=principal.email,
    )
    await session.commit()
    return {"id": a.id, "attested_at": a.attested_at}
