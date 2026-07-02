"""Approval / separation-of-duties workflow API."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...governance import approvals
from ...governance.approvals import WorkflowError
from ...models import Approval
from ..auth_deps import get_principal
from ..deps import get_session

router = APIRouter(prefix="/api/approvals", tags=["approvals"])


class Decision(BaseModel):
    note: str | None = None


@router.get("")
async def list_approvals(
    entity_type: str | None = None,
    state: str | None = None,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    stmt = select(Approval).order_by(Approval.updated_at.desc())
    if principal.org_id is not None:
        stmt = stmt.where(Approval.organization_id == principal.org_id)
    if entity_type:
        stmt = stmt.where(Approval.entity_type == entity_type)
    if state:
        stmt = stmt.where(Approval.state == state)
    rows = (await session.execute(stmt)).scalars().all()
    return [approvals.out(a) for a in rows]


@router.get("/{entity_type}/{entity_id}")
async def get_approval(
    entity_type: str,
    entity_id: str,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    a = (
        await session.execute(
            select(Approval).where(
                Approval.entity_type == entity_type, Approval.entity_id == entity_id
            )
        )
    ).scalar_one_or_none()
    if a is None:
        return {"entity_type": entity_type, "entity_id": entity_id, "state": "draft"}
    return approvals.out(a)


@router.post("/{entity_type}/{entity_id}/submit")
async def submit(
    entity_type: str,
    entity_id: str,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    try:
        a = await approvals.submit(
            session,
            entity_type=entity_type,
            entity_id=entity_id,
            actor=principal.email,
            org_id=principal.org_id,
        )
    except WorkflowError as e:
        raise HTTPException(409, str(e)) from e
    await session.commit()
    return approvals.out(a)


@router.post("/{entity_type}/{entity_id}/approve")
async def approve(
    entity_type: str,
    entity_id: str,
    body: Decision | None = None,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    return await _decide(session, entity_type, entity_id, True, principal, body)


@router.post("/{entity_type}/{entity_id}/reject")
async def reject(
    entity_type: str,
    entity_id: str,
    body: Decision | None = None,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    return await _decide(session, entity_type, entity_id, False, principal, body)


async def _decide(
    session: AsyncSession,
    entity_type: str,
    entity_id: str,
    approve_it: bool,
    principal: Principal,
    body: Decision | None,
) -> dict[str, Any]:
    try:
        a = await approvals.decide(
            session,
            entity_type=entity_type,
            entity_id=entity_id,
            approve=approve_it,
            actor=principal.email,
            role=principal.role,
            note=body.note if body else None,
            org_id=principal.org_id,
        )
    except WorkflowError as e:
        # SoD / role violations are 403; state errors are 409.
        code = 403 if "duties" in str(e) or "role" in str(e) else 409
        raise HTTPException(code, str(e)) from e
    await session.commit()
    return approvals.out(a)
