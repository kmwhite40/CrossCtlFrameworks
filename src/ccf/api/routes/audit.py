"""Audit-trail read API."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...models import AuditLog
from ..audit import row_hash
from ..deps import get_session

router = APIRouter(prefix="/api/audit", tags=["audit"])

_GENESIS = "0" * 64


class AuditEntryOut(BaseModel):
    id: int
    at: datetime
    actor: str | None
    action: str
    entity_type: str
    entity_id: str | None
    diff: dict[str, Any]

    model_config = {"from_attributes": True}


@router.get("", response_model=list[AuditEntryOut])
async def list_audit(
    session: AsyncSession = Depends(get_session),
    entity_type: str | None = Query(None),
    action: str | None = Query(None),
    actor: str | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> list[AuditEntryOut]:
    stmt = select(AuditLog).order_by(AuditLog.id.desc())
    if entity_type:
        stmt = stmt.where(AuditLog.entity_type == entity_type)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if actor:
        stmt = stmt.where(AuditLog.actor == actor)
    stmt = stmt.limit(limit).offset(offset)
    rows = (await session.execute(stmt)).scalars().all()
    return [AuditEntryOut.model_validate(r) for r in rows]


@router.get("/verify")
async def verify_chain(
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Recompute the audit hash chain and report whether it is intact.

    A mismatch means a row was modified, deleted, or inserted out of band.
    """
    rows = (await session.execute(select(AuditLog).order_by(AuditLog.id))).scalars().all()
    prev = _GENESIS
    checked = 0
    for r in rows:
        if r.row_hash is None:
            continue  # pre-chain legacy row; skip
        content = {
            "actor": r.actor,
            "action": r.action,
            "entity_type": r.entity_type,
            "entity_id": r.entity_id,
            "diff": r.diff,
        }
        expected = row_hash(r.prev_hash or _GENESIS, content)
        if r.prev_hash != prev or r.row_hash != expected:
            return {
                "ok": False,
                "broken_at_id": r.id,
                "checked": checked,
                "total": len(rows),
            }
        prev = r.row_hash
        checked += 1
    return {"ok": True, "checked": checked, "total": len(rows)}
