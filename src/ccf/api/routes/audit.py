"""Audit-trail read API.

Access is gated to privileged roles (``admin``/``assessor``) because the audit
trail spans every tenant's mutations — see the module-level note below on why
row-level tenant scoping isn't applied yet (DATA-06).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...models import AuditLog
from ..audit import row_hash
from ..auth_deps import require_role
from ..deps import get_session

router = APIRouter(prefix="/api/audit", tags=["audit"])

_GENESIS = "0" * 64

# SECURITY (DATA-06, deferred): audit_log has no organization_id column, so we
# cannot cheaply scope rows to the caller's tenant here. entity_type/entity_id
# are a generic, per-record-type polymorphic reference (systems, ssp projects,
# ksi_exceptions, ...) with no single join back to an organization, so deriving
# scope from them per-request would be expensive and fragile — and getting it
# wrong would silently drop rows a tenant is entitled to see (or leak rows they
# aren't). Rather than fabricate that filter, these endpoints are restricted to
# privileged, cross-tenant-trusted roles (admin/assessor) via require_role until
# a real organization_id column + row-level security lands (DATA-06).


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
    _principal: Principal = Depends(require_role("admin", "assessor")),
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
    _principal: Principal = Depends(require_role("admin", "assessor")),
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
