"""Audit-trail read API.

Access is gated to privileged roles (``admin``/``assessor``) because the audit
trail is a security-sensitive, tamper-evident record — see the module-level
note below. As of DATA-06, ``audit_log`` also carries ``organization_id`` +
a ``tenant_isolation`` RLS policy, so a scoped admin/assessor's rows are now
additionally row-isolated to their own org (+ NULL-org system rows) by the
tenant-clamped session both endpoints already receive via ``get_session``
(``ccf.api.deps``), not just gated by role.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...db import set_session_tenant
from ...models import AuditLog
from ..audit import row_hash
from ..auth_deps import require_role
from ..deps import get_session

router = APIRouter(prefix="/api/audit", tags=["audit"])

_GENESIS = "0" * 64

# SECURITY (DATA-06, closed): audit_log now carries a real organization_id
# column + tenant_isolation RLS policy (migration 0044), written by the audit
# middleware from the request principal's org (NULL for system/global events).
# entity_type/entity_id remain a generic, per-record-type polymorphic reference
# (systems, ssp projects, ksi_exceptions, ...) with no single join back to an
# organization, so app-layer filtering on those was never viable — but RLS
# scoping on the new organization_id column, beneath the get_session tenant
# clamp, doesn't need one. The require_role admin/assessor gate stays: a
# non-privileged user still can't reach these endpoints at all, and the RLS
# policy now additionally confines a privileged caller's own org-scoped
# session to their own org's rows (+ NULL-org system rows).


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

    The hash chain is GLOBAL (each row links to the previous row's hash across
    all organizations — see the middleware in ``ccf.api.audit``), but this
    session, like every request session, arrives tenant-clamped to the caller's
    org by ``get_session`` (DATA-06 RLS). Walking only the RLS-visible subset
    would see gaps in ``prev_hash``/``row_hash`` linkage that aren't real tamper
    events, just rows belonging to other orgs — a false ``ok=False``. Reset the
    tenant to unscoped for this read: the caller is already gated to
    admin/assessor above, and the response leaks nothing beyond a boolean, a row
    id, and counts.
    """
    await set_session_tenant(session, None)
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
