"""Waiver endpoints -- request, approve, revoke.

A waiver stops the consequence of a finding that has been formally accepted; it
never alters the finding (see
``docs/superpowers/specs/2026-09-15-waivers-design.md``). These routes own the
decision trail: who asked, who granted, when, until when, and why.

Scoping follows the rest of the tenant-owned API -- ``organization_id`` comes
from the calling principal and is never read from a request body -- and the
app-level ``auth_gate_middleware`` supplies the write gate, so routes do not
re-declare one. Approval and revocation additionally require a role, because
they are the acts that change what the platform stops telling you about.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...governance.waivers import WAIVER_STATUSES, can_approve, is_active
from ...models import System
from ...models_waivers import Waiver
from ..audit import record_event
from ..auth_deps import get_principal, require_role
from ..deps import get_session

router = APIRouter(prefix="/api", tags=["waivers"])

#: Roles that may grant or withdraw an acceptance.
APPROVER_ROLES = ("admin", "issm", "isso")


class WaiverIn(BaseModel):
    system_id: int
    rationale: str
    check_key: str | None = None
    control_id: str | None = None
    resource_id: str | None = None
    expires_on: date | None = None
    risk_id: int | None = None
    notes: str | None = None


def _out(w: Waiver) -> dict[str, Any]:
    return {
        "id": w.id,
        "system_id": w.system_id,
        "check_key": w.check_key,
        "control_id": w.control_id,
        "resource_id": w.resource_id,
        "rationale": w.rationale,
        "status": w.status,
        "requested_by": w.requested_by,
        "approved_by": w.approved_by,
        "approved_at": w.approved_at.isoformat() if w.approved_at else None,
        "expires_on": w.expires_on.isoformat() if w.expires_on else None,
        "risk_id": w.risk_id,
        "notes": w.notes,
        "active": is_active(w, today=datetime.now(UTC).date()),
        "created_at": w.created_at.isoformat() if w.created_at else None,
    }


async def _load(session: AsyncSession, waiver_id: int, principal: Principal) -> Waiver:
    """One waiver, or 404 -- including when it belongs to another tenant.

    404 rather than 403: telling an unauthorized caller that an id exists is
    itself a disclosure.
    """
    w = (
        await session.execute(select(Waiver).where(Waiver.id == waiver_id))
    ).scalar_one_or_none()
    if w is None or (
        principal.org_id is not None and w.organization_id != principal.org_id
    ):
        raise HTTPException(404, "waiver not found")
    return w


@router.post("/waivers", status_code=201)
async def create_waiver(
    body: WaiverIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Request a waiver. It arrives ``requested`` and suppresses nothing."""
    if not body.rationale or not body.rationale.strip():
        raise HTTPException(400, "rationale is required: an acceptance must state why")
    # Mirrors ck_waiver_one_target so the client gets a message rather than a
    # 500 from the database.
    if bool(body.check_key) == bool(body.control_id):
        raise HTTPException(
            400, "supply exactly one of check_key or control_id"
        )
    system = (
        await session.execute(select(System).where(System.id == body.system_id))
    ).scalar_one_or_none()
    if system is None or system.deleted_at is not None:
        raise HTTPException(404, "system not found")
    if principal.org_id is not None and system.organization_id != principal.org_id:
        raise HTTPException(404, "system not found")

    w = Waiver(
        # From the principal, never the body.
        organization_id=(
            principal.org_id if principal.org_id is not None else system.organization_id
        ),
        system_id=system.id,
        check_key=body.check_key,
        control_id=body.control_id,
        resource_id=body.resource_id,
        rationale=body.rationale.strip(),
        status="requested",
        requested_by=principal.email,
        expires_on=body.expires_on,
        risk_id=body.risk_id,
        notes=body.notes,
    )
    session.add(w)
    await session.flush()
    await record_event(
        session,
        actor=principal.email,
        action="create",
        entity_type="waiver",
        entity_id=str(w.id),
        diff={
            "event": "requested",
            "target": w.check_key or w.control_id,
            "resource_id": w.resource_id,
            "expires_on": w.expires_on.isoformat() if w.expires_on else None,
            "rationale": w.rationale,
        },
    )
    await session.commit()
    await session.refresh(w)
    return _out(w)


@router.get("/waivers")
async def list_waivers(  # noqa: PLR0917 -- FastAPI binds these by keyword
    system_id: int | None = None,
    check_key: str | None = None,
    control_id: str | None = None,
    status: str | None = Query(default=None),
    active_only: bool = False,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    """Waivers for this tenant, newest first."""
    if status is not None and status not in WAIVER_STATUSES:
        raise HTTPException(400, f"status must be one of {WAIVER_STATUSES}")
    stmt = select(Waiver).order_by(Waiver.id.desc())
    if principal.org_id is not None:
        stmt = stmt.where(Waiver.organization_id == principal.org_id)
    if system_id is not None:
        stmt = stmt.where(Waiver.system_id == system_id)
    if check_key is not None:
        stmt = stmt.where(Waiver.check_key == check_key)
    if control_id is not None:
        stmt = stmt.where(Waiver.control_id == control_id)
    if status is not None:
        stmt = stmt.where(Waiver.status == status)
    rows = (await session.execute(stmt)).scalars().all()
    today = datetime.now(UTC).date()
    # active_only is applied in Python through is_active, so there is one
    # definition of "in force" rather than a SQL predicate that could drift
    # from it.
    if active_only:
        rows = [w for w in rows if is_active(w, today=today)]
    return [_out(w) for w in rows]


@router.post("/waivers/{waiver_id}/approve")
async def approve_waiver(
    waiver_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*APPROVER_ROLES)),
) -> dict[str, Any]:
    """Grant a waiver. From here it suppresses, until it expires or is revoked."""
    w = await _load(session, waiver_id, principal)
    if w.status == "revoked":
        # Terminal: re-approving would resurrect an acceptance someone
        # deliberately withdrew, with no new decision recorded. A fresh
        # request is the honest path.
        raise HTTPException(409, "a revoked waiver cannot be re-approved; request a new one")
    if not can_approve(w.requested_by, principal.email, is_global=principal.is_global):
        raise HTTPException(403, "the requester may not approve their own waiver")
    w.status = "approved"
    w.approved_by = principal.email
    w.approved_at = datetime.now(UTC)
    await session.flush()
    await record_event(
        session,
        actor=principal.email,
        action="update",
        entity_type="waiver",
        entity_id=str(w.id),
        diff={"event": "approved", "approved_by": w.approved_by},
    )
    await session.commit()
    await session.refresh(w)
    return _out(w)


@router.post("/waivers/{waiver_id}/revoke")
async def revoke_waiver(
    waiver_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*APPROVER_ROLES)),
) -> dict[str, Any]:
    """Withdraw a waiver. Alerting resumes on the next result."""
    w = await _load(session, waiver_id, principal)
    w.status = "revoked"
    await session.flush()
    await record_event(
        session,
        actor=principal.email,
        action="update",
        entity_type="waiver",
        entity_id=str(w.id),
        diff={"event": "revoked"},
    )
    await session.commit()
    await session.refresh(w)
    return _out(w)
