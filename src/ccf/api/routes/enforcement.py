"""Remediation-plan endpoints -- the only way a change reaches an environment.

Plan, review, approve, apply, reverse. Each is a separate call by design: there
is no endpoint that plans and applies in one step, because the review between
them is the control.

Every state-changing call -- including plan **creation** -- is role-gated to
the same role that approves a waiver, and the requester cannot approve their
own plan (enforced in the service, where it cannot be bypassed by a different
caller). Creation is gated too, and gated *before* the service runs a provider
over the full remediable set (``build_steps``'s blast-radius check, in turn,
runs before the provider ever reaches the tenant): without the role gate any
authenticated caller -- including a ``viewer`` -- could make the platform
authenticate with the customer's write-scoped app registration and issue one
Graph call per failing resource before the blast radius ever gets a chance to
refuse.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...enforcement.service import (
    EnforcementError,
    apply_plan,
    approve_plan,
    create_plan,
    reverse_plan,
)
from ...models_enforcement import RemediationPlan
from ..auth_deps import get_principal, require_role
from ..deps import get_session

router = APIRouter(prefix="/api", tags=["enforcement"])

#: The roles that may create, approve, apply, or reverse a remediation plan --
#: i.e. every call that either reaches the customer's tenant or leads directly
#: to one that will.
#:
#: Deliberately ``admin`` only -- the same set ``api/routes/waivers.py``'s
#: ``APPROVER_ROLES`` settled on, for the same reasons, applied at least as
#: strictly: a waiver accepts risk on paper, where this writes to the
#: customer's live tenant. ``models.py``'s ``user_role`` enum is exactly
#: ``admin | control_owner | assessor | viewer`` -- the previous value here
#: (``"admin", "issm", "isso"``) named two roles the database cannot store, so
#: the effective gate was already ``admin`` only; this makes that explicit
#: instead of accidental, and a 403 now names a role the caller could actually
#: hold.
#:  - ``control_owner`` is typically the operational owner of the system being
#:    changed -- often the same conflict of interest ``can_approve``'s
#:    separation-of-duties check exists to police for approval, and for
#:    *creation* it would let the party with the most incentive to see a
#:    write happen be the one who decides a plan is worth reviewing at all.
#:  - ``assessor`` evaluates whether a control works; deciding to change a
#:    production system is a different responsibility, kept separate for the
#:    same independence reason FedRAMP keeps a 3PAO from remediating its own
#:    findings.
#:  - ``viewer`` is read-only by definition, and is exactly the identity this
#:    fix closes off from reaching the tenant through plan creation.
#: Because creation and approval share this one set, completing the full
#: plan -> approve -> apply cycle requires two distinct admins (``can_approve``
#: still refuses a plan approving itself) -- a deliberately higher bar than a
#: waiver, matching that this path writes rather than merely documents.
ENFORCER_ROLES = ("admin",)


class PlanIn(BaseModel):
    check_key: str
    #: Narrow the plan to specific resources -- the intended path for "just
    #: this one account".
    resource_ids: list[str] | None = None
    notes: str | None = None


def _out(plan: RemediationPlan) -> dict[str, Any]:
    return {
        "id": plan.id,
        "system_id": plan.system_id,
        "check_key": plan.check_key,
        "provider_key": plan.provider_key,
        "status": plan.status,
        "resource_count": plan.resource_count,
        "refusal_reason": plan.refusal_reason,
        "steps": plan.steps,
        "outcomes": plan.outcomes,
        "requested_by": plan.requested_by,
        "approved_by": plan.approved_by,
        "approved_at": plan.approved_at,
        "applied_at": plan.applied_at,
        "reversed_at": plan.reversed_at,
        "result_id": plan.result_id,
        "created_at": plan.created_at,
    }


async def _require_plan(
    session: AsyncSession, plan_id: int, principal: Principal
) -> RemediationPlan:
    """One plan, or 404 -- including another tenant's.

    404 rather than 403: confirming an id exists is itself a disclosure.
    """
    plan = (
        await session.execute(
            select(RemediationPlan).where(RemediationPlan.id == plan_id)
        )
    ).scalars().first()
    if plan is None or (
        principal.org_id is not None and plan.organization_id != principal.org_id
    ):
        raise HTTPException(404, "remediation plan not found")
    return plan


@router.post("/systems/{system_id}/remediation-plans", status_code=201)
async def create(
    system_id: int,
    body: PlanIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*ENFORCER_ROLES)),
) -> dict[str, Any]:
    """Build a plan from the latest recorded findings. Writes nothing to the
    environment itself, but *does* reach the tenant: the provider issues one
    read call per remediable resource to capture reversal data, after the
    blast-radius refusal in ``build_steps`` -- so this is role-gated rather
    than merely authenticated, the same as approve/apply/reverse.

    A refused plan comes back **201 with status "refused"**, not an error: the
    refusal and its reason are a stored decision an operator should be able to
    read, and an HTTP error would discard the row's id.
    """
    try:
        plan = await create_plan(
            session,
            system_id=system_id,
            check_key=body.check_key,
            actor=principal.email,
            only=tuple(body.resource_ids) if body.resource_ids else None,
        )
    except EnforcementError as e:
        raise HTTPException(404, str(e)) from e
    if body.notes:
        plan.notes = body.notes
    await session.commit()
    await session.refresh(plan)
    return _out(plan)


@router.get("/remediation-plans")
async def list_plans(
    system_id: int | None = None,
    status: str | None = None,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    stmt = select(RemediationPlan).order_by(RemediationPlan.id.desc())
    if principal.org_id is not None:
        stmt = stmt.where(RemediationPlan.organization_id == principal.org_id)
    if system_id is not None:
        stmt = stmt.where(RemediationPlan.system_id == system_id)
    if status is not None:
        stmt = stmt.where(RemediationPlan.status == status)
    return [_out(p) for p in (await session.execute(stmt)).scalars().all()]


@router.get("/remediation-plans/{plan_id}")
async def get_plan(
    plan_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    return _out(await _require_plan(session, plan_id, principal))


@router.post("/remediation-plans/{plan_id}/approve")
async def approve(
    plan_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*ENFORCER_ROLES)),
) -> dict[str, Any]:
    """Approve a plan. Still writes nothing to the environment."""
    plan = await _require_plan(session, plan_id, principal)
    try:
        await approve_plan(session, plan, approver=principal.email)
    except EnforcementError as e:
        raise HTTPException(409, str(e)) from e
    await session.commit()
    await session.refresh(plan)
    return _out(plan)


@router.post("/remediation-plans/{plan_id}/apply")
async def apply(
    plan_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*ENFORCER_ROLES)),
) -> dict[str, Any]:
    """Apply an approved plan. **This is the call that changes the environment.**

    Every precondition is re-checked in the service first, because approval may
    be hours old.
    """
    plan = await _require_plan(session, plan_id, principal)
    try:
        await apply_plan(session, plan, actor=principal.email)
    except EnforcementError as e:
        raise HTTPException(409, str(e)) from e
    await session.commit()
    await session.refresh(plan)
    return _out(plan)


@router.post("/remediation-plans/{plan_id}/reverse")
async def reverse(
    plan_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*ENFORCER_ROLES)),
) -> dict[str, Any]:
    """Undo an applied plan, restoring each step's captured state."""
    plan = await _require_plan(session, plan_id, principal)
    try:
        await reverse_plan(session, plan, actor=principal.email)
    except EnforcementError as e:
        raise HTTPException(409, str(e)) from e
    await session.commit()
    await session.refresh(plan)
    return _out(plan)
