"""Systems / control implementation / POA&M endpoints."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...constants import POAM_ACTIVE_STATUSES
from ...governance import bus, reactions
from ...models import (
    POAM,
    Assessment,
    Control,
    ControlImplementation,
    Evidence,
    Risk,
    ScoringStatus,
    System,
)
from ...schemas import (
    ComplianceSummary,
    ImplementationOut,
    ImplementationUpdate,
    POAMOut,
    SystemCreate,
    SystemOut,
)
from ..auth_deps import get_principal, require_role
from ..deps import get_session

# Severities that block authorization while an open weakness exists.
_ATO_BLOCKING_SEVERITIES = ("critical", "high")
# POA&M statuses that represent an unresolved weakness (mirrors compliance_summary).
_ATO_BLOCKING_STATUSES = POAM_ACTIVE_STATUSES
# Default authorization period when the caller doesn't specify an expiration.
_DEFAULT_ATO_PERIOD_DAYS = 365

router = APIRouter(prefix="/api/systems", tags=["systems"])


async def require_system_in_scope(
    session: AsyncSession, system_id: int, principal: Principal
) -> System:
    """Fetch a system, 404-ing if it is outside the principal's organization
    or has been soft-deleted (DATA-04) — a deleted system behaves as gone for
    every normal operation even though its row (and dependents) still exist.
    """
    sys = (
        await session.execute(
            select(System).where(System.id == system_id, System.deleted_at.is_(None))
        )
    ).scalar_one_or_none()
    if sys is None or (principal.org_id is not None and sys.organization_id != principal.org_id):
        raise HTTPException(404, "system not found")
    return sys


@router.get("", response_model=list[SystemOut])
async def list_systems(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[SystemOut]:
    stmt = select(System).where(System.deleted_at.is_(None)).order_by(System.name)
    if principal.org_id is not None:
        stmt = stmt.where(System.organization_id == principal.org_id)
    rows = (await session.execute(stmt)).scalars().all()
    return [SystemOut.model_validate(r) for r in rows]


@router.post("", response_model=SystemOut, status_code=201)
async def create_system(
    body: SystemCreate,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> SystemOut:
    data = body.model_dump(exclude_none=True)
    # Tenant principals may only create systems within their own organization.
    if principal.org_id is not None:
        data["organization_id"] = principal.org_id
    obj = System(**data)
    session.add(obj)
    await session.commit()
    await session.refresh(obj)
    return SystemOut.model_validate(obj)


async def _dependent_authorization_record_count(session: AsyncSession, system_id: int) -> int:
    """Count POA&Ms, assessments, risks, evidence, control implementations, and
    scoring statuses attached to ``system_id`` (DATA-04 hard-delete guard) —
    evidence is reached through ``control_implementations`` since it has no
    direct ``system_id`` FK. Control implementations and scoring statuses are
    counted directly (not just their own dependents) because ``System.
    implementations``/scoring statuses cascade-delete with the system
    (``ondelete=CASCADE`` in models.py): a system with SSP control
    implementation statements but no POA&M/assessment/risk/evidence must still
    be refused a hard delete, or those statements are silently wiped."""
    poams = (
        await session.execute(select(func.count(POAM.id)).where(POAM.system_id == system_id))
    ).scalar_one()
    assessments = (
        await session.execute(
            select(func.count(Assessment.id)).where(Assessment.system_id == system_id)
        )
    ).scalar_one()
    risks = (
        await session.execute(select(func.count(Risk.id)).where(Risk.system_id == system_id))
    ).scalar_one()
    evidence = (
        await session.execute(
            select(func.count(Evidence.id))
            .join(
                ControlImplementation,
                ControlImplementation.id == Evidence.implementation_id,
            )
            .where(ControlImplementation.system_id == system_id)
        )
    ).scalar_one()
    implementations = (
        await session.execute(
            select(func.count(ControlImplementation.id)).where(
                ControlImplementation.system_id == system_id
            )
        )
    ).scalar_one()
    scoring_statuses = (
        await session.execute(
            select(func.count(ScoringStatus.id)).where(ScoringStatus.system_id == system_id)
        )
    ).scalar_one()
    return poams + assessments + risks + evidence + implementations + scoring_statuses


@router.delete("/{system_id}", status_code=204)
async def delete_system(
    system_id: int,
    hard: bool = False,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> None:
    """Soft-delete a system (DATA-04): sets ``deleted_at`` so the system
    disappears from inventory/list/get views and tenant scoping, without
    triggering the ``CASCADE`` that would otherwise irreversibly wipe its
    POA&Ms, assessments, evidence, control implementations, and risks.

    Pass ``?hard=true`` to fall back to the old hard ``DELETE`` behavior —
    refused with 409 when the system still has dependent authorization
    records, so a real purge only ever removes an empty system.
    """
    sys = await require_system_in_scope(session, system_id, principal)
    if hard:
        dependent_count = await _dependent_authorization_record_count(session, system_id)
        if dependent_count:
            raise HTTPException(
                409,
                "cannot hard-delete: system has dependent authorization records "
                "(POA&Ms/assessments/evidence) — use the default soft delete instead",
            )
        await session.delete(sys)
    else:
        sys.deleted_at = datetime.now(UTC)
    await session.commit()


class AuthorizeRequest(BaseModel):
    expires_on: date | None = None


@router.post("/{system_id}/authorize", response_model=SystemOut)
async def authorize_system(
    system_id: int,
    body: AuthorizeRequest = AuthorizeRequest(),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> SystemOut:
    """Transition a system's ``ato_status`` toward "authorized".

    Refuses (409) when the system has an open POA&M of critical/high severity —
    an unresolved high-risk weakness must not be authorized away. Does not add
    an approval workflow; that's a later slice (ISSM-08).
    """
    sys = await require_system_in_scope(session, system_id, principal)

    blocking = (
        await session.execute(
            select(func.count(POAM.id))
            .where(POAM.system_id == system_id)
            .where(POAM.severity.in_(_ATO_BLOCKING_SEVERITIES))
            .where(POAM.status.in_(_ATO_BLOCKING_STATUSES))
        )
    ).scalar_one()
    if blocking:
        raise HTTPException(
            409,
            "cannot authorize: system has an open critical/high severity POA&M",
        )

    previous_status = sys.ato_status
    sys.ato_status = "authorized"
    sys.ato_expires_on = body.expires_on or (
        date.today() + timedelta(days=_DEFAULT_ATO_PERIOD_DAYS)
    )
    await session.flush()
    await bus.emit(
        session,
        verb="authorized",
        entity_type="system",
        entity_id=sys.id,
        summary=(
            f"System {sys.name} authorized ({previous_status or 'none'} → authorized), "
            f"expires {sys.ato_expires_on}"
        ),
        org_id=principal.org_id,
        actor=principal.email,
    )
    await session.commit()
    await session.refresh(sys)
    return SystemOut.model_validate(sys)


@router.get("/{system_id}/summary", response_model=ComplianceSummary)
async def compliance_summary(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> ComplianceSummary:
    sys = await require_system_in_scope(session, system_id, principal)

    # Total controls for this baseline.
    baseline_col = {
        "low": Control.fisma_low,
        "moderate": Control.fisma_mod,
        "high": Control.fisma_high,
    }.get(sys.baseline or "", Control.fisma_mod)
    total = (
        await session.execute(select(func.count(Control.id)).where(baseline_col.is_(True)))
    ).scalar_one()

    stmt = (
        select(ControlImplementation.status, func.count())
        .where(ControlImplementation.system_id == system_id)
        .group_by(ControlImplementation.status)
    )
    buckets = {
        s: 0
        for s in (
            "implemented",
            "partial",
            "planned",
            "not_implemented",
            "inherited",
            "not_applicable",
        )
    }
    for status, count in (await session.execute(stmt)).all():
        buckets[status] = count

    implemented = buckets["implemented"] + buckets["inherited"]
    applicable = total - buckets["not_applicable"]
    coverage = (implemented / applicable * 100.0) if applicable else 0.0

    open_poams = (
        await session.execute(
            select(func.count(POAM.id))
            .where(POAM.system_id == system_id)
            .where(POAM.status.in_(POAM_ACTIVE_STATUSES))
        )
    ).scalar_one()
    overdue_poams = (
        await session.execute(
            select(func.count(POAM.id))
            .where(POAM.system_id == system_id)
            .where(POAM.status.in_(POAM_ACTIVE_STATUSES))
            .where(POAM.due_on < func.current_date())
        )
    ).scalar_one()

    return ComplianceSummary(
        system_id=system_id,
        total_controls=total,
        implemented=buckets["implemented"],
        partial=buckets["partial"],
        planned=buckets["planned"],
        not_implemented=buckets["not_implemented"],
        inherited=buckets["inherited"],
        not_applicable=buckets["not_applicable"],
        coverage_pct=round(coverage, 2),
        open_poams=open_poams,
        overdue_poams=overdue_poams,
    )


@router.patch("/{system_id}/implementations/{control_id}", response_model=None)
async def upsert_implementation(
    system_id: int,
    control_id: int,
    body: ImplementationUpdate,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    await require_system_in_scope(session, system_id, principal)
    obj = (
        await session.execute(
            select(ControlImplementation)
            .where(ControlImplementation.system_id == system_id)
            .where(ControlImplementation.control_id == control_id)
        )
    ).scalar_one_or_none()
    if obj is None:
        obj = ControlImplementation(system_id=system_id, control_id=control_id)
        session.add(obj)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(obj, k, v)
    await session.flush()
    await bus.emit(
        session,
        verb="updated",
        entity_type="control_implementation",
        entity_id=obj.id,
        summary=f"Control implementation {control_id} → {obj.status}",
        org_id=principal.org_id,
        actor=principal.email,
    )
    # Reaction: propagate this status to crosswalked controls (map once, comply many).
    propagation = await reactions.propagate_implementation(
        session,
        system_id=system_id,
        control_id=control_id,
        status=obj.status,
        org_id=principal.org_id,
        actor=principal.email,
    )
    await session.commit()
    await session.refresh(obj)
    out = ImplementationOut.model_validate(obj).model_dump()
    out["propagation"] = propagation
    return out


class BulkImplementationRow(BaseModel):
    identifier: str
    status: str
    narrative: str | None = None


@router.post("/{system_id}/implementations/bulk")
async def bulk_import_implementations(
    system_id: int,
    rows: list[BulkImplementationRow],
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, int]:
    """Bulk-seed implementation state for a system from a list of rows."""
    await require_system_in_scope(session, system_id, principal)

    ctrls = {c.identifier: c.id for c in (await session.execute(select(Control))).scalars().all()}
    upserted = 0
    skipped = 0
    for r in rows:
        cid = ctrls.get(r.identifier)
        if not cid:
            skipped += 1
            continue
        obj = (
            await session.execute(
                select(ControlImplementation)
                .where(ControlImplementation.system_id == system_id)
                .where(ControlImplementation.control_id == cid)
            )
        ).scalar_one_or_none()
        if obj is None:
            obj = ControlImplementation(system_id=system_id, control_id=cid)
            session.add(obj)
        obj.status = r.status
        if r.narrative is not None:
            obj.narrative = r.narrative
        upserted += 1
    await session.commit()
    return {"upserted": upserted, "skipped": skipped, "total": len(rows)}


@router.get("/{system_id}/poams", response_model=list[POAMOut])
async def list_poams(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[POAMOut]:
    await require_system_in_scope(session, system_id, principal)
    rows = (
        (
            await session.execute(
                select(POAM).where(POAM.system_id == system_id).order_by(POAM.due_on)
            )
        )
        .scalars()
        .all()
    )
    return [POAMOut.model_validate(r) for r in rows]
