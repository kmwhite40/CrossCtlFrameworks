"""Systems / control implementation / POA&M endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...models import (
    POAM,
    Control,
    ControlImplementation,
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
from ..auth_deps import get_principal
from ..deps import get_session

router = APIRouter(prefix="/api/systems", tags=["systems"])


async def require_system_in_scope(
    session: AsyncSession, system_id: int, principal: Principal
) -> System:
    """Fetch a system, 404-ing if it is outside the principal's organization."""
    sys = (await session.execute(select(System).where(System.id == system_id))).scalar_one_or_none()
    if sys is None or (principal.org_id is not None and sys.organization_id != principal.org_id):
        raise HTTPException(404, "system not found")
    return sys


@router.get("", response_model=list[SystemOut])
async def list_systems(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[SystemOut]:
    stmt = select(System).order_by(System.name)
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
            .where(POAM.status.in_(("open", "in_progress")))
        )
    ).scalar_one()
    overdue_poams = (
        await session.execute(
            select(func.count(POAM.id))
            .where(POAM.system_id == system_id)
            .where(POAM.status.in_(("open", "in_progress")))
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


@router.patch("/{system_id}/implementations/{control_id}", response_model=ImplementationOut)
async def upsert_implementation(
    system_id: int,
    control_id: int,
    body: ImplementationUpdate,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> ImplementationOut:
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
    await session.commit()
    await session.refresh(obj)
    return ImplementationOut.model_validate(obj)


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
