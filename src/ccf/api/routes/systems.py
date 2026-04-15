"""Systems / control implementation / POA&M endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...models import (
    Control,
    ControlImplementation,
    POAM,
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
from ..deps import get_session

router = APIRouter(prefix="/api/systems", tags=["systems"])


@router.get("", response_model=list[SystemOut])
async def list_systems(session: AsyncSession = Depends(get_session)) -> list[SystemOut]:
    rows = (await session.execute(select(System).order_by(System.name))).scalars().all()
    return [SystemOut.model_validate(r) for r in rows]


@router.post("", response_model=SystemOut, status_code=201)
async def create_system(
    body: SystemCreate,
    session: AsyncSession = Depends(get_session),
) -> SystemOut:
    obj = System(**body.model_dump(exclude_none=True))
    session.add(obj)
    await session.commit()
    await session.refresh(obj)
    return SystemOut.model_validate(obj)


@router.get("/{system_id}/summary", response_model=ComplianceSummary)
async def compliance_summary(
    system_id: int,
    session: AsyncSession = Depends(get_session),
) -> ComplianceSummary:
    sys = (
        await session.execute(select(System).where(System.id == system_id))
    ).scalar_one_or_none()
    if sys is None:
        raise HTTPException(404, "system not found")

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
    buckets = {s: 0 for s in (
        "implemented", "partial", "planned",
        "not_implemented", "inherited", "not_applicable",
    )}
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
) -> ImplementationOut:
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


class BulkImplementationRow(__import__("pydantic").BaseModel):
    identifier: str
    status: str
    narrative: str | None = None


@router.post("/{system_id}/implementations/bulk")
async def bulk_import_implementations(
    system_id: int,
    rows: list[BulkImplementationRow],
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Bulk-seed implementation state for a system from a list of rows."""
    if not (await session.execute(select(System).where(System.id == system_id))).scalar_one_or_none():
        raise HTTPException(404, "system not found")

    ctrls = {
        c.identifier: c.id for c in (
            await session.execute(select(Control))
        ).scalars().all()
    }
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
) -> list[POAMOut]:
    rows = (
        await session.execute(
            select(POAM).where(POAM.system_id == system_id).order_by(POAM.due_on)
        )
    ).scalars().all()
    return [POAMOut.model_validate(r) for r in rows]
