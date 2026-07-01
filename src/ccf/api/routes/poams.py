"""POA&M management — FedRAMP-style fields, milestones, workflow, and export."""

from __future__ import annotations

import csv
import io
from datetime import UTC, date, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ...auth import Principal
from ...governance import bus
from ...models import POAM, PoamMilestone, System
from ..auth_deps import get_principal, org_systems_subq
from ..deps import get_session

router = APIRouter(prefix="/api/poams", tags=["poams"])

SEVERITIES = r"^(low|moderate|high|critical)$"
STATUSES = r"^(open|in_progress|completed|risk_accepted|closed)$"
MS_STATUS = r"^(pending|in_progress|completed|delayed)$"


class POAMCreate(BaseModel):
    system_id: int
    control_id: int | None = None
    title: str
    weakness: str | None = None
    severity: str = Field("moderate", pattern=SEVERITIES)
    status: str = Field("open", pattern=STATUSES)
    identified_on: date | None = None
    due_on: date | None = None
    owner_user_id: int | None = None
    source: str | None = None
    point_of_contact: str | None = None
    remediation_plan: str | None = None
    resources_required: str | None = None
    cost_estimate: str | None = None
    scheduled_completion: date | None = None
    risk_id: int | None = None
    vendor_id: int | None = None


class POAMUpdate(BaseModel):
    title: str | None = None
    weakness: str | None = None
    severity: str | None = Field(None, pattern=SEVERITIES)
    status: str | None = Field(None, pattern=STATUSES)
    identified_on: date | None = None
    due_on: date | None = None
    closed_on: date | None = None
    owner_user_id: int | None = None
    source: str | None = None
    point_of_contact: str | None = None
    remediation_plan: str | None = None
    resources_required: str | None = None
    cost_estimate: str | None = None
    scheduled_completion: date | None = None
    risk_id: int | None = None
    vendor_id: int | None = None


class MilestoneIn(BaseModel):
    description: str
    due_on: date | None = None
    status: str = Field("pending", pattern=MS_STATUS)
    sort_order: int = 0


class MilestoneUpdate(BaseModel):
    description: str | None = None
    due_on: date | None = None
    completed_on: date | None = None
    status: str | None = Field(None, pattern=MS_STATUS)
    sort_order: int | None = None


def _ms_out(m: PoamMilestone) -> dict[str, Any]:
    return {
        "id": m.id,
        "description": m.description,
        "due_on": m.due_on,
        "completed_on": m.completed_on,
        "status": m.status,
        "sort_order": m.sort_order,
    }


def _out(p: POAM, today: date | None = None) -> dict[str, Any]:
    ms = list(p.milestones or [])
    done = sum(1 for m in ms if m.status == "completed")
    overdue = (
        today is not None
        and p.due_on is not None
        and p.due_on < today
        and p.status
        in (
            "open",
            "in_progress",
        )
    )
    slipped = (
        p.original_due_on is not None and p.due_on is not None and p.due_on > p.original_due_on
    )
    return {
        "id": p.id,
        "system_id": p.system_id,
        "control_id": p.control_id,
        "title": p.title,
        "weakness": p.weakness,
        "severity": p.severity,
        "status": p.status,
        "identified_on": p.identified_on,
        "due_on": p.due_on,
        "original_due_on": p.original_due_on,
        "scheduled_completion": p.scheduled_completion,
        "closed_on": p.closed_on,
        "owner_user_id": p.owner_user_id,
        "point_of_contact": p.point_of_contact,
        "source": p.source,
        "remediation_plan": p.remediation_plan,
        "resources_required": p.resources_required,
        "cost_estimate": p.cost_estimate,
        "risk_id": p.risk_id,
        "vendor_id": p.vendor_id,
        "overdue": overdue,
        "deviation": slipped,
        "milestone_total": len(ms),
        "milestone_done": done,
        "progress_pct": round(100 * done / len(ms)) if ms else None,
        "milestones": [_ms_out(m) for m in ms],
    }


async def _require_poam(session: AsyncSession, pid: int, principal: Principal) -> POAM:
    obj = (
        await session.execute(
            select(POAM).options(selectinload(POAM.milestones)).where(POAM.id == pid)
        )
    ).scalar_one_or_none()
    if obj is None:
        raise HTTPException(404, "poam not found")
    if principal.org_id is not None:
        ok = (
            await session.execute(
                select(System.id).where(
                    System.id == obj.system_id, System.organization_id == principal.org_id
                )
            )
        ).scalar_one_or_none()
        if ok is None:
            raise HTTPException(404, "poam not found")
    return obj


@router.get("")
async def list_poams(
    session: AsyncSession = Depends(get_session),
    system_id: int | None = None,
    status: str | None = None,
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    stmt = select(POAM).options(selectinload(POAM.milestones)).order_by(POAM.due_on.nulls_last())
    if principal.org_id is not None:
        stmt = stmt.where(POAM.system_id.in_(org_systems_subq(principal)))
    if system_id is not None:
        stmt = stmt.where(POAM.system_id == system_id)
    if status:
        stmt = stmt.where(POAM.status == status)
    today = datetime.now(UTC).date()
    rows = (await session.execute(stmt)).scalars().all()
    return [_out(p, today) for p in rows]


@router.get("/export", response_model=None)
async def export_poams(
    fmt: str = Query("csv"),
    system_id: int | None = None,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> StreamingResponse:
    """FedRAMP-style POA&M export (CSV) of open items."""
    stmt = select(POAM).options(selectinload(POAM.milestones)).order_by(POAM.id)
    if principal.org_id is not None:
        stmt = stmt.where(POAM.system_id.in_(org_systems_subq(principal)))
    if system_id is not None:
        stmt = stmt.where(POAM.system_id == system_id)
    rows = (await session.execute(stmt)).scalars().all()
    today = datetime.now(UTC).date()
    cols = [
        "poam_id",
        "control_id",
        "weakness",
        "severity",
        "status",
        "point_of_contact",
        "source",
        "identified_on",
        "original_due_on",
        "scheduled_completion",
        "due_on",
        "milestones",
        "progress_pct",
        "resources_required",
        "cost_estimate",
    ]
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for p in rows:
        d = _out(p, today)
        ms = " | ".join(
            f"{m['description']} ({m['status']}"
            + (f", due {m['due_on']}" if m["due_on"] else "")
            + ")"
            for m in d["milestones"]
        )
        w.writerow(
            {
                "poam_id": p.id,
                "control_id": p.control_id,
                "weakness": (p.weakness or p.title),
                "severity": p.severity,
                "status": p.status,
                "point_of_contact": p.point_of_contact,
                "source": p.source,
                "identified_on": p.identified_on,
                "original_due_on": p.original_due_on,
                "scheduled_completion": p.scheduled_completion,
                "due_on": p.due_on,
                "milestones": ms,
                "progress_pct": d["progress_pct"],
                "resources_required": p.resources_required,
                "cost_estimate": p.cost_estimate,
            }
        )
    return StreamingResponse(
        iter([buf.getvalue().encode()]),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="poam.csv"'},
    )


@router.post("", status_code=201)
async def create_poam(
    body: POAMCreate,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    if principal.org_id is not None:
        ok = (
            await session.execute(
                select(System.id).where(
                    System.id == body.system_id, System.organization_id == principal.org_id
                )
            )
        ).scalar_one_or_none()
        if ok is None:
            raise HTTPException(404, "system not found")
    data = body.model_dump(exclude_none=True)
    obj = POAM(**data)
    if obj.due_on is not None and obj.original_due_on is None:
        obj.original_due_on = obj.due_on  # capture the baseline for deviation tracking
    session.add(obj)
    await session.flush()
    await bus.emit(
        session,
        verb="created",
        entity_type="poam",
        entity_id=obj.id,
        summary=f"POA&M opened ({obj.severity}): {obj.title}",
        org_id=principal.org_id,
        actor=principal.email,
    )
    await session.commit()
    obj = await _require_poam(session, obj.id, principal)
    return _out(obj, datetime.now(UTC).date())


@router.get("/{pid}")
async def get_poam(
    pid: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    obj = await _require_poam(session, pid, principal)
    return _out(obj, datetime.now(UTC).date())


@router.patch("/{pid}")
async def update_poam(
    pid: int,
    body: POAMUpdate,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    obj = await _require_poam(session, pid, principal)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(obj, k, v)
    await bus.emit(
        session,
        verb="updated",
        entity_type="poam",
        entity_id=obj.id,
        summary=f"POA&M {obj.status}: {obj.title}",
        org_id=principal.org_id,
        actor=principal.email,
    )
    await session.commit()
    obj = await _require_poam(session, pid, principal)
    return _out(obj, datetime.now(UTC).date())


@router.post("/{pid}/close")
async def close_poam(
    pid: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    obj = await _require_poam(session, pid, principal)
    obj.status = "closed"
    obj.closed_on = date.today()
    await bus.emit(
        session,
        verb="closed",
        entity_type="poam",
        entity_id=obj.id,
        summary=f"POA&M closed: {obj.title}",
        org_id=principal.org_id,
        actor=principal.email,
    )
    await session.commit()
    obj = await _require_poam(session, pid, principal)
    return _out(obj, datetime.now(UTC).date())


# --- Milestones --------------------------------------------------------------


@router.post("/{pid}/milestones", status_code=201)
async def add_milestone(
    pid: int,
    body: MilestoneIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    await _require_poam(session, pid, principal)
    m = PoamMilestone(poam_id=pid, **body.model_dump())
    session.add(m)
    await session.commit()
    await session.refresh(m)
    return _ms_out(m)


@router.patch("/{pid}/milestones/{mid}")
async def update_milestone(
    pid: int,
    mid: int,
    body: MilestoneUpdate,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    await _require_poam(session, pid, principal)
    m = (
        await session.execute(
            select(PoamMilestone).where(PoamMilestone.id == mid, PoamMilestone.poam_id == pid)
        )
    ).scalar_one_or_none()
    if m is None:
        raise HTTPException(404, "milestone not found")
    data = body.model_dump(exclude_none=True)
    for k, v in data.items():
        setattr(m, k, v)
    if data.get("status") == "completed" and m.completed_on is None:
        m.completed_on = date.today()
    await session.commit()
    await session.refresh(m)
    return _ms_out(m)
