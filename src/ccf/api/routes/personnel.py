"""Personnel & Access API — workforce security lifecycle.

People (PS-2 risk designation, PS-3 screening, PS-4/PS-5 lifecycle), security
training (AT-2/AT-3), and access-certification reviews (AC-2). Onboarding and
offboarding drive automated tasks/training via :mod:`ccf.governance.personnel`.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ...auth import Principal
from ...governance import bus, personnel
from ...models_people import AccessReview, AccessReviewItem, Person, TrainingRecord
from ..auth_deps import get_principal
from ..deps import get_session

router = APIRouter(prefix="/api", tags=["personnel"])

EMPLOYMENT = r"^(employee|contractor)$"
RISK = r"^(low|moderate|high)$"
SCREENING = r"^(not_started|initiated|in_progress|completed|waived)$"
DECISION = r"^(pending|retain|revoke|modify)$"


# --- schemas ----------------------------------------------------------------


class PersonIn(BaseModel):
    full_name: str
    email: str | None = None
    employment_type: str = Field("employee", pattern=EMPLOYMENT)
    position: str | None = None
    department: str | None = None
    manager: str | None = None
    start_date: date | None = None
    risk_designation: str = Field("low", pattern=RISK)
    background_check_status: str = Field("not_started", pattern=SCREENING)
    background_check_completed_on: date | None = None
    notes: str | None = None


class PersonUpdate(BaseModel):
    full_name: str | None = None
    email: str | None = None
    position: str | None = None
    department: str | None = None
    manager: str | None = None
    risk_designation: str | None = Field(None, pattern=RISK)
    background_check_status: str | None = Field(None, pattern=SCREENING)
    background_check_completed_on: date | None = None
    notes: str | None = None


class OffboardIn(BaseModel):
    end_date: date | None = None


class TrainingIn(BaseModel):
    course: str
    kind: str = "awareness"
    control_ref: str | None = None
    assigned_on: date | None = None
    due_on: date | None = None


class TrainingComplete(BaseModel):
    completed_on: date | None = None
    evidence_ref: str | None = None


class ReviewIn(BaseModel):
    name: str
    system_id: int | None = None
    reviewer: str | None = None
    started_on: date | None = None
    due_on: date | None = None


class ReviewItemIn(BaseModel):
    subject: str
    person_id: int | None = None
    resource: str | None = None
    access_level: str | None = None


class ItemDecision(BaseModel):
    decision: str = Field(..., pattern=DECISION)
    note: str | None = None


# --- serializers ------------------------------------------------------------


def _person_out(p: Person) -> dict[str, Any]:
    return {
        "id": p.id,
        "full_name": p.full_name,
        "email": p.email,
        "employment_type": p.employment_type,
        "position": p.position,
        "department": p.department,
        "manager": p.manager,
        "status": p.status,
        "start_date": p.start_date,
        "end_date": p.end_date,
        "risk_designation": p.risk_designation,
        "background_check_status": p.background_check_status,
        "background_check_completed_on": p.background_check_completed_on,
        "notes": p.notes,
    }


def _training_out(t: TrainingRecord) -> dict[str, Any]:
    return {
        "id": t.id,
        "person_id": t.person_id,
        "course": t.course,
        "kind": t.kind,
        "control_ref": t.control_ref,
        "assigned_on": t.assigned_on,
        "due_on": t.due_on,
        "completed_on": t.completed_on,
        "status": t.status,
        "evidence_ref": t.evidence_ref,
    }


def _item_out(i: AccessReviewItem) -> dict[str, Any]:
    return {
        "id": i.id,
        "review_id": i.review_id,
        "person_id": i.person_id,
        "subject": i.subject,
        "resource": i.resource,
        "access_level": i.access_level,
        "decision": i.decision,
        "decided_on": i.decided_on,
        "note": i.note,
    }


def _review_out(r: AccessReview) -> dict[str, Any]:
    items = list(r.items or [])
    decided = sum(1 for i in items if i.decision != "pending")
    return {
        "id": r.id,
        "name": r.name,
        "system_id": r.system_id,
        "reviewer": r.reviewer,
        "status": r.status,
        "started_on": r.started_on,
        "due_on": r.due_on,
        "completed_on": r.completed_on,
        "item_total": len(items),
        "item_decided": decided,
        "items": [_item_out(i) for i in items],
    }


async def _require_person(session: AsyncSession, pid: int, principal: Principal) -> Person:
    p = (await session.execute(select(Person).where(Person.id == pid))).scalar_one_or_none()
    if p is None or (principal.org_id is not None and p.organization_id != principal.org_id):
        raise HTTPException(404, "person not found")
    return p


async def _require_review(session: AsyncSession, rid: int, principal: Principal) -> AccessReview:
    r = (
        await session.execute(
            select(AccessReview).options(selectinload(AccessReview.items)).where(
                AccessReview.id == rid
            )
        )
    ).scalar_one_or_none()
    if r is None or (principal.org_id is not None and r.organization_id != principal.org_id):
        raise HTTPException(404, "access review not found")
    return r


# --- people -----------------------------------------------------------------


@router.get("/personnel/summary")
async def personnel_summary(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    return await personnel.summary(session, org_id=principal.org_id)


@router.get("/personnel")
async def list_personnel(
    status: str | None = None,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    stmt = select(Person).order_by(Person.full_name)
    if principal.org_id is not None:
        stmt = stmt.where(Person.organization_id == principal.org_id)
    if status:
        stmt = stmt.where(Person.status == status)
    return [_person_out(p) for p in (await session.execute(stmt)).scalars().all()]


@router.post("/personnel", status_code=201)
async def create_person(
    body: PersonIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Create a person and run onboarding (baseline training + screening task)."""
    p = Person(organization_id=principal.org_id, status="active", **body.model_dump())
    session.add(p)
    await session.flush()
    await personnel.onboard(session, p, actor=principal.email)
    await session.commit()
    return _person_out(p)


@router.get("/personnel/{pid}")
async def get_person(
    pid: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    p = await _require_person(session, pid, principal)
    training = (
        await session.execute(
            select(TrainingRecord)
            .where(TrainingRecord.person_id == pid)
            .order_by(TrainingRecord.id)
        )
    ).scalars().all()
    return {**_person_out(p), "training": [_training_out(t) for t in training]}


@router.patch("/personnel/{pid}")
async def update_person(
    pid: int,
    body: PersonUpdate,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    p = await _require_person(session, pid, principal)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(p, k, v)
    if p.background_check_status == "completed" and p.background_check_completed_on is None:
        p.background_check_completed_on = datetime.now(UTC).date()
    await session.commit()
    return _person_out(p)


@router.post("/personnel/{pid}/offboard")
async def offboard_person(
    pid: int,
    body: OffboardIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    p = await _require_person(session, pid, principal)
    await personnel.offboard(session, p, end_date=body.end_date, actor=principal.email)
    await session.commit()
    return _person_out(p)


# --- training ---------------------------------------------------------------


@router.post("/personnel/{pid}/training", status_code=201)
async def assign_training(
    pid: int,
    body: TrainingIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    await _require_person(session, pid, principal)
    t = TrainingRecord(person_id=pid, status="assigned", **body.model_dump())
    session.add(t)
    await session.commit()
    await session.refresh(t)
    return _training_out(t)


@router.post("/training/{tid}/complete")
async def complete_training(
    tid: int,
    body: TrainingComplete,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    t = (
        await session.execute(select(TrainingRecord).where(TrainingRecord.id == tid))
    ).scalar_one_or_none()
    if t is None:
        raise HTTPException(404, "training record not found")
    await _require_person(session, t.person_id, principal)  # org scope via parent
    t.status = "completed"
    t.completed_on = body.completed_on or datetime.now(UTC).date()
    if body.evidence_ref:
        t.evidence_ref = body.evidence_ref
    await session.commit()
    return _training_out(t)


# --- access reviews ---------------------------------------------------------


@router.get("/access-reviews")
async def list_reviews(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    stmt = (
        select(AccessReview)
        .options(selectinload(AccessReview.items))
        .order_by(AccessReview.id.desc())
    )
    if principal.org_id is not None:
        stmt = stmt.where(AccessReview.organization_id == principal.org_id)
    return [_review_out(r) for r in (await session.execute(stmt)).scalars().all()]


@router.post("/access-reviews", status_code=201)
async def create_review(
    body: ReviewIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    r = AccessReview(organization_id=principal.org_id, status="open", **body.model_dump())
    session.add(r)
    await session.flush()
    await bus.emit(
        session,
        verb="created",
        entity_type="access_review",
        entity_id=r.id,
        summary=f"Access review opened: {r.name}",
        org_id=principal.org_id,
        actor=principal.email,
    )
    await session.commit()
    r = await _require_review(session, r.id, principal)
    return _review_out(r)


@router.get("/access-reviews/{rid}")
async def get_review(
    rid: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    return _review_out(await _require_review(session, rid, principal))


@router.post("/access-reviews/{rid}/items", status_code=201)
async def add_review_item(
    rid: int,
    body: ReviewItemIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    await _require_review(session, rid, principal)
    item = AccessReviewItem(review_id=rid, decision="pending", **body.model_dump())
    session.add(item)
    await session.commit()
    await session.refresh(item)
    return _item_out(item)


@router.patch("/access-review-items/{iid}")
async def decide_item(
    iid: int,
    body: ItemDecision,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    item = (
        await session.execute(select(AccessReviewItem).where(AccessReviewItem.id == iid))
    ).scalar_one_or_none()
    if item is None:
        raise HTTPException(404, "access review item not found")
    await _require_review(session, item.review_id, principal)  # org scope via parent
    item.decision = body.decision
    item.note = body.note
    item.decided_on = datetime.now(UTC).date()
    await session.commit()
    return _item_out(item)


@router.post("/access-reviews/{rid}/complete")
async def complete_review(
    rid: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    r = await _require_review(session, rid, principal)
    pending = [i for i in (r.items or []) if i.decision == "pending"]
    if pending:
        raise HTTPException(409, f"{len(pending)} item(s) still pending a decision")
    r.status = "completed"
    r.completed_on = datetime.now(UTC).date()
    await bus.emit(
        session,
        verb="completed",
        entity_type="access_review",
        entity_id=r.id,
        summary=f"Access review completed: {r.name}",
        org_id=principal.org_id,
        actor=principal.email,
    )
    await session.commit()
    return _review_out(await _require_review(session, rid, principal))
