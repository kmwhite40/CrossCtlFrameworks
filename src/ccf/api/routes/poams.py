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

from ...assessment.engine import jobs as engine_jobs
from ...auth import Principal
from ...config import get_settings
from ...governance import bus
from ...governance.approvals import entity_state, entity_states
from ...logging import get_logger
from ...models import POAM, Approval, ControlImplementation, Evidence, PoamMilestone, System
from ..auth_deps import get_principal, org_systems_subq
from ..deps import get_session

router = APIRouter(prefix="/api/poams", tags=["poams"])
log = get_logger(__name__)

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


def _out(p: POAM, today: date | None = None, approval_state: str | None = None) -> dict[str, Any]:
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
        "source_ref": p.source_ref,
        "remediation_plan": p.remediation_plan,
        "resources_required": p.resources_required,
        "cost_estimate": p.cost_estimate,
        "risk_id": p.risk_id,
        "vendor_id": p.vendor_id,
        # Read-time reflection of the ISSM-08/09 approval workflow (ISSM-07): draft
        # (never submitted) | submitted (pending review) | approved | rejected. This
        # does NOT drive the closure gate itself — see _require_closure_gate — it
        # only makes the decision visible on the record.
        "approval_state": approval_state,
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


# --- Closure gate (ISSM-08/09): a POA&M can only close once the weakness is
# validated (all milestones complete) or corroborated by a closure evidence
# artifact, and — when auth is enabled — with a separation-of-duties approval
# from a principal other than the one who submitted it. -----------------------


def _milestones_satisfy_closure(obj: POAM) -> bool:
    ms = obj.milestones or []
    return bool(ms) and all(m.status == "completed" for m in ms)


async def _has_closure_evidence(session: AsyncSession, obj: POAM) -> bool:
    """A closure artifact: *dated* evidence collected against the control this
    POA&M remediates (same system + control) that post-dates the weakness.

    Requires ``Evidence.collected_on`` to be present and, when the POA&M records
    an ``identified_on``, on/after it — so pre-existing evidence that predates the
    weakness cannot satisfy closure (it does not demonstrate remediation)."""
    if obj.control_id is None:
        return False
    stmt = (
        select(Evidence.id)
        .join(ControlImplementation, Evidence.implementation_id == ControlImplementation.id)
        .where(
            ControlImplementation.system_id == obj.system_id,
            ControlImplementation.control_id == obj.control_id,
            Evidence.collected_on.is_not(None),
        )
    )
    if obj.identified_on is not None:
        stmt = stmt.where(Evidence.collected_on >= obj.identified_on)
    stmt = stmt.limit(1)
    return (await session.execute(stmt)).scalar_one_or_none() is not None


async def _is_approved(session: AsyncSession, entity_type: str, entity_id: int | str) -> bool:
    row = (
        await session.execute(
            select(Approval).where(
                Approval.entity_type == entity_type, Approval.entity_id == str(entity_id)
            )
        )
    ).scalar_one_or_none()
    return row is not None and row.state == "approved"


async def _require_closure_gate(session: AsyncSession, obj: POAM) -> None:
    if not _milestones_satisfy_closure(obj) and not await _has_closure_evidence(session, obj):
        raise HTTPException(
            409,
            "cannot close: requires either all milestones completed or a linked closure "
            "evidence artifact for the remediated control",
        )
    if get_settings().auth_enabled and not await _is_approved(session, "poam", obj.id):
        raise HTTPException(
            409,
            "cannot close: requires an approved review (submit for approval, then have a "
            "different principal approve it — separation of duties)",
        )


# --- risk_accepted gate: a POA&M can be routed to 'risk_accepted' instead of
# remediation-driven 'closed' — a parallel path that, left ungated, let a
# caller bypass the owner+expiry(+approval) discipline risks.py's own
# acceptance gate enforces for an equivalent decision on the Risk register.
# Reuses that same shape here so neither path can under-cut the other. -------


async def _require_risk_accepted_gate(
    session: AsyncSession,
    *,
    owner_user_id: int | None,
    due_on: object,
    poam_id: int | str | None,
) -> None:
    if owner_user_id is None or due_on is None:
        raise HTTPException(
            409,
            "risk_accepted requires an owner (owner_user_id) and an expiration/due_on date",
        )
    if get_settings().auth_enabled and (
        poam_id is None or not await _is_approved(session, "poam", poam_id)
    ):
        raise HTTPException(
            409,
            "risk_accepted requires an approved authorizing-official review (submit for "
            "approval, then have an AO/admin approve it)",
        )


async def _maybe_enqueue_reevaluation(session: AsyncSession, obj: POAM) -> None:
    """Best-effort: enqueue a re-evaluation of the control this POA&M remediated.

    Only assessment-sourced POA&Ms qualify -- see
    ``ccf.assessment.engine.jobs.enqueue_reevaluation`` for the ``source_ref``
    convention this relies on; a scan-sourced or profile-gap POA&M's
    ``source_ref`` never matches it, so this is silently a no-op for those.
    Called only after the closure itself is already committed, so a failure
    here must never surface as a failure of the closure -- the ISSM-08/09
    gate above already did the only thing that must be allowed to block a
    close.

    The enqueue runs inside its own savepoint
    (``async with session.begin_nested()``): ``AsyncSession.rollback()`` is
    NOT savepoint-scoped -- it unwinds the *whole* transaction, which here
    would mean nothing (the closure is already committed by the time this
    runs), but a bare, un-nested write that raised partway through would
    leave the session's transaction poisoned for every query the route still
    has to make afterward (re-fetching ``obj`` for the response). The
    savepoint confines any failure to just this enqueue attempt.
    """
    if not obj.source_ref:
        return
    org_id = (
        await session.execute(select(System.organization_id).where(System.id == obj.system_id))
    ).scalar_one_or_none()
    if org_id is None:
        return
    try:
        async with session.begin_nested():
            job = await engine_jobs.enqueue_reevaluation(
                session, poam_id=obj.id, source_ref=obj.source_ref, organization_id=int(org_id)
            )
        if job is not None:
            await session.commit()
    except Exception as exc:  # the closure itself is already committed
        log.warning("poam.reevaluation_enqueue_failed", poam_id=obj.id, error=str(exc))


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
    states = await entity_states(session, "poam", [p.id for p in rows])
    return [_out(p, today, states.get(str(p.id))) for p in rows]


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
    if data.get("status") == "closed":
        await _require_closure_gate(session, obj)
    elif data.get("status") == "risk_accepted":
        # A brand-new POA&M cannot already carry an approved review — it must
        # be created open, then moved to risk_accepted via PATCH once approved
        # (mirrors create_risk's handling of status="accepted" in risks.py).
        await _require_risk_accepted_gate(
            session, owner_user_id=obj.owner_user_id, due_on=obj.due_on, poam_id=None
        )
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
    state = await entity_state(session, "poam", obj.id)
    return _out(obj, datetime.now(UTC).date(), state)


@router.get("/{pid}")
async def get_poam(
    pid: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    obj = await _require_poam(session, pid, principal)
    state = await entity_state(session, "poam", obj.id)
    return _out(obj, datetime.now(UTC).date(), state)


@router.patch("/{pid}")
async def update_poam(
    pid: int,
    body: POAMUpdate,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    obj = await _require_poam(session, pid, principal)
    data = body.model_dump(exclude_none=True)
    was_closed = obj.status == "closed"
    if data.get("status") == "closed":
        await _require_closure_gate(session, obj)
    elif data.get("status") == "risk_accepted":
        await _require_risk_accepted_gate(
            session,
            owner_user_id=data.get("owner_user_id", obj.owner_user_id),
            due_on=data.get("due_on", obj.due_on),
            poam_id=pid,
        )
    for k, v in data.items():
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
    if data.get("status") == "closed" and not was_closed:
        await _maybe_enqueue_reevaluation(session, obj)
    obj = await _require_poam(session, pid, principal)
    state = await entity_state(session, "poam", obj.id)
    return _out(obj, datetime.now(UTC).date(), state)


@router.post("/{pid}/close")
async def close_poam(
    pid: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    obj = await _require_poam(session, pid, principal)
    was_closed = obj.status == "closed"
    await _require_closure_gate(session, obj)
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
    if not was_closed:
        await _maybe_enqueue_reevaluation(session, obj)
    obj = await _require_poam(session, pid, principal)
    state = await entity_state(session, "poam", obj.id)
    return _out(obj, datetime.now(UTC).date(), state)


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
