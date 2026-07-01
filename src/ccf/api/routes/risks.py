"""Risk register — quantitative scoring, cross-links, heatmap, and workflow.

Beyond CRUD: create/update recomputes an inherent (likelihood x impact, 1-25)
and treatment-discounted residual score, emits an event, raises a critical alert
for high residual exposure, and opens a mitigation task when the treatment is
"mitigate". A heatmap endpoint powers the 5x5 register view.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...governance import bus
from ...governance.risk import band, compute_scores
from ...models import Risk, System, Task
from ..auth_deps import get_principal, org_systems_subq
from ..deps import get_session

router = APIRouter(prefix="/api/risks", tags=["risks"])

LEVEL = r"^(low|moderate|high)$"
TREATMENT = r"^(mitigate|transfer|accept|avoid)$"
STATUS = r"^(open|mitigated|accepted|closed)$"
HIGH_RESIDUAL = 15  # >= this residual score raises a critical alert


class RiskCreate(BaseModel):
    title: str
    system_id: int | None = None
    description: str | None = None
    category: str | None = None
    source: str | None = None
    likelihood: str | None = Field(None, pattern=LEVEL)
    impact: str | None = Field(None, pattern=LEVEL)
    treatment: str | None = Field(None, pattern=TREATMENT)
    status: str = Field("open", pattern=STATUS)
    owner_user_id: int | None = None
    next_review_on: date | None = None
    control_id: int | None = None
    vendor_id: int | None = None


class RiskUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    category: str | None = None
    source: str | None = None
    likelihood: str | None = Field(None, pattern=LEVEL)
    impact: str | None = Field(None, pattern=LEVEL)
    treatment: str | None = Field(None, pattern=TREATMENT)
    status: str | None = Field(None, pattern=STATUS)
    owner_user_id: int | None = None
    next_review_on: date | None = None
    control_id: int | None = None
    vendor_id: int | None = None


def _out(r: Risk) -> dict[str, Any]:
    return {
        "id": r.id,
        "system_id": r.system_id,
        "title": r.title,
        "description": r.description,
        "category": r.category,
        "source": r.source,
        "likelihood": r.likelihood,
        "impact": r.impact,
        "treatment": r.treatment,
        "status": r.status,
        "inherent_score": r.inherent_score,
        "residual_score": r.residual_score,
        "residual_band": band(r.residual_score),
        "owner_user_id": r.owner_user_id,
        "next_review_on": r.next_review_on,
        "control_id": r.control_id,
        "vendor_id": r.vendor_id,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


async def _require_risk(session: AsyncSession, rid: int, principal: Principal) -> Risk:
    obj = (await session.execute(select(Risk).where(Risk.id == rid))).scalar_one_or_none()
    if obj is None:
        raise HTTPException(404, "risk not found")
    if principal.org_id is not None and obj.system_id is not None:
        ok = (
            await session.execute(
                select(System.id).where(
                    System.id == obj.system_id, System.organization_id == principal.org_id
                )
            )
        ).scalar_one_or_none()
        if ok is None:
            raise HTTPException(404, "risk not found")
    return obj


def _rescore(obj: Risk) -> None:
    obj.inherent_score, obj.residual_score = compute_scores(
        obj.likelihood, obj.impact, obj.treatment
    )


async def _post_write(session: AsyncSession, obj: Risk, principal: Principal, *, verb: str) -> None:
    """Emit an event, alert on high residual, and open a mitigation task."""
    await bus.emit(
        session,
        verb=verb,
        entity_type="risk",
        entity_id=obj.id,
        summary=f"Risk {verb}: {obj.title} (residual {obj.residual_score or '?'})",
        org_id=principal.org_id,
        actor=principal.email,
    )
    if (
        obj.residual_score is not None
        and obj.residual_score >= HIGH_RESIDUAL
        and obj.status not in ("closed", "accepted")
    ):
        await bus.notify(
            session,
            category="risk",
            title=f"High residual risk: {obj.title}",
            body=f"Residual exposure {obj.residual_score}/25 ({band(obj.residual_score)}).",
            org_id=principal.org_id,
            severity="critical",
            entity_type="risk",
            entity_id=obj.id,
            dedupe_key=f"risk-high:{obj.id}",
        )
    if obj.treatment == "mitigate" and obj.status == "open":
        dedupe = f"risk-mitigate:{obj.id}"
        exists = (
            await session.execute(select(Task).where(Task.dedupe_key == dedupe))
        ).scalar_one_or_none()
        if exists is None:
            session.add(
                Task(
                    organization_id=principal.org_id,
                    system_id=obj.system_id,
                    title=f"Mitigate risk: {obj.title}",
                    description=obj.description,
                    kind="remediation",
                    priority="high" if (obj.residual_score or 0) >= HIGH_RESIDUAL else "medium",
                    status="open",
                    source="auto",
                    entity_type="risk",
                    entity_id=str(obj.id),
                    dedupe_key=dedupe,
                    due_on=obj.next_review_on,
                )
            )


@router.get("")
async def list_risks(
    session: AsyncSession = Depends(get_session),
    system_id: int | None = None,
    status: str | None = None,
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    stmt = select(Risk).order_by(Risk.residual_score.desc().nulls_last(), Risk.created_at.desc())
    if principal.org_id is not None:
        stmt = stmt.where(Risk.system_id.in_(org_systems_subq(principal)))
    if system_id is not None:
        stmt = stmt.where(Risk.system_id == system_id)
    if status:
        stmt = stmt.where(Risk.status == status)
    rows = (await session.execute(stmt)).scalars().all()
    return [_out(r) for r in rows]


@router.get("/heatmap")
async def heatmap(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """5x5 likelihood x impact matrix + register rollup for open risks."""
    stmt = select(Risk).where(Risk.status.in_(("open", "mitigated")))
    if principal.org_id is not None:
        stmt = stmt.where(Risk.system_id.in_(org_systems_subq(principal)))
    rows = (await session.execute(stmt)).scalars().all()
    levels = ["low", "moderate", "high"]
    matrix = {lk: {im: 0 for im in levels} for lk in levels}
    by_band = {"low": 0, "moderate": 0, "high": 0, "critical": 0, "unknown": 0}
    for r in rows:
        if r.likelihood in matrix and r.impact in levels:
            matrix[r.likelihood][r.impact] += 1
        by_band[band(r.residual_score)] += 1
    return {
        "open_total": len(rows),
        "matrix": matrix,
        "by_residual_band": by_band,
        "top": [
            _out(r) for r in sorted(rows, key=lambda x: x.residual_score or 0, reverse=True)[:10]
        ],
    }


@router.post("", status_code=201)
async def create_risk(
    body: RiskCreate,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    if principal.org_id is not None and body.system_id is not None:
        ok = (
            await session.execute(
                select(System.id).where(
                    System.id == body.system_id, System.organization_id == principal.org_id
                )
            )
        ).scalar_one_or_none()
        if ok is None:
            raise HTTPException(404, "system not found")
    obj = Risk(**body.model_dump(exclude_none=True))
    _rescore(obj)
    session.add(obj)
    await session.flush()
    await _post_write(session, obj, principal, verb="created")
    await session.commit()
    await session.refresh(obj)
    return _out(obj)


@router.patch("/{rid}")
async def update_risk(
    rid: int,
    body: RiskUpdate,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    obj = await _require_risk(session, rid, principal)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(obj, k, v)
    _rescore(obj)
    await session.flush()
    await _post_write(session, obj, principal, verb="updated")
    await session.commit()
    await session.refresh(obj)
    return _out(obj)


@router.get("/{rid}")
async def get_risk(
    rid: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    return _out(await _require_risk(session, rid, principal))
