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
from ...config import get_settings
from ...governance import bus
from ...governance.approvals import entity_state, entity_states
from ...governance.risk import band, compute_scores
from ...models import Risk, System, Task
from ...models_grc import AuditFinding
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


class RiskFromFindingIn(BaseModel):
    """Optional overrides for the accept-finding -> Risk action; title,
    description, and system_id are always taken from the finding itself so
    the new Risk carries an accurate origin."""

    category: str | None = None
    likelihood: str | None = Field(None, pattern=LEVEL)
    impact: str | None = Field(None, pattern=LEVEL)
    treatment: str | None = Field(None, pattern=TREATMENT)
    owner_user_id: int | None = None
    next_review_on: date | None = None


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


def _out(r: Risk, approval_state: str | None = None) -> dict[str, Any]:
    return {
        "id": r.id,
        "system_id": r.system_id,
        "title": r.title,
        "description": r.description,
        "category": r.category,
        "source": r.source,
        "source_ref": r.source_ref,
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
        # Read-time reflection of the ISSM-08/09 approval workflow (ISSM-07): draft
        # (never submitted) | submitted (pending review) | approved | rejected. This
        # does NOT drive the acceptance gate itself — see _require_acceptance_gate —
        # it only makes the decision visible on the record.
        "approval_state": approval_state,
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


# --- Acceptance gate (ISSM-08/09): a risk can only move to 'accepted' with a
# named owner and an expiration/review date, and — when auth is enabled — with
# an AO-role approval recorded via the existing Approval workflow. -----------


async def _require_acceptance_gate(
    session: AsyncSession, *, owner_user_id: int | None, next_review_on: object, risk_id: int | str
) -> None:
    if owner_user_id is None or next_review_on is None:
        raise HTTPException(
            409,
            "risk acceptance requires an owner (owner_user_id) and an expiration/"
            "next_review_on date",
        )
    if get_settings().auth_enabled and await entity_state(session, "risk", risk_id) != "approved":
        raise HTTPException(
            409,
            "risk acceptance requires an approved authorizing-official review (submit for "
            "approval, then have an AO/admin approve it)",
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
    states = await entity_states(session, "risk", [r.id for r in rows])
    return [_out(r, states.get(str(r.id))) for r in rows]


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
    top_rows = sorted(rows, key=lambda x: x.residual_score or 0, reverse=True)[:10]
    top_states = await entity_states(session, "risk", [r.id for r in top_rows])
    return {
        "open_total": len(rows),
        "matrix": matrix,
        "by_residual_band": by_band,
        "top": [_out(r, top_states.get(str(r.id))) for r in top_rows],
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
    data = body.model_dump(exclude_none=True)
    if data.get("status") == "accepted":
        if data.get("owner_user_id") is None or data.get("next_review_on") is None:
            raise HTTPException(
                409,
                "risk acceptance requires an owner (owner_user_id) and an expiration/"
                "next_review_on date",
            )
        if get_settings().auth_enabled:
            # A brand-new risk cannot already carry an approved SoD review — it
            # must be created open, then accepted via PATCH after submit/approve.
            raise HTTPException(
                409,
                "risk acceptance requires an approved authorizing-official review; create "
                "the risk first, then accept it once approved",
            )
    obj = Risk(**data)
    _rescore(obj)
    session.add(obj)
    await session.flush()
    await _post_write(session, obj, principal, verb="created")
    await session.commit()
    await session.refresh(obj)
    state = await entity_state(session, "risk", obj.id)
    return _out(obj, state)


@router.patch("/{rid}")
async def update_risk(
    rid: int,
    body: RiskUpdate,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    obj = await _require_risk(session, rid, principal)
    data = body.model_dump(exclude_none=True)
    if data.get("status") == "accepted":
        await _require_acceptance_gate(
            session,
            owner_user_id=data.get("owner_user_id", obj.owner_user_id),
            next_review_on=data.get("next_review_on", obj.next_review_on),
            risk_id=rid,
        )
    for k, v in data.items():
        setattr(obj, k, v)
    _rescore(obj)
    await session.flush()
    await _post_write(session, obj, principal, verb="updated")
    await session.commit()
    await session.refresh(obj)
    state = await entity_state(session, "risk", obj.id)
    return _out(obj, state)


@router.get("/{rid}")
async def get_risk(
    rid: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    obj = await _require_risk(session, rid, principal)
    state = await entity_state(session, "risk", obj.id)
    return _out(obj, state)


@router.post("/from-finding/{finding_id}", status_code=201)
async def create_risk_from_finding(
    finding_id: int,
    body: RiskFromFindingIn | None = None,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """ISSM-05: accept-finding -> Risk. Opens a Risk carrying the finding's
    origin (``source_ref``) so it is traceable back to what generated it. The
    Risk is created ``open`` — moving it to ``accepted`` still goes through
    the normal PATCH acceptance gate above (owner + expiry, + AO approval when
    auth is enabled). Idempotent on the finding: one already accepted to a
    Risk returns the existing Risk rather than creating a duplicate.
    """
    finding = await session.get(AuditFinding, finding_id)
    if finding is None or (
        principal.org_id is not None
        and finding.organization_id is not None
        and finding.organization_id != principal.org_id
    ):
        raise HTTPException(404, "audit finding not found")
    if finding.risk_id is not None:
        existing = await session.get(Risk, finding.risk_id)
        if existing is not None:
            state = await entity_state(session, "risk", existing.id)
            return _out(existing, state)
    if finding.system_id is None:
        raise HTTPException(
            400, "audit finding has no system_id set; set one before accepting to a risk"
        )
    if principal.org_id is not None:
        ok = (
            await session.execute(
                select(System.id).where(
                    System.id == finding.system_id, System.organization_id == principal.org_id
                )
            )
        ).scalar_one_or_none()
        if ok is None:
            raise HTTPException(404, "system not found")
    data = (body or RiskFromFindingIn()).model_dump(exclude_none=True)
    obj = Risk(
        system_id=finding.system_id,
        title=f"Audit finding: {finding.title}",
        description=finding.description,
        source="audit_finding",
        source_ref=f"audit_finding:{finding.id}",
        **data,
    )
    _rescore(obj)
    session.add(obj)
    await session.flush()
    finding.risk_id = obj.id
    await _post_write(session, obj, principal, verb="created")
    await session.commit()
    await session.refresh(obj)
    state = await entity_state(session, "risk", obj.id)
    return _out(obj, state)
