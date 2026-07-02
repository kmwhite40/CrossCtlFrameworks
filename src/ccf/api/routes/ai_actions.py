"""Typed AI GRC action API — run, review-queue, approve/reject, guardrails."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ...ai_actions import ACTIONS, run_action, service
from ...auth import Principal
from ...models_ai_actions import AiActionRun, AiGuardrailViolation
from ..auth_deps import get_principal
from ..deps import get_session

router = APIRouter(prefix="/api/ai-actions", tags=["ai-actions"])


class RunIn(BaseModel):
    entity_type: str
    entity_id: str


class ReviewIn(BaseModel):
    note: str | None = None


def _action_out(key: str) -> dict[str, Any]:
    a = ACTIONS[key]
    return {
        "key": a.key, "title": a.title, "description": a.description,
        "input_entity_types": list(a.input_entity_types),
        "requires_approval": a.requires_approval, "citation_required": a.citation_required,
        "allowed_mutation": a.allowed_mutation, "guardrails": list(a.guardrails),
    }


def _run_out(run: AiActionRun, *, detail: bool = False) -> dict[str, Any]:
    out = {
        "id": run.id, "action_key": run.action_key, "entity_type": run.entity_type,
        "entity_id": run.entity_id, "status": run.status, "provider": run.provider,
        "input_hash": run.input_hash, "output_hash": run.output_hash,
        "mutation_applied": run.mutation_applied, "reviewer": run.reviewer,
        "disposition": run.disposition, "summary": run.summary, "created_at": run.created_at,
    }
    if detail:
        out["outputs"] = [
            {"content": o.content, "uncited": o.uncited, "payload": o.payload}
            for o in (run.outputs or [])
        ]
        out["citations"] = [
            {"source_type": c.source_type, "source_id": c.source_id, "label": c.label}
            for c in (run.citations or [])
        ]
    return out


@router.get("")
async def list_actions(_principal: Principal = Depends(get_principal)) -> list[dict[str, Any]]:
    return [_action_out(k) for k in ACTIONS]


@router.get("/review-queue")
async def review_queue(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    stmt = (
        select(AiActionRun)
        .where(AiActionRun.status == "pending_review")
        .order_by(AiActionRun.id.desc())
    )
    if principal.org_id is not None:
        stmt = stmt.where(AiActionRun.organization_id == principal.org_id)
    return [_run_out(r) for r in (await session.execute(stmt)).scalars().all()]


@router.get("/guardrail-violations")
async def guardrail_violations(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    stmt = select(AiGuardrailViolation).order_by(AiGuardrailViolation.id.desc())
    if principal.org_id is not None:
        stmt = stmt.where(AiGuardrailViolation.organization_id == principal.org_id)
    return [
        {"id": v.id, "run_id": v.run_id, "kind": v.kind, "detail": v.detail,
         "created_at": v.created_at}
        for v in (await session.execute(stmt)).scalars().all()
    ]


@router.get("/runs")
async def list_runs(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    stmt = select(AiActionRun).order_by(AiActionRun.id.desc()).limit(200)
    if principal.org_id is not None:
        stmt = stmt.where(AiActionRun.organization_id == principal.org_id)
    return [_run_out(r) for r in (await session.execute(stmt)).scalars().all()]


@router.get("/{action_key}")
async def get_action_def(
    action_key: str, _principal: Principal = Depends(get_principal)
) -> dict[str, Any]:
    if action_key not in ACTIONS:
        raise HTTPException(404, "unknown action")
    return _action_out(action_key)


async def _require_run(session: AsyncSession, rid: int, principal: Principal) -> AiActionRun:
    run = (
        await session.execute(
            select(AiActionRun)
            .options(selectinload(AiActionRun.outputs), selectinload(AiActionRun.citations))
            .where(AiActionRun.id == rid)
        )
    ).scalar_one_or_none()
    if run is None or (principal.org_id is not None and run.organization_id != principal.org_id):
        raise HTTPException(404, "run not found")
    return run


@router.post("/{action_key}/run", status_code=201)
async def run(
    action_key: str,
    body: RunIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    try:
        run = await run_action(
            session, action_key=action_key, entity_type=body.entity_type,
            entity_id=body.entity_id, org_id=principal.org_id, actor=principal.email,
        )
    except service.AiActionError as e:
        await session.commit()  # persist any guardrail violation recorded before the raise
        raise HTTPException(422, str(e)) from e
    await session.commit()
    run = await _require_run(session, run.id, principal)
    return _run_out(run, detail=True)


@router.get("/runs/{rid}")
async def get_run(
    rid: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    return _run_out(await _require_run(session, rid, principal), detail=True)


@router.post("/runs/{rid}/approve")
async def approve(
    rid: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    run = await _require_run(session, rid, principal)
    try:
        await service.approve_run(session, run, reviewer=principal.email)
    except service.AiActionError as e:
        await session.commit()
        raise HTTPException(409, str(e)) from e
    await session.commit()
    return _run_out(await _require_run(session, rid, principal), detail=True)


@router.post("/runs/{rid}/reject")
async def reject(
    rid: int,
    body: ReviewIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    run = await _require_run(session, rid, principal)
    try:
        await service.reject_run(session, run, reviewer=principal.email, note=body.note)
    except service.AiActionError as e:
        raise HTTPException(409, str(e)) from e
    await session.commit()
    return _run_out(await _require_run(session, rid, principal), detail=True)
