"""Activity feed + outbound webhook management — the integration surface."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...models import Event, Webhook
from ..auth_deps import get_principal
from ..deps import get_session

router = APIRouter(prefix="/api", tags=["events"])


class WebhookIn(BaseModel):
    url: str
    secret: str | None = None
    events: list[str] = []
    active: bool = True


@router.get("/events")
async def list_events(
    entity_type: str | None = None,
    limit: int = 100,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    """The activity feed — every emitted event, newest first."""
    stmt = select(Event).order_by(Event.id.desc()).limit(min(limit, 500))
    if principal.org_id is not None:
        stmt = stmt.where(Event.organization_id == principal.org_id)
    if entity_type:
        stmt = stmt.where(Event.entity_type == entity_type)
    rows = (await session.execute(stmt)).scalars().all()
    return [
        {
            "id": e.id,
            "actor": e.actor,
            "verb": e.verb,
            "entity_type": e.entity_type,
            "entity_id": e.entity_id,
            "summary": e.summary,
            "created_at": e.created_at,
        }
        for e in rows
    ]


@router.get("/webhooks")
async def list_webhooks(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    stmt = select(Webhook)
    if principal.org_id is not None:
        stmt = stmt.where(Webhook.organization_id == principal.org_id)
    rows = (await session.execute(stmt)).scalars().all()
    return [
        {"id": w.id, "url": w.url, "events": list(w.events or []), "active": w.active} for w in rows
    ]


@router.post("/webhooks", status_code=201)
async def create_webhook(
    body: WebhookIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    w = Webhook(organization_id=principal.org_id, **body.model_dump())
    session.add(w)
    await session.commit()
    return {"id": w.id, "url": w.url, "active": w.active}


@router.delete("/webhooks/{webhook_id}", status_code=204)
async def delete_webhook(
    webhook_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> None:
    w = (
        await session.execute(select(Webhook).where(Webhook.id == webhook_id))
    ).scalar_one_or_none()
    if w is None:
        raise HTTPException(404, "webhook not found")
    await session.delete(w)
    await session.commit()
