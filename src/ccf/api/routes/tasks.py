"""Governance task workflow API — the cross-module work queue."""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...governance import bus
from ...models import Task
from ..auth_deps import get_principal
from ..deps import get_session

router = APIRouter(prefix="/api/tasks", tags=["tasks"])

_OPEN = ("open", "in_progress", "blocked")


class TaskCreate(BaseModel):
    title: str
    description: str | None = None
    kind: str = "general"
    priority: str = "medium"
    assignee_user_id: int | None = None
    system_id: int | None = None
    entity_type: str | None = None
    entity_id: str | None = None
    due_on: date | None = None


class TaskUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    status: str | None = None
    priority: str | None = None
    assignee_user_id: int | None = None
    due_on: date | None = None


def _out(t: Task) -> dict[str, Any]:
    return {
        "id": t.id,
        "title": t.title,
        "description": t.description,
        "kind": t.kind,
        "status": t.status,
        "priority": t.priority,
        "assignee_user_id": t.assignee_user_id,
        "system_id": t.system_id,
        "entity_type": t.entity_type,
        "entity_id": t.entity_id,
        "source": t.source,
        "due_on": t.due_on,
        "created_at": t.created_at,
        "closed_at": t.closed_at,
    }


@router.get("")
async def list_tasks(
    *,
    status: str | None = None,
    assignee_user_id: int | None = None,
    system_id: int | None = None,
    kind: str | None = None,
    open_only: bool = False,
    limit: int = 100,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    stmt = select(Task).order_by(Task.priority.desc(), Task.due_on.nulls_last(), Task.id.desc())
    if principal.org_id is not None:
        stmt = stmt.where(Task.organization_id == principal.org_id)
    if status:
        stmt = stmt.where(Task.status == status)
    if open_only:
        stmt = stmt.where(Task.status.in_(_OPEN))
    if assignee_user_id is not None:
        stmt = stmt.where(Task.assignee_user_id == assignee_user_id)
    if system_id is not None:
        stmt = stmt.where(Task.system_id == system_id)
    if kind:
        stmt = stmt.where(Task.kind == kind)
    rows = (await session.execute(stmt.limit(min(limit, 500)))).scalars().all()
    return [_out(t) for t in rows]


@router.post("", status_code=201)
async def create_task(
    body: TaskCreate,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    t = Task(organization_id=principal.org_id, source="manual", **body.model_dump())
    session.add(t)
    await session.flush()
    await bus.emit(
        session,
        verb="created",
        entity_type="task",
        entity_id=t.id,
        summary=f"Task created: {t.title}",
        org_id=principal.org_id,
        actor=principal.email,
    )
    await session.commit()
    return _out(t)


@router.patch("/{task_id}")
async def update_task(
    task_id: int,
    body: TaskUpdate,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    t = (await session.execute(select(Task).where(Task.id == task_id))).scalar_one_or_none()
    if t is None:
        raise HTTPException(404, "task not found")
    data = body.model_dump(exclude_none=True)
    for k, v in data.items():
        setattr(t, k, v)
    if data.get("status") in ("done", "cancelled") and t.closed_at is None:
        t.closed_at = datetime.now(UTC)
    await bus.emit(
        session,
        verb="updated",
        entity_type="task",
        entity_id=t.id,
        summary=f"Task {t.status}: {t.title}",
        org_id=principal.org_id,
        actor=principal.email,
    )
    await session.commit()
    return _out(t)
