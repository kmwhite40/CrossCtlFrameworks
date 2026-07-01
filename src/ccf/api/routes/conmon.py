"""Continuous monitoring API — control health + scan-driven work generation."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...governance import conmon
from ...models import MonitoringRun
from ..auth_deps import get_principal
from ..deps import get_session

router = APIRouter(prefix="/api/conmon", tags=["conmon"])


def _today() -> Any:
    return datetime.now(UTC).date()


@router.get("/health")
async def health(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Live control-health rollup with the list of controls needing attention."""
    return await conmon.health_summary(session, today=_today(), org_id=principal.org_id)


@router.post("/scan")
async def scan(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Run a monitoring scan: generate tasks + notifications for unhealthy controls."""
    result = await conmon.scan(session, today=_today(), org_id=principal.org_id)
    await session.commit()
    return result


@router.get("/runs")
async def runs(
    limit: int = 20,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    """Recent monitoring runs."""
    stmt = select(MonitoringRun).order_by(MonitoringRun.id.desc()).limit(min(limit, 100))
    if principal.org_id is not None:
        stmt = stmt.where(MonitoringRun.organization_id == principal.org_id)
    rows = (await session.execute(stmt)).scalars().all()
    return [
        {
            "id": r.id,
            "started_at": r.started_at,
            "controls_checked": r.controls_checked,
            "findings": r.findings,
            "tasks_created": r.tasks_created,
            "notifications_created": r.notifications_created,
            "summary": r.summary,
        }
        for r in rows
    ]
