"""Concord-on-Concord self-assurance API (admin)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...self_assurance import (
    export_package,
    init_self_assurance,
    run_self_assessment,
    status,
)
from ..auth_deps import require_role
from ..deps import get_session

router = APIRouter(prefix="/api/admin/self-assurance", tags=["self-assurance"])


@router.post("/init")
async def init_endpoint(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> dict[str, Any]:
    out = await init_self_assurance(session, actor=principal.email)
    await session.commit()
    return out


@router.post("/run")
async def run_endpoint(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> dict[str, Any]:
    run = await run_self_assessment(session, actor=principal.email)
    await session.commit()
    return {"run_id": run.id, "readiness_pct": run.readiness_pct,
            "checks_total": run.checks_total, "checks_passed": run.checks_passed,
            "control_status": (run.summary or {}).get("control_status", {})}


@router.get("/status")
async def status_endpoint(
    session: AsyncSession = Depends(get_session),
    _principal: Principal = Depends(require_role("admin")),
) -> dict[str, Any]:
    return await status(session)


@router.get("/package")
async def package_endpoint(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> dict[str, Any]:
    out = await export_package(session, actor=principal.email)
    await session.commit()
    return out
