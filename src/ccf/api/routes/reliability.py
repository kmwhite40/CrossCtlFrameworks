"""Admin reliability / operational-readiness endpoint."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...reliability import run_checks, summarize
from ..auth_deps import require_role
from ..deps import get_session

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.get("/reliability")
async def reliability(
    session: AsyncSession = Depends(get_session),
    _p: Principal = Depends(require_role("admin", "platform_admin")),
) -> Any:
    checks = await run_checks(session)
    summary = summarize(checks)
    # 200 when healthy/degraded, 503 when any check fails — friendly to probes.
    status_code = 503 if summary["overall"] == "fail" else 200
    return JSONResponse(summary, status_code=status_code)
