"""Health / readiness endpoints.

``/healthz`` is a liveness probe: cheap, unconditional, no dependency on the
reliability suite (a failing blocking check must never restart-loop the
container — that's what ``/readyz`` pulling it from rotation is for).

``/readyz`` is a readiness probe: it runs the *blocking* subset of the
reliability checks (``ccf.reliability.checks.BLOCKING_CHECKS`` — DB
connectivity, migration status, required tables, auth posture, tenant/RLS
boundary integrity) and returns 503 naming any FAILing check, so an unsafe
container is kept out of rotation instead of serving traffic.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from ...reliability.checks import FAIL, run_blocking_checks
from ..deps import get_session

router = APIRouter(tags=["health"])


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz")
async def readyz(session: AsyncSession = Depends(get_session)) -> JSONResponse:
    # database_connectivity is the first blocking check, so this alone covers
    # the old "SELECT 1" behavior — no separate round trip needed.
    checks = await run_blocking_checks(session)
    failing = [c.name for c in checks if c.status == FAIL]
    body = {
        "status": "ready" if not failing else "not_ready",
        "failing_checks": failing,
        "checks": [c.as_dict() for c in checks],
    }
    return JSONResponse(body, status_code=503 if failing else 200)
