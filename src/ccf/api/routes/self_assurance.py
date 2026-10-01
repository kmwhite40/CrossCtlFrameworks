"""Concord-on-Concord self-assurance API (admin).

Every endpoint here acts on **Concord's own** assurance boundary, not on the
caller's tenant, so all four require a platform administrator rather than a
tenant admin. `require_role("admin")` was the wrong gate: it admits any
customer's administrator, and a tenant-scoped session cannot read or write
platform-owned rows anyway -- RLS hides them, so a lookup came back empty, the
service tried to create what already existed, and the policy refused the insert.
The caller got a 500 where the honest answer was "not yours to ask".
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...self_assurance import (
    SelfAssuranceNotInitialisedError,
    export_package,
    init_self_assurance,
    run_self_assessment,
    status,
)
from ..auth_deps import require_platform_admin
from ..deps import get_session

router = APIRouter(prefix="/api/admin/self-assurance", tags=["self-assurance"])


@router.post("/init")
async def init_endpoint(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_platform_admin()),
) -> dict[str, Any]:
    out = await init_self_assurance(session, actor=principal.email)
    await session.commit()
    return out


@router.post("/run")
async def run_endpoint(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_platform_admin()),
) -> dict[str, Any]:
    try:
        run = await run_self_assessment(session, actor=principal.email)
    except SelfAssuranceNotInitialisedError as exc:
        raise HTTPException(409, str(exc)) from exc
    await session.commit()
    return {"run_id": run.id, "readiness_pct": run.readiness_pct,
            "checks_total": run.checks_total, "checks_passed": run.checks_passed,
            "control_status": (run.summary or {}).get("control_status", {})}


@router.get("/status")
async def status_endpoint(
    session: AsyncSession = Depends(get_session),
    _principal: Principal = Depends(require_platform_admin()),
) -> dict[str, Any]:
    return await status(session)


@router.get("/package")
async def package_endpoint(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_platform_admin()),
) -> dict[str, Any]:
    # A 409 rather than seeding on demand: creating the boundary is `init`'s job,
    # and this is served from a GET. It used to create an organization and a
    # system as a side effect of being read.
    try:
        out = await export_package(session, actor=principal.email)
    except SelfAssuranceNotInitialisedError as exc:
        raise HTTPException(409, str(exc)) from exc
    await session.commit()
    return out
