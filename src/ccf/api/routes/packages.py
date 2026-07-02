"""Authorization package provenance, diff, and replay API."""

from __future__ import annotations

from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ...auth import Principal
from ...models import System
from ...models_packages import PACKAGE_KINDS, AuthorizationPackage
from ...packages import service
from ..auth_deps import get_principal
from ..deps import get_session

router = APIRouter(prefix="/api/authorization-packages", tags=["authorization-packages"])


class PackageIn(BaseModel):
    system_id: int
    kind: str = Field("fedramp20x")
    label: str | None = None


def _pkg_out(p: AuthorizationPackage) -> dict[str, Any]:
    return {
        "id": p.id,
        "system_id": p.system_id,
        "kind": p.kind,
        "label": p.label,
        "readiness_pct": p.readiness_pct,
        "fact_count": p.fact_count,
        "created_by": p.created_by,
        "created_at": p.created_at,
        "summary": p.summary,
    }


async def _require_pkg(
    session: AsyncSession, pid: int, principal: Principal
) -> AuthorizationPackage:
    p = await session.get(AuthorizationPackage, pid)
    if p is None or (principal.org_id is not None and p.organization_id != principal.org_id):
        raise HTTPException(404, "authorization package not found")
    return p


@router.get("")
async def list_packages(
    system_id: int | None = None,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    stmt = select(AuthorizationPackage).order_by(AuthorizationPackage.id.desc())
    if principal.org_id is not None:
        stmt = stmt.where(AuthorizationPackage.organization_id == principal.org_id)
    if system_id is not None:
        stmt = stmt.where(AuthorizationPackage.system_id == system_id)
    return [_pkg_out(p) for p in (await session.execute(stmt)).scalars().all()]


@router.post("", status_code=201)
async def create_package(
    body: PackageIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Export (persist) an authorization package: capture facts as provenance."""
    if body.kind not in PACKAGE_KINDS:
        raise HTTPException(422, f"kind must be one of {PACKAGE_KINDS}")
    sysm = await session.get(System, body.system_id)
    if sysm is None or (principal.org_id is not None and sysm.organization_id != principal.org_id):
        raise HTTPException(404, "system not found")
    pkg = await service.create_package(
        session, org_id=principal.org_id, system_id=body.system_id,
        kind=body.kind, label=body.label, created_by=principal.email,
    )
    await session.commit()
    return _pkg_out(pkg)


@router.get("/{pid}")
async def get_package(
    pid: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    return _pkg_out(await _require_pkg(session, pid, principal))


@router.get("/{pid}/provenance")
async def package_provenance(
    pid: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    p = (
        await session.execute(
            select(AuthorizationPackage)
            .options(
                selectinload(AuthorizationPackage.facts),
                selectinload(AuthorizationPackage.artifacts),
            )
            .where(AuthorizationPackage.id == pid)
        )
    ).scalar_one_or_none()
    if p is None or (principal.org_id is not None and p.organization_id != principal.org_id):
        raise HTTPException(404, "authorization package not found")
    return {
        **_pkg_out(p),
        "facts": [
            {"fact_type": f.fact_type, "fact_key": f.fact_key, "value": f.value,
             "digest": f.digest, "metadata": f.fact_metadata}
            for f in p.facts
        ],
        "artifacts": [
            {"artifact_kind": a.artifact_kind, "sha256": a.sha256,
             "media_type": a.media_type, "size_bytes": a.size_bytes}
            for a in p.artifacts
        ],
    }


@router.get("/{pid}/diff/{other_id}")
async def diff_package(
    pid: int,
    other_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    await _require_pkg(session, pid, principal)
    await _require_pkg(session, other_id, principal)
    diff = await service.diff_packages(
        session, org_id=principal.org_id, from_id=pid, to_id=other_id
    )
    await session.commit()
    return {
        "from_package_id": pid, "to_package_id": other_id,
        "summary": diff.summary, "changes": diff.changes,
    }


@router.post("/{pid}/replay")
async def replay_package(
    pid: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Re-derive the package's facts from the live DB and report drift (read-only)."""
    p = await _require_pkg(session, pid, principal)
    run = await service.replay_package(session, org_id=principal.org_id, package=p)
    await session.commit()
    return {"package_id": pid, "status": run.status, "drift": run.drift}


# --- FedRAMP 20x authorization delta (mounted on the fedramp path) -----------
delta_router = APIRouter(prefix="/api/fedramp/20x", tags=["authorization-packages"])


@delta_router.get("/systems/{system_id}/authorization-delta")
async def authorization_delta(
    system_id: int,
    since: date | None = None,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """An assessor-facing delta memo between the two latest packages for a system."""
    sysm = await session.get(System, system_id)
    if sysm is None or (principal.org_id is not None and sysm.organization_id != principal.org_id):
        raise HTTPException(404, "system not found")
    memo = await service.delta_memo(
        session, org_id=principal.org_id, system_id=system_id, since=since
    )
    await session.commit()
    return {
        "system_id": system_id,
        "from_package_id": memo.from_package_id,
        "to_package_id": memo.to_package_id,
        "summary": memo.summary,
        "body": memo.body,
    }
