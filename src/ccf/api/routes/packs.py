"""Compliance pack runtime API — list, validate, install, upgrade, coverage, test."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...models import System
from ...models_packs import CompliancePack
from ...packs import catalog
from ...packs import service as pack_service
from ..auth_deps import get_principal
from ..deps import get_session

router = APIRouter(prefix="/api/packs", tags=["packs"])


class InstallIn(BaseModel):
    pack_id: str | None = None  # bundled/override id or filesystem path
    manifest: dict[str, Any] | None = None


def _pack_out(p: CompliancePack) -> dict[str, Any]:
    return {
        "id": p.id, "pack_key": p.pack_key, "name": p.name, "version": p.version,
        "schema_version": p.schema_version, "status": p.status, "source": p.source,
        "manifest_sha": p.manifest_sha, "installed_at": p.installed_at,
        "control_count": len((p.manifest or {}).get("controls", [])),
    }


async def _require(session: AsyncSession, key: str, principal: Principal) -> CompliancePack:
    stmt = select(CompliancePack).where(CompliancePack.pack_key == key)
    if principal.org_id is not None:
        stmt = stmt.where(CompliancePack.organization_id == principal.org_id)
    p = (await session.execute(stmt)).scalars().first()
    if p is None:
        raise HTTPException(404, "installed pack not found")
    return p


@router.get("")
async def list_packs(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    stmt = select(CompliancePack).order_by(CompliancePack.pack_key)
    if principal.org_id is not None:
        stmt = stmt.where(CompliancePack.organization_id == principal.org_id)
    installed = [_pack_out(p) for p in (await session.execute(stmt)).scalars().all()]
    return {"available": catalog.list_available(), "installed": installed}


@router.post("/validate")
async def validate(
    body: dict[str, Any],
    _principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    errors = catalog.validate_manifest(body)
    return {"valid": not errors, "errors": errors}


@router.post("/install", status_code=201)
async def install(
    body: InstallIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    if body.manifest is not None:
        manifest = body.manifest
        source = "api"
    elif body.pack_id:
        try:
            manifest = catalog.load_pack(body.pack_id)
        except FileNotFoundError as e:
            raise HTTPException(404, str(e)) from e
        source = body.pack_id
    else:
        raise HTTPException(422, "provide pack_id or manifest")
    try:
        pack = await pack_service.install_pack(
            session, org_id=principal.org_id, manifest=manifest, source=source,
            actor=principal.email,
        )
    except pack_service.PackError as e:
        raise HTTPException(422, str(e)) from e
    await session.commit()
    return _pack_out(pack)


@router.get("/{pack_key}")
async def get_pack(
    pack_key: str,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    p = await _require(session, pack_key, principal)
    return {**_pack_out(p), "manifest": p.manifest}


@router.post("/{pack_key}/upgrade")
async def upgrade(
    pack_key: str,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    await _require(session, pack_key, principal)
    try:
        manifest = catalog.load_pack(pack_key)
    except FileNotFoundError as e:
        raise HTTPException(404, str(e)) from e
    pack = await pack_service.install_pack(
        session, org_id=principal.org_id, manifest=manifest, source=pack_key,
        actor=principal.email,
    )
    await session.commit()
    return _pack_out(pack)


@router.get("/{pack_key}/coverage")
async def coverage(
    pack_key: str,
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    p = await _require(session, pack_key, principal)
    sysm = await session.get(System, system_id)
    if sysm is None or (principal.org_id is not None and sysm.organization_id != principal.org_id):
        raise HTTPException(404, "system not found")
    return await pack_service.coverage(session, pack=p, system_id=system_id)


@router.post("/{pack_key}/test")
async def test_pack(
    pack_key: str,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    p = await _require(session, pack_key, principal)
    results = await pack_service.run_tests(session, p)
    await session.commit()
    return {
        "pack_key": pack_key,
        "results": [{"test_key": r.test_key, "status": r.status, "detail": r.detail}
                    for r in results],
        "passed": sum(1 for r in results if r.status == "pass"),
        "failed": sum(1 for r in results if r.status == "fail"),
    }
