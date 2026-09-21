"""Compliance pack runtime API — list, validate, install, upgrade, coverage, test."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...models import System
from ...models_packs import CompliancePack, CompliancePackVersion, PackSource
from ...packs import catalog
from ...packs import service as pack_service
from ...packs.diff import diff_posture_rules
from ...packs.impact import build_config_change_impact
from ...packs.sync import (
    PackSourceRejectedError,
    adopt_pending,
    check_pack_source,
    divergence,
    validate_pack_source_url,
)
from ..audit import record_event
from ..auth_deps import get_principal, require_role
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
    # A pack's rules become executable posture checks -- their verdicts feed
    # directly into control tests and, per CRITICAL 2/3 above, into what an
    # assessor sees for a control. That is administrative write access, the
    # same tier as connector credential config (api.routes.connector_settings)
    # and catalog admin actions (api.routes.catalog): "admin" is the role this
    # repo already uses for those, not the broader "admin"+"assessor" pairing
    # used for read/assess-oriented writes elsewhere (e.g. boundary, audit).
    principal: Principal = Depends(require_role("admin")),
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


async def _version_row(
    session: AsyncSession, pack_id: int, version: str
) -> CompliancePackVersion:
    row = (
        await session.execute(
            select(CompliancePackVersion)
            .where(
                CompliancePackVersion.pack_id == pack_id,
                CompliancePackVersion.version == version,
            )
            .order_by(CompliancePackVersion.id.desc())
        )
    ).scalars().first()
    if row is None:
        raise HTTPException(404, f"pack has no installed version {version!r}")
    return row


@router.get("/{pack_key}/impact")
async def pack_impact(
    pack_key: str,
    from_version: str | None = None,
    to_version: str | None = None,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """What adopting a desired-state change would affect in this deployment.

    Defaults to the two most recently installed versions, which is the question
    an operator has just after an upgrade: "what did that change?". Read-only --
    it computes for review and applies nothing.

    A pack with only one installed version is a 409 rather than an empty
    impact: having nothing to compare against is not the same as a change with
    no consequences, and reporting the two identically would hide the
    difference.
    """
    pack = await _require(session, pack_key, principal)
    versions = (
        await session.execute(
            select(CompliancePackVersion)
            .where(CompliancePackVersion.pack_id == pack.id)
            .order_by(CompliancePackVersion.id.desc())
        )
    ).scalars().all()
    if from_version is None and to_version is None:
        if len(versions) < 2:
            raise HTTPException(
                409,
                "pack has only one version installed; there is nothing to compare it against",
            )
        newer, older = versions[0], versions[1]
    else:
        if from_version is None or to_version is None:
            raise HTTPException(400, "supply both from_version and to_version, or neither")
        older = await _version_row(session, pack.id, from_version)
        newer = await _version_row(session, pack.id, to_version)

    diff = diff_posture_rules(older.manifest, newer.manifest)
    impact = await build_config_change_impact(
        session, org_id=pack.organization_id, pack_key=pack.pack_key, diff=diff
    )
    return {
        "pack_key": pack.pack_key,
        "from_version": older.version,
        "to_version": newer.version,
        "diff": diff.as_dict(),
        "impact": impact.to_dict(),
    }


class PackSourceIn(BaseModel):
    url: str
    ref: str | None = None
    auto_install: bool = False


#: Roles that may adopt a fetched change. The same gate waivers use, for the
#: same reason: this is the act that changes what the platform asserts.
#:
#: It says ``("admin",)`` because that is what it always *meant*: ``issm`` and
#: ``isso`` are not members of the ``user_role`` enum backing ``User.role``, so
#: no real user could ever hold one and this tuple has only ever matched
#: ``admin``. Naming them made the gate read broader than it was and made a 403
#: quote roles nobody can be granted. ``control_owner`` is deliberately still
#: out: adoption is the separation-of-duties act waivers keeps to
#: ``APPROVER_ROLES = ("admin",)``, and the control owner is the party whose own
#: posture the adopted content re-asserts.
ADOPTER_ROLES = ("admin",)

#: Its own router: these paths are addressed by source id, not pack key, so
#: they do not sit under the /api/packs/{pack_key} prefix. Two routers in one
#: module follows the precedent in api/routes/posture.py.
source_router = APIRouter(prefix="/api/pack-sources", tags=["packs"])


def _public_error(status: str | None, error: str | None) -> str | None:
    """``last_error``, scrubbed of anything usable as a file-existence or
    internal-port oracle.

    A transport failure's exception text differs by what sits on the other
    end of a poll -- ``FileNotFoundError`` vs. ``PermissionError`` vs.
    connection-refused vs. timeout -- which is exactly the signal CRITICAL 1
    (PR #17 security review) warned turns ``/sync`` and this endpoint into an
    oracle for probing the filesystem and internal network. Only ``error``
    (a transport failure) is scrubbed; ``invalid`` (a bad URL shape, an
    oversized body, or a manifest that fails validation) describes a content
    or config problem in the source itself, not what the fetch touched, so it
    stays verbatim -- an operator needs it to fix their repository. The
    unscrubbed detail is still in ``source.last_error`` and the server log.
    """
    if error is None:
        return None
    if status == "error":
        return "fetch failed; see server logs for detail"
    return error


def _source_out(s: PackSource) -> dict[str, Any]:
    return {
        "id": s.id,
        "pack_key": s.pack_key,
        "url": s.url,
        "ref": s.ref,
        "enabled": s.enabled,
        "auto_install": s.auto_install,
        "last_status": s.last_status,
        "last_error": _public_error(s.last_status, s.last_error),
        "last_checked_at": s.last_checked_at,
        "last_commit_sha": s.last_commit_sha,
        "consecutive_failures": s.consecutive_failures,
        "pending": bool(s.pending_manifest),
        "pending_version": str(s.pending_manifest.get("version", "")) or None,
        "pending_commit_sha": s.pending_commit_sha,
    }


async def _require_source(
    session: AsyncSession, source_id: int, principal: Principal
) -> PackSource:
    """One source, or 404 -- including another tenant's.

    404 rather than 403: confirming an id exists is itself a disclosure.
    """
    s = (
        await session.execute(select(PackSource).where(PackSource.id == source_id))
    ).scalars().first()
    if s is None or (
        principal.org_id is not None and s.organization_id != principal.org_id
    ):
        raise HTTPException(404, "pack source not found")
    return s


@router.post("/{pack_key}/sources", status_code=201)
async def register_source(
    pack_key: str,
    body: PackSourceIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Register a repository that declares this pack's desired state.

    Polling it is automatic from here; installing what it declares is not,
    unless ``auto_install`` is set -- and setting it requires an adopter role
    (:data:`ADOPTER_ROLES`). Without that gate, any authenticated principal
    could create a source the scheduler then installs from with no approver,
    routing around the same check ``/adopt`` enforces (PR #17 security
    review, IMPORTANT 5) and breaking this feature's own stated property:
    detection is automatic, adoption is not.
    """
    if not body.url.strip():
        raise HTTPException(400, "url is required")
    url = body.url.strip()
    try:
        validate_pack_source_url(url)
    except PackSourceRejectedError as e:
        raise HTTPException(400, str(e)) from e
    if principal.org_id is None:
        # organization_id=NULL is never polled -- the scheduler and the CLI
        # both iterate real Organization.id (IMPORTANT 6) -- so a source
        # registered by a global principal would sit at "unknown" forever,
        # polled by nothing. Reject rather than silently create dead state.
        raise HTTPException(400, "pack sources require an organization-scoped principal")
    if body.auto_install and not (principal.is_global or principal.role in ADOPTER_ROLES):
        raise HTTPException(403, f"auto_install requires role: {', '.join(ADOPTER_ROLES)}")
    src = PackSource(
        # From the principal, never the body.
        organization_id=principal.org_id,
        pack_key=pack_key,
        url=url,
        ref=body.ref,
        auto_install=body.auto_install,
    )
    session.add(src)
    await session.flush()
    await record_event(
        session,
        actor=principal.email,
        action="create",
        entity_type="pack_source",
        entity_id=str(src.id),
        diff={
            "event": "registered",
            "pack_key": pack_key,
            "url": src.url,
            "ref": src.ref,
            "auto_install": src.auto_install,
        },
    )
    await session.commit()
    await session.refresh(src)
    return _source_out(src)


@router.get("/{pack_key}/sources")
async def list_sources(
    pack_key: str,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    stmt = select(PackSource).where(PackSource.pack_key == pack_key).order_by(PackSource.id)
    if principal.org_id is not None:
        stmt = stmt.where(PackSource.organization_id == principal.org_id)
    return [_source_out(s) for s in (await session.execute(stmt)).scalars().all()]


@source_router.post("/{source_id}/sync")
async def sync_source(
    source_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Poll now. Read-only unless the source opted into auto-install."""
    src = await _require_source(session, source_id, principal)
    out = await check_pack_source(session, src, actor=principal.email)
    await session.commit()
    if "reason" in out:
        # Same oracle concern as _source_out's last_error -- a transport
        # failure's exception text must not leak through the response.
        out = {**out, "reason": _public_error(out.get("status"), out.get("reason"))}
    return out


@source_router.post("/{source_id}/adopt")
async def adopt_source(
    source_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*ADOPTER_ROLES)),
) -> dict[str, Any]:
    """Install the manifest a poll stored as pending.

    Role-gated like a waiver approval: this is the act that changes what the
    platform asserts about a system.
    """
    src = await _require_source(session, source_id, principal)
    try:
        pack = await adopt_pending(session, src, actor=principal.email)
    except ValueError as e:
        raise HTTPException(409, str(e)) from e
    await session.commit()
    return {"pack_key": pack.pack_key, "version": pack.version, "status": "installed"}


@source_router.get("/{source_id}/divergence")
async def source_divergence(
    source_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Is what is running what the repository declares?"""
    src = await _require_source(session, source_id, principal)
    return await divergence(session, src)
