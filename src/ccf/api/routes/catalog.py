"""Catalog currency — inspect authoritative sources and trigger drift checks.

Read endpoints surface the last-known drift status per source (safe in the
read-only Reader build). The ``check`` endpoint runs a poll on demand; it is a
POST, so the read-only guard blocks it automatically.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...catalog.impact import build_adoption_impact
from ...catalog.revisions import (
    AdoptionRefusedError,
    _catalog_for,
    adopt_revision,
    compute_revision_diff,
)
from ...db import session_scope
from ...etl.sources import check_source
from ...models import CatalogCheck, CatalogRevision, CatalogSource
from ..auth_deps import require_role
from ..deps import get_session

router = APIRouter(prefix="/api/catalog", tags=["catalog"])


class AdoptIn(BaseModel):
    """Adoption request body — acknowledging a reviewed, non-empty impact."""

    acknowledge_impact: bool = False


def _source_out(s: CatalogSource) -> dict[str, Any]:
    return {
        "id": s.id,
        "key": s.key,
        "name": s.name,
        "authority": s.authority,
        "kind": s.kind,
        "url": s.url,
        "framework_code": s.framework_code,
        "enabled": s.enabled,
        "auto_ingest": s.auto_ingest,
        "revision_label": s.revision_label,
        "item_count": s.item_count,
        "last_status": s.last_status,
        "last_error": s.last_error,
        "last_checked_at": s.last_checked_at,
        "last_changed_at": s.last_changed_at,
    }


def _check_out(c: CatalogCheck) -> dict[str, Any]:
    return {
        "id": c.id,
        "source_id": c.source_id,
        "checked_at": c.checked_at,
        "status": c.status,
        "http_status": c.http_status,
        "sha256": c.sha256,
        "duration_ms": c.duration_ms,
        "detail": c.detail,
    }


@router.get("/sources")
async def list_sources(session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    """All registered catalog sources with their last-known drift status."""
    rows = (await session.execute(select(CatalogSource).order_by(CatalogSource.id))).scalars().all()
    return [_source_out(s) for s in rows]


@router.get("/sources/{source_id}/checks")
async def list_checks(
    source_id: int,
    limit: int = 20,
    session: AsyncSession = Depends(get_session),
) -> list[dict[str, Any]]:
    """Recent drift checks for one source (most recent first)."""
    rows = (
        (
            await session.execute(
                select(CatalogCheck)
                .where(CatalogCheck.source_id == source_id)
                .order_by(CatalogCheck.id.desc())
                .limit(min(limit, 200))
            )
        )
        .scalars()
        .all()
    )
    return [_check_out(c) for c in rows]


@router.post("/sources/{source_id}/check")
async def check_now(
    source_id: int,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Poll one source immediately and return the resulting check."""
    source = (
        await session.execute(select(CatalogSource).where(CatalogSource.id == source_id))
    ).scalar_one_or_none()
    if source is None:
        raise HTTPException(status_code=404, detail="Unknown catalog source")
    check = await check_source(session, source)
    await session.commit()
    return _check_out(check)


def _revision_out(r: CatalogRevision) -> dict[str, Any]:
    return {
        "id": r.id,
        "source_id": r.source_id,
        "revision": r.revision,
        "upstream_commit_sha": r.upstream_commit_sha,
        "upstream_url": r.upstream_url,
        "oscal_version": r.oscal_version,
        "content_sha256": r.content_sha256,
        "status": r.status,
        "retrieved_at": r.retrieved_at,
        "retrieved_by": r.retrieved_by,
        "adopted_at": r.adopted_at,
        "adopted_by": r.adopted_by,
        "notes": r.notes,
    }


async def _revision_or_404(session: AsyncSession, revision_id: int) -> CatalogRevision:
    row = await session.get(CatalogRevision, revision_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Unknown catalog revision")
    return row


@router.get("/sources/{source_id}/revisions")
async def list_revisions(
    source_id: int,
    limit: int = 50,
    session: AsyncSession = Depends(get_session),
) -> list[dict[str, Any]]:
    """Retained revisions for one source, newest first."""
    rows = (
        (
            await session.execute(
                select(CatalogRevision)
                .where(CatalogRevision.source_id == source_id)
                .order_by(CatalogRevision.id.desc())
                .limit(min(limit, 200))
            )
        )
        .scalars()
        .all()
    )
    return [_revision_out(r) for r in rows]


@router.get("/revisions/{revision_id}/diff")
async def revision_diff(
    revision_id: int,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Diff one revision against its source's currently adopted revision.

    ``catalog_revisions`` is global reference data with no ``organization_id``
    and no RLS, so this is unaffected by the caller's tenant scope -- unlike
    ``/impact`` below, there is no per-org slice to compute against.
    """
    row = await _revision_or_404(session, revision_id)
    diff = await compute_revision_diff(session, revision=row)
    return {"revision": _revision_out(row), "diff": diff.to_dict()}


@router.get("/revisions/{revision_id}/impact")
async def revision_impact(
    revision_id: int,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """What adopting this revision would do to this deployment's content.

    Computed on a separate, unscoped session -- not the caller's tenant-scoped
    ``session`` -- for the same reason ``adopt_revision``'s gate is: adopting
    a revision is a platform-wide change, so the impact must reflect every
    organization's content, not just the org the caller happens to belong to.
    """
    row = await _revision_or_404(session, revision_id)
    async with session_scope() as unscoped:
        diff = await compute_revision_diff(unscoped, revision=row)
        impact = await build_adoption_impact(unscoped, diff=diff, candidate=_catalog_for(row))
    return {"revision": _revision_out(row), "impact": impact.to_dict()}


@router.post("/revisions/{revision_id}/adopt")
async def adopt(
    revision_id: int,
    body: AdoptIn | None = None,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> dict[str, Any]:
    """Adopt a revision — changes the catalog the platform loads.

    Returns **409** with the impact report when adoption would affect existing
    content and ``acknowledge_impact`` was not set, so a client cannot adopt
    past consequences it has not seen. Adoption stays available to any org
    admin (``require_role("admin")``), but the impact behind that 409 is
    computed platform-wide, not scoped to the calling admin's own org: a
    catalog revision is a single global pointer, so an org with no SSP content
    of its own must not be able to adopt straight past a revision that guts
    another org's authored content just because its own (empty) slice showed
    no impact. See :func:`ccf.catalog.revisions.adopt_revision`.
    """
    acknowledge = bool(body and body.acknowledge_impact)
    try:
        row = await adopt_revision(
            session,
            revision_id=revision_id,
            actor=principal.email,
            acknowledge_impact=acknowledge,
        )
    except AdoptionRefusedError as e:
        raise HTTPException(
            status_code=409,
            detail={"message": str(e), "impact": e.impact.to_dict()},
        ) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    await session.commit()
    return _revision_out(row)
