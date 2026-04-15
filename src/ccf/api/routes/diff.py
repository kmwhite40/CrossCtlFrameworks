"""Workbook version diff (#40) — compare two snapshots in control_history."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...models import ControlHistory, MappingHistory, WorkbookVersion
from ..deps import get_session

router = APIRouter(prefix="/api/diff", tags=["diff"])


@router.get("/workbook")
async def diff_workbook(
    a: str = Query(..., description="SHA-256 of base version"),
    b: str = Query(..., description="SHA-256 of compare version"),
    session: AsyncSession = Depends(get_session),
) -> dict:
    va = (await session.execute(
        select(WorkbookVersion).where(WorkbookVersion.sha256 == a)
    )).scalar_one_or_none()
    vb = (await session.execute(
        select(WorkbookVersion).where(WorkbookVersion.sha256 == b)
    )).scalar_one_or_none()
    if not va or not vb:
        raise HTTPException(404, "workbook version not found")

    def _flatten(rows):
        return {r.identifier: r.payload for r in rows}

    ha = _flatten((await session.execute(
        select(ControlHistory).where(ControlHistory.workbook_version_id == va.id)
    )).scalars().all())
    hb = _flatten((await session.execute(
        select(ControlHistory).where(ControlHistory.workbook_version_id == vb.id)
    )).scalars().all())

    added = sorted(set(hb) - set(ha))
    removed = sorted(set(ha) - set(hb))
    changed = sorted([k for k in set(ha) & set(hb) if ha[k] != hb[k]])

    return {
        "a": {"sha256": va.sha256, "imported_at": va.imported_at.isoformat()},
        "b": {"sha256": vb.sha256, "imported_at": vb.imported_at.isoformat()},
        "added_controls": added[:1000],
        "removed_controls": removed[:1000],
        "changed_controls": changed[:1000],
        "counts": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
        },
    }
