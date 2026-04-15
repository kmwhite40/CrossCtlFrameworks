"""Coverage heatmap (framework x family) — read-only reporting."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...models import Control, ControlFamily, Framework, FrameworkMapping
from ..deps import get_session

router = APIRouter(prefix="/api/coverage", tags=["coverage"])


@router.get("/matrix")
async def coverage_matrix(session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    # Count distinct controls per (framework, family)
    stmt = (
        select(
            Framework.code.label("framework"),
            ControlFamily.code.label("family"),
            func.count(func.distinct(Control.id)).label("controls"),
        )
        .select_from(FrameworkMapping)
        .join(Framework, Framework.id == FrameworkMapping.framework_id)
        .join(Control, Control.id == FrameworkMapping.control_id)
        .join(ControlFamily, ControlFamily.id == Control.family_id, isouter=True)
        .group_by(Framework.code, ControlFamily.code)
    )
    rows = (await session.execute(stmt)).all()

    # Also collect totals per framework + per family for normalization.
    fam_totals = {
        r.code: r.n
        for r in (
            await session.execute(
                select(ControlFamily.code, func.count(Control.id).label("n"))
                .select_from(Control)
                .join(ControlFamily, ControlFamily.id == Control.family_id, isouter=True)
                .group_by(ControlFamily.code)
            )
        ).all()
    }
    fw_totals = {
        r.code: r.n
        for r in (
            await session.execute(
                select(
                    Framework.code,
                    func.count(func.distinct(FrameworkMapping.control_id)).label("n"),
                )
                .select_from(FrameworkMapping)
                .join(Framework, Framework.id == FrameworkMapping.framework_id)
                .group_by(Framework.code)
            )
        ).all()
    }

    return {
        "cells": [
            {"framework": r.framework, "family": r.family, "controls": r.controls} for r in rows
        ],
        "family_totals": fam_totals,
        "framework_totals": fw_totals,
    }
