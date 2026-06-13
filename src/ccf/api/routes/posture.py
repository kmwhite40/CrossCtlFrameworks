"""Enterprise compliance posture API — org-wide rollups and analytics."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from ...analytics import (
    evidence_freshness,
    org_summary,
    poam_aging,
    systems_scorecard,
)
from ..deps import get_session

router = APIRouter(prefix="/api/posture", tags=["posture"])


def _today() -> Any:
    return datetime.now(UTC).date()


@router.get("/summary")
async def summary(session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    """Executive rollup: avg SPRS, POA&M aging, evidence freshness, risk posture."""
    return await org_summary(session, today=_today())


@router.get("/systems")
async def systems(session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    """Per-system scorecard."""
    return await systems_scorecard(session, today=_today())


@router.get("/poam-aging")
async def poams(session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    return await poam_aging(session, today=_today())


@router.get("/evidence-freshness")
async def evidence(session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    return await evidence_freshness(session, today=_today())
