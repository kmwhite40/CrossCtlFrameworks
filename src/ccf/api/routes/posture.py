"""Enterprise posture API — compliance rollups plus live security posture.

This module deliberately serves both senses of "posture". The original
endpoints roll up internal records (POA&M aging, evidence freshness); the
``failing-resources`` endpoint reports what a live scan observed in the
environment, and ``scan_router`` carries the cross-cutting paths that do not
fit under the ``/api/posture`` prefix. They live together so one concept is
not split across two modules.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...analytics import (
    evidence_freshness,
    org_summary,
    poam_aging,
    systems_scorecard,
)
from ...auth import Principal
from ...models_grc import ControlTest, ControlTestResourceResult, ControlTestResult
from ..auth_deps import get_principal
from ..deps import get_session

router = APIRouter(prefix="/api/posture", tags=["posture"])

#: Cross-cutting posture paths that do not sit under /api/posture. Two routers
#: in one module follows the precedent in api/routes/packages.py.
scan_router = APIRouter(prefix="/api", tags=["posture"])


def _today() -> Any:
    return datetime.now(UTC).date()


@router.get("/summary")
async def summary(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Executive rollup: avg SPRS, POA&M aging, evidence freshness, risk posture."""
    return await org_summary(session, today=_today(), org_id=principal.org_id)


@router.get("/systems")
async def systems(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    """Per-system scorecard."""
    return await systems_scorecard(session, today=_today(), org_id=principal.org_id)


@router.get("/poam-aging")
async def poams(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    return await poam_aging(session, today=_today(), org_id=principal.org_id)


@router.get("/evidence-freshness")
async def evidence(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    return await evidence_freshness(session, today=_today(), org_id=principal.org_id)


@router.get("/failing-resources")
async def failing_resources(
    resource_type: str | None = None,
    limit: int = 200,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    """Every resource currently failing a control test, newest first.

    The org-wide question resource granularity exists to answer. "Currently"
    means restricted to each test's *latest* ``ControlTestResult`` -- the
    child rows are append-only, so a resource that failed a stale run and has
    since passed a newer one must not still show up here. That restriction is
    done via a correlated subquery (one per ``ControlTest``, picking its most
    recent result by ``run_at``/``id``) rather than a window function, which
    keeps this a plain ``SELECT`` the existing indexes can serve directly:
    ``ix_control_test_results_test_run`` (control_test_id, run_at) drives the
    subquery, and ``ix_ctrr_verdict``/``ix_ctrr_result`` still serve the outer
    filter/join on ``control_test_resource_results``.
    """
    latest_result_id = (
        select(ControlTestResult.id)
        .where(ControlTestResult.control_test_id == ControlTest.id)
        .order_by(ControlTestResult.run_at.desc(), ControlTestResult.id.desc())
        .limit(1)
        .correlate(ControlTest)
        .scalar_subquery()
    )
    stmt = (
        select(
            ControlTestResourceResult,
            ControlTest.control_id,
            ControlTest.system_id,
            ControlTest.id,
        )
        .join(
            ControlTestResult,
            ControlTestResult.id == ControlTestResourceResult.result_id,
        )
        .join(ControlTest, ControlTest.id == ControlTestResult.control_test_id)
        .where(
            ControlTestResourceResult.verdict == "fail",
            ControlTestResourceResult.result_id == latest_result_id,
        )
        .order_by(ControlTestResourceResult.created_at.desc())
        .limit(min(max(limit, 1), 1000))
    )
    if principal.org_id is not None:
        stmt = stmt.where(ControlTest.organization_id == principal.org_id)
    if resource_type:
        stmt = stmt.where(ControlTestResourceResult.resource_type == resource_type)
    return [
        {
            "resource_id": row[0].resource_id,
            "resource_type": row[0].resource_type,
            "observed": row[0].observed,
            "detail": row[0].detail,
            "result_id": row[0].result_id,
            "created_at": row[0].created_at,
            "control_id": row[1],
            "system_id": row[2],
            "test_id": row[3],
        }
        for row in (await session.execute(stmt)).all()
    ]


@scan_router.post("/systems/{system_id}/scan")
async def scan_system(
    system_id: int,
    connector: str,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Scan one system with one connector, recording per-resource findings."""
    from ...posture.scan import scan_for_system  # noqa: PLC0415

    try:
        out = await scan_for_system(
            session,
            system_id=system_id,
            connector_key=connector,
            actor=principal.email,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    await session.commit()
    return out


@scan_router.get("/control-tests/{test_id}/results/{result_id}/resources")
async def result_resources(
    test_id: int,
    result_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    """Every resource row for one result -- passing and failing alike.

    Unlike the org-wide failing view, the per-result view shows what was
    evaluated, not only what broke: "3 of 47" is only meaningful alongside
    the 44.
    """
    owner = (
        await session.execute(
            select(ControlTest)
            .join(ControlTestResult, ControlTestResult.control_test_id == ControlTest.id)
            .where(ControlTest.id == test_id, ControlTestResult.id == result_id)
        )
    ).scalars().first()
    if owner is None:
        raise HTTPException(status_code=404, detail="Unknown result for that test")
    if principal.org_id is not None and owner.organization_id != principal.org_id:
        # Indistinguishable from absent: never confirm existence across tenants.
        raise HTTPException(status_code=404, detail="Unknown result for that test")
    rows = (
        await session.execute(
            select(ControlTestResourceResult)
            .where(ControlTestResourceResult.result_id == result_id)
            .order_by(
                ControlTestResourceResult.verdict, ControlTestResourceResult.resource_id
            )
        )
    ).scalars().all()
    return [
        {
            "resource_id": r.resource_id,
            "resource_type": r.resource_type,
            "verdict": r.verdict,
            "observed": r.observed,
            "detail": r.detail,
        }
        for r in rows
    ]


@scan_router.get("/controls/{control_id}/effective-verdict")
async def control_effective_verdict(
    control_id: str,
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Which verdict should be believed for this control on this system."""
    from ...posture.scan import effective_verdict  # noqa: PLC0415

    return await effective_verdict(session, system_id=system_id, control_id=control_id)
