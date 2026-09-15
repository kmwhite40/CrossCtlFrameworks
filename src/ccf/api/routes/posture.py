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
from ...posture.drift import latest_drift, resource_timeline
from ...posture.latest import latest_result_ids
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
    """Every resource failing a control test *as of its latest run*, newest first.

    The org-wide question resource granularity exists to answer.

    Restricted to each test's most recent result. Without that restriction this
    read the append-only resource history as though it were current state and
    reported resources fixed weeks earlier, carrying the stale ``observed``
    text from the scan that found them broken -- so an operator's queue named
    work that no longer existed. "Latest" comes from
    :func:`ccf.posture.latest.latest_result_ids`, which is the one definition
    every current-state read shares.
    """
    latest = latest_result_ids()
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
        .join(latest, latest.c.result_id == ControlTestResult.id)
        .where(ControlTestResourceResult.verdict == "fail")
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


async def _owned_test(
    session: AsyncSession, test_id: int, principal: Principal
) -> ControlTest:
    """One control test, or 404 -- including when it belongs to another tenant.

    404 rather than 403, matching ``result_resources``: confirming an id exists
    is itself a disclosure.
    """
    test = (
        await session.execute(select(ControlTest).where(ControlTest.id == test_id))
    ).scalars().first()
    if test is None or (
        principal.org_id is not None and test.organization_id != principal.org_id
    ):
        raise HTTPException(status_code=404, detail="Unknown control test")
    return test


@scan_router.get("/control-tests/{test_id}/drift")
async def control_test_drift(
    test_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    """What changed between this check's two most recent runs.

    Empty for a check with fewer than two results: there is no baseline, and a
    first scan is not wholesale change.
    """
    await _owned_test(session, test_id, principal)
    return [
        {
            "resource_id": t.resource_id,
            "kind": t.kind,
            "before": t.before,
            "after": t.after,
            "observed": t.observed,
        }
        for t in await latest_drift(session, test_id=test_id)
    ]


@scan_router.get("/control-tests/{test_id}/resources/{resource_id}/timeline")
async def control_test_resource_timeline(
    test_id: int,
    resource_id: str,
    limit: int = 50,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    """One resource's verdict history for this check, newest first."""
    await _owned_test(session, test_id, principal)
    return await resource_timeline(
        session, test_id=test_id, resource_id=resource_id, limit=limit
    )
