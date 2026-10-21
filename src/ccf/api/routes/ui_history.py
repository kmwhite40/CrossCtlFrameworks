"""Posture history pages: compliance trends and a projection from them.

Spec: docs/superpowers/specs/2026-10-20-grc-buildout-design.md, "A -- history".

Both pages read only ``PostureSnapshot`` rows (``analytics.posture_history``),
filtered on the caller's organization in the query itself. The one write --
"record today's snapshot now" -- is admin-only and audited. A global or
unauthenticated session has no organization, and these pages describe one
organization, so it sees an explanation rather than an aggregate.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from ...analytics import posture_history as ph
from ...auth import Principal
from ..audit import record_event
from ..auth_deps import require_role
from ..deps import get_session
from .ui import _principal_org, templates

router = APIRouter(include_in_schema=False)


def _today() -> Any:
    # UTC, as the scheduler dates its cycle, so a manual capture and the
    # scheduled one on the same day land on the same row.
    return datetime.now(UTC).date()


def _can_capture(request: Request) -> bool:
    """Whether to offer the capture button. Display only: the POST route's
    ``require_role`` is the control."""
    p = getattr(request.state, "principal", None)
    return p is not None and getattr(p, "role", None) == "admin"


@router.get("/trends", response_class=HTMLResponse)
async def trends_page(
    request: Request,
    days: int = Query(ph.DEFAULT_RANGE),
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    org = _principal_org(request)
    if days not in ph.RANGES:
        days = ph.DEFAULT_RANGE
    today = _today()
    data = (
        await ph.trends_for(session, org, today=today, range_days=days) if org is not None else None
    )
    return templates.TemplateResponse(
        request,
        "trends.html",
        {
            "active": "trends",
            "scoped": org is not None,
            "t": data,
            "ranges": ph.RANGES,
            "days": days,
            "can_capture": _can_capture(request) and org is not None,
            "captured": request.query_params.get("captured"),
        },
    )


@router.post("/trends/capture")
async def trends_capture(
    request: Request,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> RedirectResponse:
    """Record the caller's organization's posture for today, now.

    Same day replaces: the scheduler's capture and this one share a row."""
    org = _principal_org(request)
    if org is None:
        raise HTTPException(400, "no organization in scope: a snapshot is one organization's")
    out = await ph.capture_snapshot(session, org, today=_today(), source="manual")
    await record_event(
        session,
        actor=principal.email,
        action="posture_snapshot_captured",
        entity_type="posture_snapshot",
        entity_id=str(out["id"]),
        diff={
            "taken_on": out["taken_on"].isoformat(),
            "source": "manual",
            "replaced": out["replaced"],
        },
        organization_id=org,
    )
    await session.commit()
    return RedirectResponse(
        f"/trends?captured={'replaced' if out['replaced'] else 'new'}", status_code=303
    )


@router.get("/forecast", response_class=HTMLResponse)
async def forecast_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    today = _today()
    data = await ph.forecast_for(session, org, today=today) if org is not None else None
    return templates.TemplateResponse(
        request,
        "forecast.html",
        {
            "active": "forecast",
            "scoped": org is not None,
            "f": data,
            "min_points": ph.MIN_POINTS,
            "min_span": ph.MIN_SPAN_DAYS,
            "horizon": ph.HORIZON_DAYS,
            "window": ph.FIT_WINDOW_DAYS,
        },
    )
