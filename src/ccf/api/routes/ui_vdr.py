"""Pages for the FedRAMP 20x VDR engine: every system, one system, evaluate.

The arithmetic is :mod:`ccf.vdr.timeframes`; the reads and the one write are
:mod:`ccf.vdr.service`, the same calls ``/api/systems/{id}/vdr`` and
``/api/poams/{id}/evaluations`` make, so the page and the API cannot disagree.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...analytics.posture import org_system_subq
from ...auth import Principal
from ...models import System
from ...vdr import service
from ...vdr import timeframes as tf
from ..auth_deps import VIEWER_ROLE, get_principal
from ..deps import get_session
from .poams import _require_poam
from .systems import require_system_in_scope
from .ui import _principal_org, no_org_page, templates

router = APIRouter(include_in_schema=False)

ACTIVE = "vdr"


def _can_write(request: Request) -> bool:
    principal = getattr(request.state, "principal", None)
    return principal is None or getattr(principal, "role", None) != VIEWER_ROLE


@router.get("/vdr", response_class=HTMLResponse)
async def vdr_index(request: Request, session: AsyncSession = Depends(get_session)) -> Response:
    org = _principal_org(request)
    principal = getattr(request.state, "principal", None)
    if org is None and principal is not None and not getattr(principal, "is_global", False):
        return no_org_page(request, ACTIVE)
    systems = (
        (
            await session.execute(
                select(System).where(System.id.in_(org_system_subq(org))).order_by(System.name)
            )
        )
        .scalars()
        .all()
    )
    rows = [(s, await service.system_vdr(session, s)) for s in systems]
    return templates.TemplateResponse(
        request,
        "vdr_index.html",
        {"active": ACTIVE, "rows": rows, "rules_version": tf.rules_version()},
    )


@router.get("/systems/{sid}/vdr", response_class=HTMLResponse)
async def vdr_system(
    request: Request,
    sid: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> Response:
    system = await require_system_in_scope(session, sid, principal)
    view = await service.system_vdr(session, system)
    return templates.TemplateResponse(
        request,
        "vdr_system.html",
        {
            "active": ACTIVE,
            "system": system,
            "view": view,
            "can_write": _can_write(request),
            "me": getattr(getattr(request.state, "principal", None), "email", None),
            "msg": request.query_params.get("msg"),
            "error": request.query_params.get("error"),
            "labels": tf.COLUMN_LABELS,
        },
    )


@router.post("/systems/{sid}/vdr/poams/{pid}/evaluate")
async def vdr_evaluate(
    sid: int,
    pid: int,
    *,
    pain_rating: int = Form(..., ge=0, le=5),
    internet_reachable: str | None = Form(None),
    likely_exploitable: str | None = Form(None),
    false_positive: str | None = Form(None),
    rationale: str = Form("", max_length=20000),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> Response:
    await require_system_in_scope(session, sid, principal)
    poam = await _require_poam(session, pid, principal)
    if poam.system_id != sid:
        raise HTTPException(404, "poam not found")
    base = f"/systems/{sid}/vdr"
    try:
        done = await service.record_evaluation(
            session,
            poam=poam,
            pain_rating=pain_rating,
            internet_reachable=internet_reachable is not None,
            likely_exploitable=likely_exploitable is not None,
            false_positive=false_positive is not None,
            rationale=rationale,
            principal=principal,
        )
    except service.EvaluationError as e:
        return RedirectResponse(_with(base, error=f"POA&M #{pid}: {e}"), status_code=303)
    await session.commit()
    note = f"POA&M #{pid} evaluated N{pain_rating}."
    if done.pending_confirmation:
        note += " It relaxes a deadline, so it takes effect once someone else confirms it."
    if done.due_on_changed:
        note += f" Due date moved earlier to {poam.due_on}."
    return RedirectResponse(_with(base, msg=note) + f"#poam-{pid}", status_code=303)


@router.post("/systems/{sid}/vdr/poams/{pid}/evaluations/{eid}/confirm")
async def vdr_confirm(
    sid: int,
    pid: int,
    eid: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> Response:
    await require_system_in_scope(session, sid, principal)
    poam = await _require_poam(session, pid, principal)
    if poam.system_id != sid:
        raise HTTPException(404, "poam not found")
    base = f"/systems/{sid}/vdr"
    try:
        await service.confirm_evaluation(session, poam=poam, evaluation_id=eid, principal=principal)
    except service.EvaluationError as e:
        return RedirectResponse(_with(base, error=f"POA&M #{pid}: {e}"), status_code=303)
    await session.commit()
    return RedirectResponse(
        _with(base, msg=f"POA&M #{pid}: evaluation confirmed and in effect.") + f"#poam-{pid}",
        status_code=303,
    )


def _with(base: str, **params: Any) -> str:
    from urllib.parse import urlencode  # noqa: PLC0415

    return f"{base}?{urlencode(params)}"
