"""Assurance query layer API + UI (Phase 9).

Deterministic, parameterized query templates over the authorization data. The API
(`/api/queries`) lists templates and runs/exports them; the UI (`/queries`) is a
pick-a-template → fill-params → results-table → export-CSV surface. Results are
tenant-scoped to the caller's org: a caller-supplied ``organization_id``
may only confirm the principal's own org, never name a different one.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...queries import REGISTRY, export_csv, list_templates, run_query
from ..auth_deps import get_principal, resolve_caller_org
from ..deps import get_session
from .ui import _principal_org, templates

router = APIRouter(prefix="/api/queries", tags=["queries"])
ui_router = APIRouter(tags=["queries"])


class RunIn(BaseModel):
    organization_id: int | None = None
    params: dict[str, Any] = {}


def _org(request: Request, body_org: int | None) -> int | None:
    """The org these templates run against.

    A body/query ``organization_id`` used to *win* over the authenticated
    principal here, so a tenant caller could name any org and have every
    template -- and its CSV export -- run against it. Postgres RLS happened to
    return nothing (``deps.get_session`` binds the tenant, and every table
    these templates read carries a ``tenant_isolation`` policy), but that is
    the backstop, not the check: ``run_query`` itself had no org predicate of
    its own, which an unscoped ``session_scope()`` shows immediately.
    ``resolve_caller_org`` is now that check.
    """
    return resolve_caller_org(_principal_org(request), body_org)


@router.get("")
async def list_endpoint(
    _principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    return list_templates()


@router.post("/{key}/run")
async def run_endpoint(
    key: str,
    body: RunIn,
    request: Request,
    session: AsyncSession = Depends(get_session),
    _principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    try:
        return await run_query(
            session, key, body.params, org_id=_org(request, body.organization_id)
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="unknown query template") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/{key}/export")
async def export_endpoint(
    key: str,
    body: RunIn,
    request: Request,
    session: AsyncSession = Depends(get_session),
    _principal: Principal = Depends(get_principal),
) -> Response:
    try:
        result = await run_query(
            session, key, body.params, org_id=_org(request, body.organization_id)
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="unknown query template") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return Response(
        content=export_csv(result),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{key}.csv"'},
    )


@ui_router.get("/queries", response_class=HTMLResponse)
async def queries_page(
    request: Request,
    key: str = "",
    organization_id: int | None = None,
    run: str = "",
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    org_id = _org(request, organization_id)
    selected = REGISTRY.get(key)
    result = None
    values: dict[str, str] = {}
    if selected is not None:
        values = {p.name: request.query_params.get(p.name, "") for p in selected.params}
        if run:
            result = await run_query(session, key, dict(values), org_id=org_id)
    return templates.TemplateResponse(
        request, "queries.html",
        {"active": "queries", "org_id": org_id, "templates": list_templates(),
         "selected": selected, "values": values, "result": result},
    )
