"""Server-rendered UI for the system boundary (Keystone #1) — a role-gated
page listing a system's components, inventory items, information types, and
interconnections, plus auto-rendered Mermaid boundary/data-flow diagrams.

Kept separate from the large ``ui.py`` and reuses its configured Jinja
environment (same base.html + light theme, asset-version cache-busting), same
convention as ``ui_grc.py``.

The diagrams are generated from the same ``BoundarySummary`` the Task-6 JSON
CRUD API (``ccf.api.routes.boundary``) reads and writes, so they can never
drift from the inventory the forms on this page edit.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...boundary.diagram import boundary_mermaid, data_flow_mermaid
from ...boundary.summary import system_boundary_summary
from ..auth_deps import require_role
from ..deps import get_session
from .boundary import (
    COMPONENT_STATUSES,
    COMPONENT_TYPES,
    FIPS199_IMPACTS,
    INTERCONNECTION_AGREEMENT_TYPES,
    INTERCONNECTION_DIRECTIONS,
    INVENTORY_ASSET_TYPES,
)
from .systems import require_system_in_scope
from .ui import templates

router = APIRouter(include_in_schema=False)


@router.get("/systems/{system_id}/boundary", response_class=HTMLResponse)
async def boundary_page(
    request: Request,
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "assessor")),
) -> HTMLResponse:
    sys = await require_system_in_scope(session, system_id, principal)
    summary = await system_boundary_summary(session, system_id)
    return templates.TemplateResponse(
        request,
        "system_boundary.html",
        {
            "system": sys,
            "summary": summary,
            "boundary_diagram": boundary_mermaid(summary, sys.name),
            "dataflow_diagram": data_flow_mermaid(summary, sys.name),
            "active": "systems",
            # Controlled vocabularies for the create forms — sourced from the
            # Task-6 JSON API's own frozensets so the UI can never drift from
            # what the API actually accepts.
            "component_types": sorted(COMPONENT_TYPES),
            "component_statuses": sorted(COMPONENT_STATUSES),
            "inventory_asset_types": sorted(INVENTORY_ASSET_TYPES),
            "interconnection_directions": sorted(INTERCONNECTION_DIRECTIONS),
            "interconnection_agreement_types": sorted(INTERCONNECTION_AGREEMENT_TYPES),
            "fips199_impacts": sorted(FIPS199_IMPACTS),
        },
    )
