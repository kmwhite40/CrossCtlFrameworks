"""External collaboration portal API + UI.

Three surfaces:

* ``/api/admin/portal`` — internal admins issue / list / revoke scoped grants
  (role-gated, tenant-scoped).
* ``/api/portal`` — the external, **token-authenticated** JSON API a customer /
  assessor / vendor calls. No session; the bearer token *is* the credential.
* ``/portal`` — a minimal, read-mostly HTML view of what a token can see.

The public surfaces are listed in ``auth_deps._PUBLIC_PREFIXES`` so the session
gate lets them through; the portal service is the real authorization boundary.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...portal import (
    add_comment,
    create_grant,
    grant_contents,
    list_grants,
    record_access,
    resolve_grant,
    revoke_grant,
)
from ..auth_deps import require_role
from ..deps import get_session

TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter(prefix="/api/admin/portal", tags=["portal"])
public_router = APIRouter(prefix="/api/portal", tags=["portal"])
ui_router = APIRouter(tags=["portal"])


# --- admin (internal) ------------------------------------------------------


class GrantIn(BaseModel):
    organization_id: int
    principal_name: str
    kind: str = "customer"
    email: str | None = None
    organization_name: str | None = None
    package_ids: list[int] = []
    evidence_ids: list[int] = []
    ttl_days: int | None = 30
    label: str | None = None


@router.post("/grants")
async def create_grant_endpoint(
    body: GrantIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> dict[str, Any]:
    grant = await create_grant(
        session, org_id=body.organization_id, principal_name=body.principal_name,
        kind=body.kind, email=body.email, organization_name=body.organization_name,
        package_ids=body.package_ids, evidence_ids=body.evidence_ids,
        ttl_days=body.ttl_days, label=body.label, actor=principal.email,
    )
    await session.commit()
    return {"id": grant.id, "token": grant.token, "kind": grant.kind,
            "expires_at": grant.expires_at}


@router.get("/grants")
async def list_grants_endpoint(
    organization_id: int,
    session: AsyncSession = Depends(get_session),
    _principal: Principal = Depends(require_role("admin")),
) -> list[dict[str, Any]]:
    grants = await list_grants(session, org_id=organization_id)
    return [
        {"id": g.id, "token": g.token, "kind": g.kind, "label": g.label,
         "revoked": g.revoked, "expires_at": g.expires_at, "created_at": g.created_at}
        for g in grants
    ]


@router.post("/grants/{grant_id}/revoke")
async def revoke_grant_endpoint(
    grant_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> dict[str, Any]:
    ok = await revoke_grant(session, grant_id, actor=principal.email)
    await session.commit()
    if not ok:
        raise HTTPException(status_code=404, detail="grant not found")
    return {"revoked": True}


# --- external (token-authenticated) ----------------------------------------


def _token(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return request.query_params.get("token", "")


async def _require_grant(request: Request, session: AsyncSession) -> Any:
    grant = await resolve_grant(session, _token(request))
    if grant is None:
        raise HTTPException(status_code=401, detail="invalid or expired token")
    return grant


class CommentIn(BaseModel):
    target_type: str
    target_id: str
    body: str
    author: str | None = None


@public_router.get("/session")
async def portal_session(
    request: Request, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    grant = await _require_grant(request, session)
    contents = await grant_contents(session, grant)
    await record_access(session, grant, action="view")
    await session.commit()
    return contents


@public_router.post("/comments")
async def portal_comment(
    body: CommentIn, request: Request, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    grant = await _require_grant(request, session)
    comment = await add_comment(
        session, grant, target_type=body.target_type, target_id=body.target_id,
        author=body.author, body=body.body,
    )
    await session.commit()
    return {"id": comment.id}


@ui_router.get("/portal", response_class=HTMLResponse)
async def portal_ui(
    request: Request, token: str = "", session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    grant = await resolve_grant(session, token) if token else None
    contents = None
    if grant is not None:
        contents = await grant_contents(session, grant)
        await record_access(session, grant, action="view")
        await session.commit()
    return templates.TemplateResponse(
        request,
        "portal.html",
        {"token": token, "grant": grant, "contents": contents},
    )
