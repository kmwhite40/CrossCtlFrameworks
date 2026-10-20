"""Server-rendered ATO workspace: ``/ato`` (portfolio) and ``/ato/{system_id}``.

Every form here calls the same service the JSON API calls -- ``ato.roles``,
``ato.lifecycle``, ``ato.extensions``, ``governance.approvals`` -- so the
authority, separation-of-duties and blocker rules live in one place. A refused
action redirects back with the reason (``?error=``); never a bare 4xx page, the
shape of defect that once had form refusals landing on a blank screen.

``/workspace`` is a different page (the customer-journey stepper) and is left
alone; this one is ``active="atows"``.
"""

from __future__ import annotations

from datetime import date
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...ato import extensions as poam_extensions
from ...ato import lifecycle, workspace
from ...ato import roles as system_roles
from ...auth import Principal
from ...governance import approvals
from ...models import POAM, System, User
from ...models_ato import SYSTEM_ROLES, PoamExtension
from ...models_packages import AuthorizationPackage
from ...packages import service as package_service
from ..auth_deps import get_principal
from ..deps import get_session
from .ui import _principal_org, templates

router = APIRouter(include_in_schema=False)

AUDIENCES = {
    "authorizing_official": "Authorizing Official",
    "issm": "ISSM",
    "isso": "ISSO",
    "system_owner": "System Owner",
}


def _back(system_id: int, *, error: str | None = None, anchor: str = "") -> RedirectResponse:
    url = f"/ato/{system_id}"
    if error:
        url += f"?error={quote(error)}"
    return RedirectResponse(url + (f"#{anchor}" if anchor else ""), status_code=303)


async def _system(session: AsyncSession, system_id: int, request: Request) -> System:
    org = _principal_org(request)
    sysm = (
        await session.execute(
            select(System).where(System.id == system_id, System.deleted_at.is_(None))
        )
    ).scalar_one_or_none()
    if sysm is None or (org is not None and sysm.organization_id != org):
        raise HTTPException(404, "system not found")
    return sysm


@router.get("/ato", response_class=HTMLResponse)
async def ato_index(request: Request, session: AsyncSession = Depends(get_session)) -> HTMLResponse:
    org = _principal_org(request)
    stmt = select(System).where(System.deleted_at.is_(None)).order_by(System.name)
    if org is not None:
        stmt = stmt.where(System.organization_id == org)
    systems = list((await session.execute(stmt)).scalars())
    rows = await workspace.portfolio(session, systems)
    counts = {
        "systems": len(rows),
        "authorized": sum(1 for r in rows if r["ato_status"] == "authorized"),
        "in_review": sum(1 for r in rows if r["package_status"] in lifecycle.REVIEW_STATUSES),
        "blocked": sum(1 for r in rows if r["blockers"]),
    }
    return templates.TemplateResponse(
        request, "ato.html", {"active": "atows", "rows": rows, "counts": counts}
    )


@router.get("/ato/{system_id}", response_class=HTMLResponse)
async def ato_system(
    system_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> HTMLResponse:
    sysm = await _system(session, system_id, request)
    ws = await workspace.build(session, sysm)
    users = list(
        (
            await session.execute(
                select(User)
                .where(
                    User.organization_id == sysm.organization_id,
                    User.active.is_(True),
                    User.role != "viewer",
                )
                .order_by(User.email)
            )
        ).scalars()
    )
    return templates.TemplateResponse(
        request,
        "ato_system.html",
        {
            "active": "atows",
            "ws": ws,
            "users": users,
            "role_labels": system_roles.ROLE_LABELS,
            "system_roles": SYSTEM_ROLES,
            "action_labels": lifecycle.ACTION_LABELS,
            "transitions": lifecycle.TRANSITIONS,
            "audiences": AUDIENCES,
            "is_admin": principal.role == "admin",
            "me": principal.email,
            "error": request.query_params.get("error"),
        },
    )


@router.post("/ato/{system_id}/roles")
async def ato_assign_role(  # noqa: PLR0917 -- FastAPI binds these by keyword
    system_id: int,
    request: Request,
    role: str = Form(...),
    user_id: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> RedirectResponse:
    sysm = await _system(session, system_id, request)
    if principal.role != "admin":
        return _back(system_id, error="Only an admin can assign signing roles.", anchor="roles")
    try:
        if user_id.strip():
            await system_roles.assign(
                session, system=sysm, role=role, user_id=int(user_id), principal=principal
            )
        else:
            await system_roles.unassign(session, system=sysm, role=role, principal=principal)
    except (system_roles.RoleError, ValueError) as e:
        return _back(system_id, error=str(e), anchor="roles")
    await session.commit()
    return _back(system_id, anchor="roles")


@router.post("/ato/{system_id}/packages")
async def ato_capture_package(
    system_id: int,
    request: Request,
    label: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> RedirectResponse:
    sysm = await _system(session, system_id, request)
    pkg = await package_service.create_package(
        session, org_id=sysm.organization_id, system_id=sysm.id, kind="fedramp20x",
        label=label.strip() or f"{sysm.name} authorization package {date.today()}",
        created_by=principal.email,
    )
    await lifecycle.manifest_sha256(session, pkg)
    await session.commit()
    return _back(system_id, anchor="package")


@router.post("/ato/{system_id}/packages/{package_id}/{action}")
async def ato_package_action(  # noqa: PLR0917 -- FastAPI binds these by keyword
    system_id: int,
    package_id: int,
    action: str,
    request: Request,
    reason: str = Form(""),
    expires_on: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> RedirectResponse:
    sysm = await _system(session, system_id, request)
    pkg = await session.get(AuthorizationPackage, package_id)
    if pkg is None or pkg.system_id != sysm.id:
        raise HTTPException(404, "package not found")
    until: date | None = None
    if expires_on.strip():
        try:
            until = date.fromisoformat(expires_on.strip())
        except ValueError:
            return _back(system_id, error="End date must be YYYY-MM-DD.", anchor="package")
    try:
        await lifecycle.apply(
            session, package=pkg, action=action, principal=principal,
            reason=reason, expires_on=until,
        )
    except lifecycle.LifecycleError as e:
        return _back(system_id, error=str(e), anchor="package")
    await session.commit()
    return _back(system_id, anchor="package")


async def _poam_in(session: AsyncSession, sysm: System, poam_id: int) -> POAM:
    poam = await session.get(POAM, poam_id)
    if poam is None or poam.system_id != sysm.id:
        raise HTTPException(404, "POA&M not found")
    return poam


@router.post("/ato/{system_id}/extensions")
async def ato_request_extension(  # noqa: PLR0917 -- FastAPI binds these by keyword
    system_id: int,
    request: Request,
    poam_id: int = Form(...),
    requested_due_on: str = Form(""),
    reason: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> RedirectResponse:
    sysm = await _system(session, system_id, request)
    poam = await _poam_in(session, sysm, poam_id)
    try:
        when = date.fromisoformat(requested_due_on.strip())
    except ValueError:
        return _back(system_id, error="New due date must be YYYY-MM-DD.", anchor="poams")
    try:
        await poam_extensions.request(
            session, poam=poam, requested_due_on=when, reason=reason, principal=principal
        )
    except poam_extensions.ExtensionError as e:
        return _back(system_id, error=str(e), anchor="poams")
    await session.commit()
    return _back(system_id, anchor="extensions")


@router.post("/ato/{system_id}/extensions/{extension_id}/{decision}")
async def ato_decide_extension(  # noqa: PLR0917 -- FastAPI binds these by keyword
    system_id: int,
    extension_id: int,
    decision: str,
    request: Request,
    note: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> RedirectResponse:
    if decision not in ("approve", "reject", "withdraw"):
        raise HTTPException(404, "unknown decision")
    sysm = await _system(session, system_id, request)
    ext = await session.get(PoamExtension, extension_id)
    if ext is None:
        raise HTTPException(404, "extension request not found")
    poam = await _poam_in(session, sysm, ext.poam_id)
    try:
        if decision == "withdraw":
            await poam_extensions.withdraw(session, extension=ext, principal=principal)
        else:
            await poam_extensions.decide(
                session, poam=poam, extension=ext, approve=decision == "approve",
                note=note, principal=principal,
            )
    except poam_extensions.ExtensionError as e:
        return _back(system_id, error=str(e), anchor="extensions")
    await session.commit()
    return _back(system_id, anchor="extensions")


@router.post("/ato/{system_id}/approvals/{entity_type}/{entity_id}/{decision}")
async def ato_decide_approval(  # noqa: PLR0917 -- FastAPI binds these by keyword
    system_id: int,
    entity_type: str,
    entity_id: int,
    decision: str,
    request: Request,
    note: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> RedirectResponse:
    """Decide a submitted POA&M or risk approval from the workspace.

    Concord had the approval engine and no page that could reach it; this is
    that page for the approvals that belong to this system.
    """
    if decision not in ("approve", "reject") or entity_type not in ("poam", "risk"):
        raise HTTPException(404, "unknown decision")
    await _system(session, system_id, request)
    try:
        await approvals.decide(
            session, entity_type=entity_type, entity_id=str(entity_id),
            approve=decision == "approve", actor=principal.email, role=principal.role,
            note=note.strip() or None, org_id=principal.org_id, user_id=principal.user_id,
        )
    except approvals.WorkflowError as e:
        return _back(system_id, error=str(e), anchor="approvals")
    await session.commit()
    return _back(system_id, anchor="approvals")


@router.get("/ato/{system_id}/brief", response_class=HTMLResponse)
async def ato_brief(
    system_id: int,
    request: Request,
    audience: str = "authorizing_official",
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    """A printable brief for one audience, rendered from the workspace itself.

    Every figure in it is one the workspace page shows; the audience changes
    what is foregrounded and what decisions are asked for, never the numbers.
    """
    if audience not in AUDIENCES:
        audience = "authorizing_official"
    sysm = await _system(session, system_id, request)
    ws = await workspace.build(session, sysm)
    return templates.TemplateResponse(
        request,
        "ato_brief.html",
        {
            "active": "atows",
            "ws": ws,
            "audience": audience,
            "audience_label": AUDIENCES[audience],
            "audiences": AUDIENCES,
            "role_labels": system_roles.ROLE_LABELS,
        },
    )
