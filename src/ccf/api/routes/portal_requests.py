"""Agency self-service access requests (CDS-TRC-SSM) and denial notice (CDS-UTC-AAD).

Four surfaces over :mod:`ccf.portal.requests`:

* ``/api/admin/portal/request-links`` and ``/api/admin/portal/access-requests``
  -- the provider's admin API (role-gated and org-scoped like every portal
  admin route).
* ``/api/portal/access-requests`` -- the agency's API: submit with a request
  link, check status and claim with the receipt. No account; the link and
  the receipt are the credentials. Rate-limited.
* ``/portal/request`` -- the same, as pages.
* ``/admin/portal/...`` form posts for the portal-admin page.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...models import System
from ...portal import requests as req_service
from ...portal.requests import RequestError
from ..auth_deps import require_role, resolve_caller_org
from ..deps import get_session
from ..limiter import limiter
from .portal import templates

admin_router = APIRouter(prefix="/api/admin/portal", tags=["certification-data"])
public_router = APIRouter(prefix="/api/portal", tags=["certification-data"])
ui_router = APIRouter(include_in_schema=False)

_NO_STORE = {"Cache-Control": "no-store"}

#: Public submissions and claims, per client address.
_PUBLIC_LIMIT = "10/minute"


def _http(exc: RequestError) -> HTTPException:
    return HTTPException(status_code=exc.status, detail=str(exc))


def _today() -> date:
    return req_service.us_today()


def _org(principal: Principal, organization_id: int | None) -> int:
    org_id = resolve_caller_org(principal.org_id, organization_id)
    if org_id is None:
        raise HTTPException(status_code=422, detail="organization_id is required")
    return org_id


def _link_url(request: Request, token: str) -> str:
    return f"{request.base_url}portal/request?link={token}"


# ── admin API ──────────────────────────────────────────────────────────────


class LinkIn(BaseModel):
    organization_id: int | None = None
    system_ids: list[int]
    label: str | None = Field(default=None, max_length=255)


@admin_router.post("/request-links")
async def create_request_link(
    body: LinkIn,
    request: Request,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> dict[str, Any]:
    """Create a link agencies use to request access (CDS-TRC-SSM). The URL is
    shown once; only its hash is kept."""
    org_id = _org(principal, body.organization_id)
    try:
        link, token = await req_service.create_link(
            session,
            org_id=org_id,
            system_ids=body.system_ids,
            label=body.label,
            actor=principal.email or "system",
        )
    except RequestError as exc:
        raise _http(exc) from exc
    await session.commit()
    return {"id": link.id, "url": _link_url(request, token), "system_ids": link.system_ids}


@admin_router.get("/request-links")
async def list_request_links(
    organization_id: int | None = None,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> list[dict[str, Any]]:
    links = await req_service.list_links(session, org_id=_org(principal, organization_id))
    return [
        {
            "id": x.id,
            "label": x.label,
            "system_ids": x.system_ids,
            "created_by": x.created_by,
            "created_at": x.created_at,
            "revoked_at": x.revoked_at,
            "revoked_by": x.revoked_by,
        }
        for x in links
    ]


@admin_router.post("/request-links/{link_id}/revoke")
async def revoke_request_link(
    link_id: int,
    organization_id: int | None = None,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> dict[str, Any]:
    try:
        await req_service.revoke_link(
            session,
            link_id,
            org_id=_org(principal, organization_id),
            actor=principal.email or "system",
        )
    except RequestError as exc:
        raise _http(exc) from exc
    await session.commit()
    return {"revoked": True}


@admin_router.get("/access-requests")
async def list_access_requests(
    organization_id: int | None = None,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> list[dict[str, Any]]:
    """Every agency request, with the CDS-UTC-AAD notice state of each denial
    (``due``, ``overdue``, ``filed``, ``filed_late``)."""
    rows = await req_service.list_requests(session, org_id=_org(principal, organization_id))
    today = _today()
    return [req_service.request_view(r, today) for r in rows]


class ApproveIn(BaseModel):
    #: Required: Concord will not choose how long an agency's access lasts.
    ttl_days: int
    system_ids: list[int] | None = None


class DenyIn(BaseModel):
    reason: str = Field(max_length=4000)


class NoticeIn(BaseModel):
    notified_on: date
    reference: str = Field(max_length=255)


async def _decide(
    session: AsyncSession, principal: Principal, organization_id: int | None, action: Any
) -> dict[str, Any]:
    try:
        req = await action(_org(principal, organization_id), principal.email or "system")
    except RequestError as exc:
        raise _http(exc) from exc
    await session.commit()
    return req_service.request_view(req, _today())


@admin_router.post("/access-requests/{req_id}/approve")
async def approve_access_request(
    req_id: int,
    body: ApproveIn,
    organization_id: int | None = None,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> dict[str, Any]:
    """Approve. The agency then claims access with its receipt."""
    return await _decide(
        session,
        principal,
        organization_id,
        lambda org, actor: req_service.approve(
            session,
            req_id,
            org_id=org,
            actor=actor,
            ttl_days=body.ttl_days,
            system_ids=body.system_ids,
        ),
    )


@admin_router.post("/access-requests/{req_id}/deny")
async def deny_access_request(
    req_id: int,
    body: DenyIn,
    organization_id: int | None = None,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> dict[str, Any]:
    """Deny, with a reason. Starts the CDS-UTC-AAD FedRAMP notice clock."""
    return await _decide(
        session,
        principal,
        organization_id,
        lambda org, actor: req_service.deny(
            session, req_id, org_id=org, actor=actor, reason=body.reason
        ),
    )


@admin_router.post("/access-requests/{req_id}/fedramp-notice")
async def record_fedramp_notice(
    req_id: int,
    body: NoticeIn,
    organization_id: int | None = None,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> dict[str, Any]:
    """Record that FedRAMP was notified of a denial, and the reference."""
    return await _decide(
        session,
        principal,
        organization_id,
        lambda org, actor: req_service.record_notice(
            session,
            req_id,
            org_id=org,
            actor=actor,
            notified_on=body.notified_on,
            reference=body.reference,
        ),
    )


# ── the agency's API ───────────────────────────────────────────────────────


class SubmitIn(BaseModel):
    link: str = Field(max_length=128)
    agency_name: str = Field(max_length=255)
    requester_name: str = Field(max_length=255)
    email: str = Field(max_length=320)
    reason: str | None = Field(default=None, max_length=4000)
    system_ids: list[int] = Field(default_factory=list, max_length=100)


class ReceiptIn(BaseModel):
    receipt: str = Field(max_length=128)


@public_router.post("/access-requests", status_code=201)
@limiter.limit(_PUBLIC_LIMIT)
async def submit_access_request(
    request: Request,
    body: SubmitIn,
    response: Response,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """An agency requests access through a published request link. The
    ``receipt`` is shown once: it is how the agency checks the decision and
    claims access."""
    try:
        req, receipt = await req_service.submit(
            session,
            link_token=body.link,
            agency_name=body.agency_name,
            requester_name=body.requester_name,
            email=body.email,
            reason=body.reason,
            system_ids=body.system_ids,
        )
    except RequestError as exc:
        raise _http(exc) from exc
    await session.commit()
    response.headers.update(_NO_STORE)
    return {"receipt": receipt, "status": req.status}


@public_router.post("/access-requests/status")
@limiter.limit(_PUBLIC_LIMIT)
async def access_request_status(
    request: Request, body: ReceiptIn, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    req = await req_service.by_receipt(session, body.receipt)
    if req is None:
        raise HTTPException(status_code=404, detail="receipt not recognised")
    return req_service.receipt_view(req)


@public_router.post("/access-requests/claim")
@limiter.limit(_PUBLIC_LIMIT)
async def claim_access(
    request: Request,
    body: ReceiptIn,
    response: Response,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Issue the approved access, once. The token is shown here and never again."""
    try:
        grant = await req_service.claim(session, body.receipt)
    except RequestError as exc:
        raise _http(exc) from exc
    token = grant.token
    await session.commit()
    response.headers.update(_NO_STORE)
    return {
        "token": token,
        "portal_url": f"{request.base_url}portal?token={token}",
        "expires_at": grant.expires_at,
    }


# ── the agency's pages ─────────────────────────────────────────────────────


async def _system_names(session: AsyncSession, ids: list[int]) -> dict[int, str]:
    rows = (await session.execute(select(System.id, System.name).where(System.id.in_(ids)))).all()
    return {int(r.id): str(r.name) for r in rows}


def _page(request: Request, **ctx: Any) -> HTMLResponse:
    base: dict[str, Any] = {
        "mode": "form",
        "link": "",
        "systems": {},
        "error": None,
        "receipt": None,
        "view": None,
        "portal_url": None,
    }
    # Receipts, request links and tokens appear on these pages exactly once.
    return templates.TemplateResponse(
        request, "portal_request.html", {**base, **ctx}, headers=_NO_STORE
    )


@ui_router.get("/portal/request", response_class=HTMLResponse)
async def request_page(
    request: Request, link: str = "", session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    found = await req_service.resolve_link(session, link)
    if found is None:
        return _page(request, mode="invalid")
    return _page(request, link=link, systems=await _system_names(session, found.system_ids))


@ui_router.post("/portal/request", response_class=HTMLResponse)
@limiter.limit(_PUBLIC_LIMIT)
async def request_submit(
    request: Request,
    *,
    link: str = Form(..., max_length=128),
    agency_name: str = Form("", max_length=255),
    requester_name: str = Form("", max_length=255),
    email: str = Form("", max_length=320),
    reason: str = Form("", max_length=4000),
    system_ids: list[int] = Form(default=[]),
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    try:
        req, receipt = await req_service.submit(
            session,
            link_token=link,
            agency_name=agency_name,
            requester_name=requester_name,
            email=email,
            reason=reason,
            system_ids=system_ids,
        )
    except RequestError as exc:
        found = await req_service.resolve_link(session, link)
        if found is None:
            return _page(request, mode="invalid")
        return _page(
            request,
            link=link,
            error=str(exc),
            systems=await _system_names(session, found.system_ids),
        )
    await session.commit()
    return _page(request, mode="submitted", receipt=receipt, view=req_service.receipt_view(req))


@ui_router.get("/portal/request/status", response_class=HTMLResponse)
async def status_page(request: Request) -> HTMLResponse:
    return _page(request, mode="status")


@ui_router.post("/portal/request/status", response_class=HTMLResponse)
@limiter.limit(_PUBLIC_LIMIT)
async def status_lookup(
    request: Request,
    receipt: str = Form(..., max_length=128),
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    req = await req_service.by_receipt(session, receipt)
    if req is None:
        return _page(request, mode="status", error="That receipt is not recognised.")
    # The receipt goes back into the page only as a hidden form field, never a URL.
    return _page(request, mode="status", receipt=receipt, view=req_service.receipt_view(req))


@ui_router.post("/portal/request/claim", response_class=HTMLResponse)
@limiter.limit(_PUBLIC_LIMIT)
async def claim_page(
    request: Request,
    receipt: str = Form(..., max_length=128),
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    try:
        grant = await req_service.claim(session, receipt)
    except RequestError as exc:
        return _page(request, mode="status", error=str(exc))
    token = grant.token
    await session.commit()
    return _page(request, mode="claimed", portal_url=f"{request.base_url}portal?token={token}")


# ── portal-admin page forms ────────────────────────────────────────────────


def _ui_principal_org(request: Request) -> int | None:
    principal = getattr(request.state, "principal", None)
    return getattr(principal, "org_id", None) if principal is not None else None


def _ui_actor(request: Request) -> str:
    principal = getattr(request.state, "principal", None)
    return getattr(principal, "email", None) or "user"


def _ui_org(request: Request, organization_id: int) -> int:
    """The admin-API gate, for the page's form posts.

    The auth gate refuses only viewers on ``/admin/*`` form posts, so without
    this an editor could approve an agency's access the API would refuse them.
    """
    principal = getattr(request.state, "principal", None)
    if principal is not None and not principal.is_global and principal.role != "admin":
        raise HTTPException(status_code=403, detail="requires role: admin")
    org = resolve_caller_org(_ui_principal_org(request), organization_id)
    return int(org)


def _back(org_id: int) -> RedirectResponse:
    return RedirectResponse(f"/admin/portal?organization_id={org_id}#access-requests", 303)


async def _ui_act(session: AsyncSession, org_id: int, action: Any) -> RedirectResponse:
    try:
        await action()
    except RequestError as exc:
        raise _http(exc) from exc
    await session.commit()
    return _back(org_id)


@ui_router.post("/admin/portal/request-links", response_class=HTMLResponse)
async def ui_create_link(
    request: Request,
    *,
    organization_id: int = Form(...),
    label: str = Form("", max_length=255),
    system_ids: list[int] = Form(default=[]),
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    from .ui import templates as ui_templates  # noqa: PLC0415 — the app shell's environment
    from .ui_grc import _portal_admin_context  # noqa: PLC0415

    org = _ui_org(request, organization_id)
    try:
        _, token = await req_service.create_link(
            session,
            org_id=org,
            system_ids=system_ids,
            label=label or None,
            actor=_ui_actor(request),
        )
    except RequestError as exc:
        raise _http(exc) from exc
    await session.commit()
    # Rendered directly, never redirected: the link token must not sit in a URL
    # the browser history or an access log keeps.
    context = await _portal_admin_context(request, session, org)
    context["issued_request_link"] = _link_url(request, token)
    return ui_templates.TemplateResponse(request, "portal_admin.html", context, headers=_NO_STORE)


@ui_router.post("/admin/portal/request-links/{link_id}/revoke")
async def ui_revoke_link(
    request: Request,
    link_id: int,
    organization_id: int = Form(...),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    org = _ui_org(request, organization_id)
    return await _ui_act(
        session,
        org,
        lambda: req_service.revoke_link(session, link_id, org_id=org, actor=_ui_actor(request)),
    )


@ui_router.post("/admin/portal/access-requests/{req_id}/approve")
async def ui_approve(
    request: Request,
    req_id: int,
    organization_id: int = Form(...),
    ttl_days: int = Form(...),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    org = _ui_org(request, organization_id)
    return await _ui_act(
        session,
        org,
        lambda: req_service.approve(
            session, req_id, org_id=org, actor=_ui_actor(request), ttl_days=ttl_days
        ),
    )


@ui_router.post("/admin/portal/access-requests/{req_id}/deny")
async def ui_deny(
    request: Request,
    req_id: int,
    organization_id: int = Form(...),
    reason: str = Form("", max_length=4000),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    org = _ui_org(request, organization_id)
    return await _ui_act(
        session,
        org,
        lambda: req_service.deny(
            session, req_id, org_id=org, actor=_ui_actor(request), reason=reason
        ),
    )


@ui_router.post("/admin/portal/access-requests/{req_id}/fedramp-notice")
async def ui_notice(
    request: Request,
    req_id: int,
    *,
    organization_id: int = Form(...),
    notified_on: date = Form(...),
    reference: str = Form("", max_length=255),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    org = _ui_org(request, organization_id)
    return await _ui_act(
        session,
        org,
        lambda: req_service.record_notice(
            session,
            req_id,
            org_id=org,
            actor=_ui_actor(request),
            notified_on=notified_on,
            reference=reference,
        ),
    )
