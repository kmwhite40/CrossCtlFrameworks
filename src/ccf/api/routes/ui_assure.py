"""Pages for the GRC program build-out.

Spec: docs/superpowers/specs/2026-10-20-grc-buildout-design.md (section H).

* ``/controls/effectiveness`` (``ctrl_eff``) -- the effectiveness rating, its
  rule stated on the page.
* ``/evidence/mapping`` (``evidence_map``) -- controls x evidence, and gaps.
* ``/evidence/expiration`` (``evidence_exp``) -- expiring evidence; request a
  renewal task (admin, control_owner), one per object.
* ``/integrations`` (``integrations``) -- connectors, webhooks, sign-in and
  issue-tracker links. Webhooks are created through the existing writer in
  ``api/routes/events.py`` (admin only here), never a second one.

The computations live in ``ccf.analytics.assurance_views``; every query there
carries its own organization predicate.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...analytics import assurance_views as av
from ...auth import Principal
from ...models import Webhook
from ..audit import record_event
from ..auth_deps import require_role
from ..deps import get_session
from . import events
from .ui import _principal_org, templates

router = APIRouter(include_in_schema=False)


def _render(request: Request, template: str, active: str, **ctx: Any) -> HTMLResponse:
    return templates.TemplateResponse(request, template, {"active": active, **ctx})


def _int_or_none(raw: str | None) -> int | None:
    """Query filters arrive as strings (an empty select option is ``""``)."""
    try:
        return int(raw) if raw else None
    except ValueError:
        return None


def _may(request: Request, *roles: str) -> bool:
    """Whether to offer a form the route behind it would accept (mirrors
    ``require_role``: a global principal, or auth off, passes)."""
    principal = getattr(request.state, "principal", None)
    if principal is None or getattr(principal, "is_global", False):
        return True
    return getattr(principal, "role", None) in roles


# ── Control effectiveness ───────────────────────────────────────────────────


@router.get("/controls/effectiveness", response_class=HTMLResponse)
async def control_effectiveness_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    system_id: str | None = Query(None, max_length=12),
    family: str | None = Query(None, max_length=16),
) -> HTMLResponse:
    sid = _int_or_none(system_id)
    view = await av.control_effectiveness(
        session, _principal_org(request), system_id=sid, family=family or None
    )
    return _render(
        request,
        "control_effectiveness.html",
        "ctrl_eff",
        view=view,
        system_id=sid,
        family=(family or "").upper(),
        labels={
            av.EFFECTIVE: "Effective",
            av.INEFFECTIVE: "Ineffective",
            av.NOT_DETERMINED: "Not determined",
        },
        methods=av.AUTOMATED_METHODS,
    )


# ── Evidence-to-control mapping ─────────────────────────────────────────────


@router.get("/evidence/mapping", response_class=HTMLResponse)
async def evidence_mapping_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    system_id: str | None = Query(None, max_length=12),
) -> HTMLResponse:
    sid = _int_or_none(system_id)
    view = await av.evidence_mapping(session, _principal_org(request), system_id=sid)
    return _render(request, "evidence_map.html", "evidence_map", view=view, system_id=sid)


# ── Evidence expiration ─────────────────────────────────────────────────────


@router.get("/evidence/expiration", response_class=HTMLResponse)
async def evidence_expiration_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    requested: str | None = Query(None, max_length=8),
) -> HTMLResponse:
    view = await av.evidence_expiration(session, _principal_org(request), today=date.today())
    return _render(
        request,
        "evidence_expiration.html",
        "evidence_exp",
        view=view,
        can_request=_may(request, "admin", "control_owner"),
        requested=requested if requested in ("new", "open") else None,
    )


@router.post("/evidence/expiration/{obj_id}/renew")
async def evidence_request_renewal(
    obj_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "control_owner")),
) -> RedirectResponse:
    """Open the renewal task for one evidence object, or keep the open one."""
    try:
        task, created = await av.request_renewal(
            session, obj_id=obj_id, principal_org=principal.org_id
        )
    except av.EvidenceNotFoundError:
        raise HTTPException(404, "evidence object not found") from None
    except av.UnassignableError:
        raise HTTPException(
            409, "this evidence object belongs to no organization, so no task can hold it"
        ) from None
    if created:
        await record_event(
            session,
            actor=principal.email or "system",
            action="create",
            entity_type="task",
            entity_id=str(task.id),
            diff={
                "event": "evidence_renewal_requested",
                "evidence_object_id": obj_id,
                "assignee_user_id": task.assignee_user_id,
            },
            organization_id=task.organization_id,
        )
    await session.commit()
    return RedirectResponse(
        f"/evidence/expiration?requested={'new' if created else 'open'}#ev-{obj_id}",
        status_code=303,
    )


# ── Integrations hub ────────────────────────────────────────────────────────


@router.get("/integrations", response_class=HTMLResponse)
async def integrations_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    view = await av.integrations_hub(session, _principal_org(request))
    return _render(
        request, "integrations.html", "integrations", view=view, is_admin=_may(request, "admin")
    )


@router.post("/integrations/webhooks")
async def integrations_create_webhook(
    url: str = Form(..., max_length=1024),
    secret: str = Form("", max_length=128),
    subscribed: str = Form("", max_length=1024),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> RedirectResponse:
    """Admin only. The row is written by ``events.create_webhook`` -- the API's
    own writer -- so the page and ``POST /api/webhooks`` cannot diverge.

    Refused without an organization: a webhook with a NULL organization
    receives every tenant's events (``governance.bus._dispatch_webhooks``)."""
    if principal.org_id is None:
        raise HTTPException(
            400, "a webhook belongs to one organization; sign in as that organization's admin"
        )
    if not url.strip():
        raise HTTPException(422, "a webhook needs a URL")
    created = await events.create_webhook(
        events.WebhookIn(
            url=url.strip(),
            secret=secret or None,
            events=[e.strip() for e in subscribed.split(",") if e.strip()],
            active=True,
        ),
        session=session,
        principal=principal,
    )
    await record_event(
        session,
        actor=principal.email or "admin",
        action="create",
        entity_type="webhook",
        entity_id=str(created["id"]),
        # Never the secret: whether one was set is all the record needs.
        diff={"url": created["url"], "signed": bool(secret)},
        organization_id=principal.org_id,
    )
    await session.commit()
    return RedirectResponse("/integrations#webhooks", status_code=303)


@router.post("/integrations/webhooks/{webhook_id}/disable")
async def integrations_disable_webhook(
    webhook_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> RedirectResponse:
    """Stop delivery without deleting the subscription (admin only)."""
    stmt = select(Webhook).where(Webhook.id == webhook_id)
    if principal.org_id is not None:
        stmt = stmt.where(Webhook.organization_id == principal.org_id)
    hook = (await session.execute(stmt)).scalar_one_or_none()
    if hook is None:
        raise HTTPException(404, "webhook not found")
    if hook.active:
        hook.active = False
        await record_event(
            session,
            actor=principal.email or "admin",
            action="update",
            entity_type="webhook",
            entity_id=str(hook.id),
            diff={"active": [True, False]},
            organization_id=hook.organization_id,
        )
        await session.commit()
    return RedirectResponse("/integrations#webhooks", status_code=303)
