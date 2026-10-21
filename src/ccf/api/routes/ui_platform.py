"""Platform administration and governed AI pages.

Spec: docs/superpowers/specs/2026-10-20-grc-buildout-design.md, section F.

* ``/settings/api-tokens`` -- rotate or revoke your own API token; an
  administrator revokes the tokens of users in their own organization.
* ``/admin/rbac`` -- the permission matrix read from the live routes
  (``ccf.governance.rbac_matrix``), and IdP group-to-role mappings.
* ``/ai/analysis`` -- the governed AI actions: start a run on a record of your
  organization, read its draft and citations. Nothing on this page applies an
  output to a record; that happens only on approval through the review queue.

Registered in ``ccf.api.main``.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ...ai_actions import ACTIONS, run_action
from ...ai_actions.service import AiActionError
from ...analytics.posture import org_system_subq
from ...auth import Principal, new_api_token
from ...config import get_settings
from ...governance import rbac_matrix
from ...identity.provisioning import VALID_ROLES
from ...models import POAM, Control, ControlImplementation, Policy, Risk, System, User, Vendor
from ...models_ai_actions import AiActionReview, AiActionRun, AiProviderConfig
from ...models_evidence import EvidenceObject
from ...models_identity import GroupRoleMapping
from ..audit import record_event
from ..auth_deps import get_principal, require_role
from ..deps import get_session
from .ui import templates

router = APIRouter(include_in_schema=False)

#: The roles that may hold and manage their own API token from this page.
#: Viewers are also refused by the auth gate before any of this runs; this
#: is the route's own gate, so the refusal does not rest on the middleware.
_SELF_SERVICE_ROLES = ("admin", "control_owner", "assessor")


def _no_store(resp: Response) -> Response:
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"
    return resp


def _redirect(path: str, error: str | None = None) -> RedirectResponse:
    if error:
        path = f"{path}?error={quote(error)}"
    return RedirectResponse(path, status_code=303)


# ── API tokens ───────────────────────────────────────────────────────────────


async def _own_user(session: AsyncSession, principal: Principal) -> User | None:
    """The caller's own user row, in the caller's own organization."""
    if principal.user_id is None:
        return None
    stmt = select(User).where(User.id == principal.user_id)
    if principal.org_id is not None:
        stmt = stmt.where(User.organization_id == principal.org_id)
    return (await session.execute(stmt)).scalar_one_or_none()


async def _token_holders(session: AsyncSession, principal: Principal) -> list[User]:
    """Users holding an API token, in the admin's organization only."""
    stmt = select(User).where(User.api_token_hash.is_not(None)).order_by(User.email)
    if principal.org_id is not None:
        stmt = stmt.where(User.organization_id == principal.org_id)
    return list((await session.execute(stmt)).scalars().all())


async def _render_tokens(
    request: Request,
    session: AsyncSession,
    principal: Principal,
    *,
    issued: str | None = None,
) -> Response:
    me = await _own_user(session, principal)
    is_admin = principal.is_global or principal.role == "admin"
    holders = await _token_holders(session, principal) if is_admin else []
    resp = templates.TemplateResponse(
        request,
        "api_tokens.html",
        {
            "active": "apitokens",
            "me": me,
            "may_manage_own": me is not None and principal.role in _SELF_SERVICE_ROLES,
            "is_viewer": principal.role == "viewer" and not principal.is_global,
            "is_admin": is_admin,
            "scoped": principal.org_id is not None,
            "holders": holders,
            "issued": issued,
            "notice": request.query_params.get("notice"),
        },
    )
    return _no_store(resp)


@router.get("/settings/api-tokens", response_class=HTMLResponse)
async def api_tokens_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> Response:
    return await _render_tokens(request, session, principal)


@router.post("/settings/api-tokens/rotate", response_class=HTMLResponse)
async def api_token_rotate(
    request: Request,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "control_owner", "assessor")),
) -> Response:
    """Issue a new token for the caller, replacing any old one.

    The one form on these pages that answers 200 rather than 303: the new
    token is rendered in this response and nowhere else. A redirect would
    have to carry it in a URL, a cookie or a server-side store, each of which
    keeps it beyond the one display. The response is ``no-store``.
    """
    me = await _own_user(session, principal)
    if me is None:
        raise HTTPException(400, "this session has no user account to hold a token")
    token = new_api_token()
    me.api_token = token  # persists sha256(token) in api_token_hash, never the token
    await record_event(
        session,
        actor=principal.email,
        action="update",
        entity_type="api_token",
        entity_id=str(me.id),
        diff={"change": "rotated", "user": me.email},
        organization_id=me.organization_id,
    )
    await session.commit()
    return await _render_tokens(request, session, principal, issued=token)


@router.post("/settings/api-tokens/revoke")
async def api_token_revoke_own(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "control_owner", "assessor")),
) -> RedirectResponse:
    me = await _own_user(session, principal)
    if me is None:
        raise HTTPException(400, "this session has no user account to hold a token")
    had = me.api_token_hash is not None
    me.api_token = None
    await record_event(
        session,
        actor=principal.email,
        action="update",
        entity_type="api_token",
        entity_id=str(me.id),
        diff={"change": "revoked", "user": me.email, "held": had},
        organization_id=me.organization_id,
    )
    await session.commit()
    return RedirectResponse("/settings/api-tokens?notice=revoked", status_code=303)


@router.post("/settings/api-tokens/users/{user_id}/revoke")
async def api_token_revoke_user(
    user_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> RedirectResponse:
    """An administrator revokes another user's token -- in their own org only.

    Another organization's user is a 404, not a 403: confirming that the id
    exists elsewhere is itself a disclosure.
    """
    stmt = select(User).where(User.id == user_id)
    if principal.org_id is not None:
        stmt = stmt.where(User.organization_id == principal.org_id)
    target = (await session.execute(stmt)).scalar_one_or_none()
    if target is None:
        raise HTTPException(404, "user not found")
    had = target.api_token_hash is not None
    target.api_token = None
    await record_event(
        session,
        actor=principal.email,
        action="update",
        entity_type="api_token",
        entity_id=str(target.id),
        diff={"change": "revoked_by_admin", "user": target.email, "held": had},
        organization_id=target.organization_id,
    )
    await session.commit()
    return RedirectResponse("/settings/api-tokens?notice=revoked-user", status_code=303)


# ── RBAC matrix + group-to-role mappings ─────────────────────────────────────


async def _mappings(session: AsyncSession, principal: Principal) -> list[GroupRoleMapping]:
    stmt = select(GroupRoleMapping).order_by(GroupRoleMapping.priority, GroupRoleMapping.id)
    if principal.org_id is not None:
        stmt = stmt.where(GroupRoleMapping.organization_id == principal.org_id)
    return list((await session.execute(stmt)).scalars().all())


@router.get("/admin/rbac", response_class=HTMLResponse)
async def rbac_page(
    request: Request,
    *,
    q: str = "",
    method: str = "",
    gate: str = "",
    role: str = "",
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> HTMLResponse:
    rows = rbac_matrix.route_matrix(request.app)
    summary = rbac_matrix.summarize(rows)
    shown = [
        r
        for r in rows
        if (not q or q.lower() in r.path.lower())
        and (not method or r.method == method.upper())
        and (not gate or r.gate == gate)
        and (not role or r.admits.get(role))
    ]
    return templates.TemplateResponse(
        request,
        "rbac.html",
        {
            "active": "rbac",
            "rows": shown,
            "summary": summary,
            "roles": rbac_matrix.ROLES,
            "gates": rbac_matrix.GATES,
            "gate_labels": rbac_matrix.GATE_LABELS,
            "methods": sorted({r.method for r in rows}),
            "filters": {"q": q, "method": method, "gate": gate, "role": role},
            "mappings": await _mappings(session, principal),
            "has_org": principal.org_id is not None,
            "error": request.query_params.get("error"),
        },
    )


def _org_required(principal: Principal) -> int:
    """Mappings are per organization; a global principal names none."""
    if principal.org_id is None:
        raise HTTPException(400, "organization context required to edit group mappings")
    return principal.org_id


@router.post("/admin/rbac/mappings")
async def rbac_mapping_create(
    group: str = Form(...),
    role: str = Form(...),
    priority: int = Form(100),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> RedirectResponse:
    org = _org_required(principal)
    group = group.strip()
    if not group:
        return _redirect("/admin/rbac", "the IdP group is required")
    if role not in VALID_ROLES:
        raise HTTPException(422, "invalid role")
    m = GroupRoleMapping(organization_id=org, group=group, role=role, priority=priority)
    session.add(m)
    try:
        await session.flush()
    except IntegrityError:
        await session.rollback()
        return _redirect("/admin/rbac", f"the group {group!r} is already mapped")
    await record_event(
        session,
        actor=principal.email,
        action="create",
        entity_type="group_role_mapping",
        entity_id=str(m.id),
        diff={"group": group, "role": role, "priority": priority},
        organization_id=org,
    )
    await session.commit()
    return RedirectResponse("/admin/rbac#mappings", status_code=303)


@router.post("/admin/rbac/mappings/{mapping_id}/delete")
async def rbac_mapping_delete(
    mapping_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> RedirectResponse:
    org = _org_required(principal)
    m = (
        await session.execute(
            select(GroupRoleMapping).where(
                GroupRoleMapping.id == mapping_id, GroupRoleMapping.organization_id == org
            )
        )
    ).scalar_one_or_none()
    if m is None:
        raise HTTPException(404, "mapping not found")
    await record_event(
        session,
        actor=principal.email,
        action="delete",
        entity_type="group_role_mapping",
        entity_id=str(m.id),
        diff={"group": m.group, "role": m.role},
        organization_id=org,
    )
    await session.delete(m)
    await session.commit()
    return RedirectResponse("/admin/rbac#mappings", status_code=303)


# ── Governed AI analysis ─────────────────────────────────────────────────────

#: Entity types this page will start a run on, each with an ownership
#: predicate below. ``run_action``'s own cross-tenant guard reads the owner
#: through the record's system, so a risk with no system has no owner to
#: compare and is refused by nothing; the page checks ownership itself first.
_TARGET_TYPES = ("system", "poam", "risk", "control", "vendor", "policy", "evidence_object")
_TARGET_LABELS = {
    "system": "Systems",
    "poam": "POA&Ms",
    "risk": "Risks",
    "control": "Control implementations",
    "vendor": "Vendors",
    "policy": "Policies",
    "evidence_object": "Evidence",
}
_ID_COLUMN = {
    "system": System.id,
    "poam": POAM.id,
    "risk": Risk.id,
    "control": ControlImplementation.id,
    "vendor": Vendor.id,
    "policy": Policy.id,
    "evidence_object": EvidenceObject.id,
}
_PICKER_LIMIT = 100
_RUN_ROLES = ("admin", "control_owner", "assessor")


def _target_stmt(entity_type: str, org: int) -> Any:  # noqa: PLR0911 — one per type
    """``(id, label)`` rows of ``entity_type`` owned by ``org``, live systems only."""
    live = org_system_subq(org)
    if entity_type == "system":
        return select(System.id, System.name).where(
            System.organization_id == org, System.deleted_at.is_(None)
        )
    if entity_type == "poam":
        return select(POAM.id, POAM.title).where(POAM.system_id.in_(live))
    if entity_type == "risk":
        return select(Risk.id, Risk.title).where(Risk.system_id.in_(live))
    if entity_type == "control":
        return (
            select(ControlImplementation.id, Control.identifier + " on " + System.name)
            .join(Control, Control.id == ControlImplementation.control_id)
            .join(System, System.id == ControlImplementation.system_id)
            .where(ControlImplementation.system_id.in_(live))
        )
    if entity_type == "vendor":
        return select(Vendor.id, Vendor.name).where(Vendor.organization_id == org)
    if entity_type == "policy":
        return select(Policy.id, Policy.name).where(Policy.organization_id == org)
    if entity_type == "evidence_object":
        return select(EvidenceObject.id, EvidenceObject.title).where(
            EvidenceObject.organization_id == org
        )
    raise ValueError(entity_type)


async def _target_visible(
    session: AsyncSession, org: int, entity_type: str, entity_id: int
) -> bool:
    stmt = _target_stmt(entity_type, org).where(_ID_COLUMN[entity_type] == entity_id)
    return (await session.execute(stmt.limit(1))).first() is not None


async def _picker(session: AsyncSession, org: int) -> list[dict[str, Any]]:
    groups = []
    for t in _TARGET_TYPES:
        stmt = _target_stmt(t, org).order_by(_ID_COLUMN[t].desc()).limit(_PICKER_LIMIT)
        rows = [(i, label) for i, label in (await session.execute(stmt)).all()]
        groups.append({"type": t, "label": _TARGET_LABELS[t], "rows": rows})
    return groups


async def _provider_configured(session: AsyncSession, org: int) -> bool:
    """An enabled provider with a stored credential -- what the gateway resolves."""
    stmt = select(AiProviderConfig.id).where(
        AiProviderConfig.organization_id == org,
        AiProviderConfig.enabled.is_(True),
        AiProviderConfig.encrypted_credential.is_not(None),
    )
    return (await session.execute(stmt.limit(1))).first() is not None


def _actions() -> list[Any]:
    """Actions this page can start: those accepting a type it can verify."""
    return [a for a in ACTIONS.values() if set(a.input_entity_types) & set(_TARGET_TYPES)]


async def _org_runs(session: AsyncSession, org: int) -> list[AiActionRun]:
    stmt = (
        select(AiActionRun)
        .where(AiActionRun.organization_id == org)
        .order_by(AiActionRun.id.desc())
        .limit(50)
    )
    return list((await session.execute(stmt)).scalars().all())


async def _org_run(session: AsyncSession, org: int, run_id: int) -> AiActionRun | None:
    stmt = (
        select(AiActionRun)
        .options(selectinload(AiActionRun.outputs), selectinload(AiActionRun.citations))
        .where(AiActionRun.id == run_id, AiActionRun.organization_id == org)
    )
    return (await session.execute(stmt)).scalar_one_or_none()


@router.get("/ai/analysis", response_class=HTMLResponse)
async def ai_analysis_page(
    request: Request,
    run: int | None = None,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> HTMLResponse:
    org = principal.org_id
    runs: list[AiActionRun] = []
    selected: AiActionRun | None = None
    reviews: list[AiActionReview] = []
    picker: list[dict[str, Any]] = []
    configured = False
    may_run = org is not None and principal.role in _RUN_ROLES
    if org is not None:
        configured = await _provider_configured(session, org)
        runs = await _org_runs(session, org)
        if run is not None:
            selected = await _org_run(session, org, run)
            if selected is None:
                raise HTTPException(404, "run not found")
            stmt = (
                select(AiActionReview)
                .where(AiActionReview.run_id == selected.id)
                .order_by(AiActionReview.id)
            )
            reviews = list((await session.execute(stmt)).scalars().all())
        if may_run:
            picker = await _picker(session, org)
    return templates.TemplateResponse(
        request,
        "ai_analysis.html",
        {
            "active": "ai_analysis",
            "has_org": org is not None,
            "configured": configured,
            "is_admin": principal.is_global or principal.role == "admin",
            "may_run": may_run,
            "actions": _actions(),
            "approval_forced": bool(get_settings().ai_require_human_approval),
            "picker": picker,
            "runs": runs,
            "selected": selected,
            "reviews": reviews,
            "error": request.query_params.get("error"),
        },
    )


@router.post("/ai/analysis/run")
async def ai_analysis_run(
    action_key: str = Form(...),
    target: str = Form(...),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "control_owner", "assessor")),
) -> RedirectResponse:
    """Start a run and show its draft. Never approves it, so never applies it."""
    org = principal.org_id
    if org is None:
        # A run written without an organization has a NULL org, which RLS
        # publishes to every tenant.
        raise HTTPException(400, "organization context required to start an AI run")
    action = ACTIONS.get(action_key)
    if action is None:
        raise HTTPException(422, "unknown action")
    entity_type, _, raw_id = target.partition(":")
    if entity_type not in _TARGET_TYPES or not raw_id.isdigit():
        raise HTTPException(422, "choose a record from the list")
    if entity_type not in action.input_entity_types:
        accepts = ", ".join(action.input_entity_types)
        return _redirect(
            "/ai/analysis", f"{action.title} accepts {accepts}; it cannot run on {entity_type}"
        )
    if not await _target_visible(session, org, entity_type, int(raw_id)):
        raise HTTPException(404, "record not found")
    try:
        new_run = await run_action(
            session,
            action_key=action_key,
            entity_type=entity_type,
            entity_id=raw_id,
            org_id=org,
            actor=principal.email,
        )
    except AiActionError as exc:
        await session.commit()  # keep any guardrail violation recorded before the raise
        return _redirect("/ai/analysis", str(exc))
    await session.commit()
    return RedirectResponse(f"/ai/analysis?run={new_run.id}", status_code=303)
