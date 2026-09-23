"""Enterprise identity routes — OIDC SSO login, admin IdP/mappings, SCIM.

The browser SSO flow (`/auth/login` → IdP → `/auth/callback`) and the SCIM
provisioning API (`/api/scim/v2/*`, authenticated by `CCF_SCIM_BEARER_TOKEN`) are
public to the user-session gate but individually guarded. With OIDC disabled the
login route falls back to the local `/login` form, so dev needs no IdP.
"""

from __future__ import annotations

import hmac
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal, sign_session
from ...config import get_settings, is_dev_env
from ...identity import provisioning
from ...identity.oidc import authorization_url, exchange_code, new_state
from ...models import Organization, User
from ...models_identity import GroupRoleMapping, IdentityProvider
from ..auth_deps import SESSION_COOKIE, get_principal, require_role
from ..deps import get_session
from ..login_service import revoke_sessions_for_request

router = APIRouter(tags=["identity"])

_STATE_COOKIE = "concord_oidc_state"


def _set_session_cookie(response: Response, user_id: int, session_version: int = 0) -> None:
    s = get_settings()
    token = sign_session(
        user_id,
        s.auth_session_secret,
        ttl_hours=s.auth_session_ttl_hours,
        session_version=session_version,
    )
    response.set_cookie(
        SESSION_COOKIE, token, max_age=s.auth_session_ttl_hours * 3600,
        httponly=True, samesite="lax", secure=not is_dev_env(s),
    )


async def _default_org_id(session: AsyncSession) -> int:
    """The oldest organization, created if the deployment has none.

    **Only the OIDC single-sign-on callback still uses this.** SCIM moved to
    ``_scim_target_org``, which refuses to guess when a deployment has several
    organizations, because a deployment-wide SCIM token names no tenant and
    guessing wrote real users into real tenants on no evidence.

    The SSO callback has the same ambiguity and is deliberately NOT changed
    here: it decides which organization a *person signing in* is provisioned
    into, so narrowing it is an authentication change that can lock users out
    of a working deployment, and it needs its own measurement of who currently
    lands where. Recorded rather than silently fixed -- the same split the
    live-capture change drew around control tests.
    """
    org = (
        await session.execute(select(Organization).order_by(Organization.id).limit(1))
    ).scalar_one_or_none()
    if org is None:
        org = Organization(name="Default Organization")
        session.add(org)
        await session.flush()
    return org.id


# --- OIDC browser flow -------------------------------------------------------


@router.get("/auth/login")
async def sso_login() -> RedirectResponse:
    """Start OIDC login, or fall back to the local login form when OIDC is off."""
    s = get_settings()
    if not s.oidc_enabled:
        return RedirectResponse("/login", status_code=303)
    try:
        state = new_state()
        url = await authorization_url(state)
    except Exception as e:
        raise HTTPException(503, "OIDC login is unavailable") from e
    resp = RedirectResponse(url, status_code=303)
    resp.set_cookie(
        _STATE_COOKIE, state, httponly=True, samesite="lax", max_age=600,
        secure=not is_dev_env(s),
    )
    return resp


@router.get("/auth/callback")
async def sso_callback(
    request: Request,
    code: str = "",
    state: str = "",
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    s = get_settings()
    if not s.oidc_enabled:
        return RedirectResponse("/login", status_code=303)
    if not code or state != request.cookies.get(_STATE_COOKIE):
        raise HTTPException(400, "invalid OIDC state or missing code")
    try:
        claims = await exchange_code(code)
    except Exception as e:
        raise HTTPException(502, "OIDC token exchange failed") from e
    org_id = await _default_org_id(session)
    try:
        user, _created = await provisioning.provision_from_oidc(
            session,
            claims=claims,
            org_id=org_id,
            allowed_domains=s.oidc_allowed_domains,
            jit=s.auth_jit_provisioning,
        )
    except provisioning.ProvisioningError as e:
        await session.rollback()
        raise HTTPException(403, str(e)) from e
    await session.commit()
    resp = RedirectResponse("/", status_code=303)
    resp.delete_cookie(_STATE_COOKIE)
    _set_session_cookie(resp, user.id, user.session_version or 0)
    return resp


@router.get("/auth/logout")
@router.post("/auth/logout")
async def sso_logout(
    request: Request, session: AsyncSession = Depends(get_session)
) -> RedirectResponse:
    # AC-12: revoke server-side as well as clearing the browser's cookie.
    await revoke_sessions_for_request(request, session)
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


# --- Admin: identity providers + group→role mappings -------------------------


class IdpIn(BaseModel):
    name: str
    issuer: str
    client_id: str | None = None
    enabled: bool = True
    default_role: str = "viewer"
    allowed_domains: list[str] = Field(default_factory=list)


class MappingIn(BaseModel):
    group: str
    role: str
    priority: int = 100


@router.get("/api/admin/idp")
async def list_idps(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> list[dict[str, Any]]:
    stmt = select(IdentityProvider).order_by(IdentityProvider.name)
    if principal.org_id is not None:
        stmt = stmt.where(IdentityProvider.organization_id == principal.org_id)
    return [
        {"id": p.id, "name": p.name, "issuer": p.issuer, "enabled": p.enabled,
         "default_role": p.default_role, "allowed_domains": p.allowed_domains}
        for p in (await session.execute(stmt)).scalars().all()
    ]


@router.post("/api/admin/idp", status_code=201)
async def create_idp(
    body: IdpIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> dict[str, Any]:
    if body.default_role not in provisioning.VALID_ROLES:
        raise HTTPException(422, "invalid default_role")
    p = IdentityProvider(organization_id=principal.org_id, **body.model_dump())
    session.add(p)
    await session.commit()
    return {"id": p.id, "name": p.name}


@router.get("/api/admin/group-role-mappings")
async def list_mappings(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> list[dict[str, Any]]:
    stmt = select(GroupRoleMapping).order_by(GroupRoleMapping.priority, GroupRoleMapping.id)
    if principal.org_id is not None:
        stmt = stmt.where(GroupRoleMapping.organization_id == principal.org_id)
    return [
        {"id": m.id, "group": m.group, "role": m.role, "priority": m.priority}
        for m in (await session.execute(stmt)).scalars().all()
    ]


@router.post("/api/admin/group-role-mappings", status_code=201)
async def create_mapping(
    body: MappingIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> dict[str, Any]:
    if body.role not in provisioning.VALID_ROLES:
        raise HTTPException(422, "invalid role")
    m = GroupRoleMapping(organization_id=principal.org_id, **body.model_dump())
    session.add(m)
    await session.commit()
    return {"id": m.id, "group": m.group, "role": m.role}


@router.delete("/api/admin/group-role-mappings/{mapping_id}", status_code=204)
async def delete_mapping(
    mapping_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> Response:
    m = await session.get(GroupRoleMapping, mapping_id)
    if m is not None and (principal.org_id is None or m.organization_id == principal.org_id):
        await session.delete(m)
        await session.commit()
    return Response(status_code=204)


# --- SCIM v2 -----------------------------------------------------------------


async def _scim_org(
    authorization: str = Header(default=""),
    session: AsyncSession = Depends(get_session),
) -> int:
    """Authorize a SCIM request and resolve the ONE organization it may touch.

    This used to authorize and then return ``None``, leaving each route to work
    out its own org -- which in practice meant the create path took the oldest
    organization and every other path took the org of whichever row the caller
    named. The token is deployment-wide and carries no tenant, and SCIM requests
    run with no principal, so ``get_session`` binds no tenant and RLS treats
    them as bypass. Nothing beneath these routes is scoped; the scope has to be
    decided here, once, and applied by every route.
    """
    s = get_settings()
    if not s.scim_enabled or not s.scim_bearer_token:
        raise HTTPException(404, "SCIM is not enabled")
    token = authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""
    # Constant-time comparison: this token authorizes full user provisioning
    # (create/update/deactivate/delete), so a short-circuiting ``!=`` would leak
    # it byte-by-byte to an attacker able to measure response latency.
    if not hmac.compare_digest(token, s.scim_bearer_token):
        raise HTTPException(401, "invalid SCIM token")
    return await _scim_target_org(session, s.scim_organization_id)


async def _scim_target_org(session: AsyncSession, configured: int | None) -> int:
    """The organization SCIM provisions into, or a refusal saying why it cannot.

    Three cases, and the third is the point:

    * **Configured** -- honour it, after checking it exists. A typo that
      silently fell back to some other tenant would be the same defect again.
    * **Exactly one organization** -- unambiguous, so no configuration needed;
      this keeps single-tenant and fresh deployments working as before, and a
      deployment with none gets one created as it always did.
    * **Several, none configured** -- refuse. Nothing in the request says which
      tenant the IdP behind this token represents, and provisioning a real user
      into a real tenant on a guess is not recoverable by the guesser. This is
      the rule ``ssp/seed.py`` already applies to a system with no baseline.
    """
    if configured is not None:
        org = await session.get(Organization, configured)
        if org is None:
            raise HTTPException(
                500,
                f"CCF_SCIM_ORGANIZATION_ID={configured} does not match any organization",
            )
        return org.id

    orgs = (
        await session.execute(select(Organization).order_by(Organization.id).limit(2))
    ).scalars().all()
    if len(orgs) == 1:
        return orgs[0].id
    if not orgs:
        org = Organization(name="Default Organization")
        session.add(org)
        await session.flush()
        return org.id
    raise HTTPException(
        500,
        "SCIM target organization is ambiguous: this deployment has more than one "
        "organization and CCF_SCIM_ORGANIZATION_ID is not set, so nothing in the "
        "request says which one this token provisions into",
    )


@router.get("/api/scim/v2/Users")
async def scim_list_users(
    org_id: int = Depends(_scim_org),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    users = (
        await session.execute(
            select(User).where(User.organization_id == org_id).order_by(User.id)
        )
    ).scalars().all()
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": len(users),
        "Resources": [provisioning.scim_user_resource(u) for u in users],
    }


@router.post("/api/scim/v2/Users", status_code=201)
async def scim_create_user(
    payload: dict[str, Any],
    org_id: int = Depends(_scim_org),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    try:
        user, _created = await provisioning.scim_create_or_update_user(
            session, org_id=org_id, payload=payload
        )
    except provisioning.ProvisioningConflictError as e:
        # SCIM's own answer for "this value already exists elsewhere".
        raise HTTPException(409, str(e)) from e
    except provisioning.ProvisioningError as e:
        raise HTTPException(400, str(e)) from e
    await session.commit()
    return provisioning.scim_user_resource(user)


@router.get("/api/scim/v2/Users/{user_id}")
async def scim_get_user(
    user_id: int,
    org_id: int = Depends(_scim_org),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    user = await _scim_user_in_org(session, user_id, org_id)
    return provisioning.scim_user_resource(user)


async def _scim_user_in_org(session: AsyncSession, user_id: int, org_id: int) -> User:
    """A user of ``org_id``, or 404 -- never a user of some other tenant.

    404 rather than 403 on purpose: to a token that may not touch this tenant,
    whether the id exists at all is not information to give back.
    """
    user = await session.get(User, user_id)
    if user is None or user.organization_id != org_id:
        raise HTTPException(404, "user not found")
    return user


def _scim_active(payload: dict[str, Any]) -> bool | None:
    """Extract the desired active flag from a SCIM PUT or PATCH body."""
    if "active" in payload:
        return bool(payload["active"])
    for op in payload.get("Operations", []):
        if isinstance(op, dict) and str(op.get("path", "")).lower() == "active":
            val = op.get("value")
            if isinstance(val, bool):
                return val
            if isinstance(val, str):
                return val.strip().lower() == "true"
    return None


@router.patch("/api/scim/v2/Users/{user_id}")
@router.put("/api/scim/v2/Users/{user_id}")
async def scim_update_user(
    user_id: int,
    payload: dict[str, Any],
    org_id: int = Depends(_scim_org),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    # The org comes from the token, not from the row: reading it off the target
    # user made the victim's own organization the authority for writing to it.
    user = await _scim_user_in_org(session, user_id, org_id)
    active = _scim_active(payload)
    if active is False:
        await provisioning.scim_deactivate_user(session, org_id=org_id, user=user)
    else:
        merged = {**payload, "userName": user.email}
        if active is True:
            merged["active"] = True
        await provisioning.scim_create_or_update_user(session, org_id=org_id, payload=merged)
    await session.commit()
    return provisioning.scim_user_resource(user)


@router.delete("/api/scim/v2/Users/{user_id}", status_code=204)
async def scim_delete_user(
    user_id: int,
    org_id: int = Depends(_scim_org),
    session: AsyncSession = Depends(get_session),
) -> Response:
    user = await _scim_user_in_org(session, user_id, org_id)
    await provisioning.scim_deactivate_user(session, org_id=org_id, user=user)
    await session.commit()
    return Response(status_code=204)


@router.get("/api/scim/v2/Groups")
async def scim_list_groups(
    _org_id: int = Depends(_scim_org),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    groups = (
        await session.execute(select(GroupRoleMapping).order_by(GroupRoleMapping.group))
    ).scalars().all()
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": len(groups),
        "Resources": [
            {"id": str(g.id), "displayName": g.group, "meta": {"resourceType": "Group"}}
            for g in groups
        ],
    }


@router.get("/api/auth/sso-status")
async def sso_status(_principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    s = get_settings()
    return {
        "oidc_enabled": s.oidc_enabled,
        "scim_enabled": s.scim_enabled,
        "jit_provisioning": s.auth_jit_provisioning,
        "issuer": s.oidc_issuer if s.oidc_enabled else None,
    }
