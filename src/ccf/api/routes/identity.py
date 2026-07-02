"""Enterprise identity routes — OIDC SSO login, admin IdP/mappings, SCIM.

The browser SSO flow (`/auth/login` → IdP → `/auth/callback`) and the SCIM
provisioning API (`/api/scim/v2/*`, authenticated by `CCF_SCIM_BEARER_TOKEN`) are
public to the user-session gate but individually guarded. With OIDC disabled the
login route falls back to the local `/login` form, so dev needs no IdP.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal, sign_session
from ...config import get_settings
from ...identity import provisioning
from ...identity.oidc import authorization_url, exchange_code, new_state
from ...models import Organization, User
from ...models_identity import GroupRoleMapping, IdentityProvider
from ..auth_deps import SESSION_COOKIE, get_principal, require_role
from ..deps import get_session

router = APIRouter(tags=["identity"])

_STATE_COOKIE = "concord_oidc_state"


def _set_session_cookie(response: Response, user_id: int) -> None:
    s = get_settings()
    token = sign_session(user_id, s.auth_session_secret, ttl_hours=s.auth_session_ttl_hours)
    response.set_cookie(
        SESSION_COOKIE, token, max_age=s.auth_session_ttl_hours * 3600,
        httponly=True, samesite="lax", secure=s.env == "prod",
    )


async def _default_org_id(session: AsyncSession) -> int:
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
    resp.set_cookie(_STATE_COOKIE, state, httponly=True, samesite="lax", max_age=600)
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
    _set_session_cookie(resp, user.id)
    return resp


@router.get("/auth/logout")
@router.post("/auth/logout")
async def sso_logout() -> RedirectResponse:
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


async def _scim_org(authorization: str = Header(default="")) -> int | None:
    """Guard SCIM routes with the configured bearer token; returns a sentinel org.

    The concrete org is resolved per-request against the default org so SCIM works
    on a fresh deployment; here we only enforce the token + enabled flag.
    """
    s = get_settings()
    if not s.scim_enabled or not s.scim_bearer_token:
        raise HTTPException(404, "SCIM is not enabled")
    token = authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""
    if token != s.scim_bearer_token:
        raise HTTPException(401, "invalid SCIM token")
    return None


@router.get("/api/scim/v2/Users")
async def scim_list_users(
    _guard: int | None = Depends(_scim_org),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    users = (await session.execute(select(User).order_by(User.id))).scalars().all()
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": len(users),
        "Resources": [provisioning.scim_user_resource(u) for u in users],
    }


@router.post("/api/scim/v2/Users", status_code=201)
async def scim_create_user(
    payload: dict[str, Any],
    _guard: int | None = Depends(_scim_org),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    org_id = await _default_org_id(session)
    try:
        user, _created = await provisioning.scim_create_or_update_user(
            session, org_id=org_id, payload=payload
        )
    except provisioning.ProvisioningError as e:
        raise HTTPException(400, str(e)) from e
    await session.commit()
    return provisioning.scim_user_resource(user)


@router.get("/api/scim/v2/Users/{user_id}")
async def scim_get_user(
    user_id: int,
    _guard: int | None = Depends(_scim_org),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(404, "user not found")
    return provisioning.scim_user_resource(user)


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
    _guard: int | None = Depends(_scim_org),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(404, "user not found")
    org_id = user.organization_id
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
    _guard: int | None = Depends(_scim_org),
    session: AsyncSession = Depends(get_session),
) -> Response:
    user = await session.get(User, user_id)
    if user is not None:
        await provisioning.scim_deactivate_user(
            session, org_id=user.organization_id, user=user
        )
        await session.commit()
    return Response(status_code=204)


@router.get("/api/scim/v2/Groups")
async def scim_list_groups(
    _guard: int | None = Depends(_scim_org),
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
