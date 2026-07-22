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

import hashlib
import hmac
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal, sign_session, verify_session
from ...config import get_settings
from ...portal import (
    add_comment,
    create_grant,
    grant_contents,
    list_grants,
    record_access,
    resolve_grant,
    resolve_grant_by_id,
    revoke_grant,
)
from ..auth_deps import require_role
from ..deps import get_session

TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter(prefix="/api/admin/portal", tags=["portal"])
public_router = APIRouter(prefix="/api/portal", tags=["portal"])
ui_router = APIRouter(tags=["portal"])

# The browser-facing ``/portal`` UI exchanges a one-time link token for this
# short-lived signed session cookie (IA-09: reduces token-in-URL exposure —
# the plaintext link token no longer needs to travel in every subsequent
# request/access-log line once the cookie is established). Deliberately a
# *different* cookie from the internal ``concord_session`` — it carries a
# grant id, not a user id, and must never be read by the internal auth path.
PORTAL_SESSION_COOKIE = "concord_portal_session"
_PORTAL_SESSION_MAX_TTL_HOURS = 24

# Domain-separation label for deriving the portal cookie's own signing key
# from the shared ``auth_session_secret`` (see ``_portal_secret``). Changing
# this string invalidates every outstanding portal session cookie.
_PORTAL_SECRET_LABEL = b"ccf-portal-session-v1"


def _portal_secret(base_secret: str) -> str:
    """Derive a signing key for portal session cookies that is cryptographically
    independent of the internal login session key (``settings.auth_session_secret``,
    used by ``concord_session`` — see ``ccf.auth.sign_session``/``verify_session``
    and ``ccf.api.auth_deps._lookup_principal``).

    ``sign_session``/``verify_session`` carry no audience/type claim — a value
    signed with the *same* secret verifies as valid under *either* cookie name.
    Without this derivation, a portal grant id and an internal user id can
    collide (independent serial sequences, both starting from 1), letting an
    external portal user replay their ``concord_portal_session`` value as
    ``concord_session`` and authenticate as whichever internal user happens to
    share that id — full account takeover. Deriving a distinct key here means
    a portal-signed value's HMAC never verifies under the internal secret, and
    vice versa, regardless of any id collision.
    """
    return hmac.new(base_secret.encode(), _PORTAL_SECRET_LABEL, hashlib.sha256).hexdigest()


def _portal_cookie_ttl_hours(grant: Any) -> int:
    """Cap the cookie's own lifetime at the grant's expiry (if any).

    This is a courtesy, not the security boundary: every cookie-authenticated
    request re-validates the grant against the DB (see ``_grant_from_cookie``),
    so a grant that's revoked or expires mid-cookie-lifetime still gets
    rejected regardless of what's baked into the cookie's signed payload.

    Floors (rather than rounds up) the remaining time to whole hours so the
    cookie's signed lifetime does not itself exceed the grant's expiry.
    """
    if grant.expires_at is None:
        return _PORTAL_SESSION_MAX_TTL_HOURS
    remaining = grant.expires_at - datetime.now(UTC)
    hours_left = max(1, int(remaining.total_seconds() // 3600))
    return min(_PORTAL_SESSION_MAX_TTL_HOURS, hours_left)


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
    # IA-09: the plaintext token is shown exactly once, here at issuance — it
    # is not persisted and cannot be recovered from `grant.token_hash`.
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
        {"id": g.id, "kind": g.kind, "label": g.label,
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


async def _grant_from_cookie(request: Request, session: AsyncSession) -> Any:
    """Authenticate a portal request off the signed session cookie, if any.

    Validates the HMAC signature + embedded expiry (``verify_session``) *and*
    re-checks the referenced grant's live revoked/expiry state in the DB —
    the cookie proves who issued it, not that the grant is still valid.
    """
    cookie = request.cookies.get(PORTAL_SESSION_COOKIE)
    if not cookie:
        return None
    grant_id = verify_session(cookie, _portal_secret(get_settings().auth_session_secret))
    if grant_id is None:
        return None
    return await resolve_grant_by_id(session, grant_id)


@ui_router.get("/portal", response_class=HTMLResponse, response_model=None)
async def portal_ui(
    request: Request, token: str = "", session: AsyncSession = Depends(get_session)
) -> HTMLResponse | RedirectResponse:
    if token:
        grant = await resolve_grant(session, token)
        if grant is None:
            return templates.TemplateResponse(
                request, "portal.html", {"token": token, "grant": None, "contents": None},
            )
        # First use of the link token: exchange it for a short-lived signed
        # session cookie scoped to this grant, then redirect to the same
        # path with the token stripped from the query string — from here on
        # the browser authenticates via the cookie, not a URL parameter that
        # would otherwise sit in browser history and portal access logs.
        settings = get_settings()
        ttl_hours = _portal_cookie_ttl_hours(grant)
        cookie_value = sign_session(
            grant.id, _portal_secret(settings.auth_session_secret), ttl_hours=ttl_hours,
        )
        remaining_params = {k: v for k, v in request.query_params.items() if k != "token"}
        target = request.url.path
        if remaining_params:
            target = f"{target}?{urlencode(remaining_params)}"
        redirect = RedirectResponse(url=target, status_code=303)
        redirect.set_cookie(
            PORTAL_SESSION_COOKIE,
            cookie_value,
            max_age=ttl_hours * 3600,
            httponly=True,
            samesite="lax",
            secure=settings.env == "prod",
        )
        return redirect

    grant = await _grant_from_cookie(request, session)
    contents = None
    if grant is not None:
        contents = await grant_contents(session, grant)
        await record_access(session, grant, action="view")
        await session.commit()
    return templates.TemplateResponse(
        request,
        "portal.html",
        {"token": "", "grant": grant, "contents": contents},
    )
