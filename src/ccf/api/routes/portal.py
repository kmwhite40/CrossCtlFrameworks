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
from ...config import get_settings, is_dev_env
from ...models_portal import AssessmentEngagement, ExternalAccessGrant
from ...portal import (
    add_comment,
    create_engagement,
    create_grant,
    create_principal,
    grant_contents,
    list_engagements,
    list_grants,
    record_access,
    resolve_grant,
    resolve_grant_by_id,
    revoke_engagement,
    revoke_grant,
)
from ..auth_deps import require_role, resolve_caller_org
from ..deps import get_session
from .systems import require_system_in_scope

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


class PrincipalIn(BaseModel):
    organization_id: int
    name: str
    kind: str = "customer"
    email: str | None = None
    organization_name: str | None = None


@router.post("/principals")
async def create_principal_endpoint(
    body: PrincipalIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> dict[str, Any]:
    """Create an external principal on its own — an engagement names one
    before any grant exists, so it cannot only be created as a side effect of
    issuing a grant.

    ``require_role("admin")`` is a *tenant* role, not an org gate, so the
    body's ``organization_id`` was the only thing deciding which tenant the
    row landed in. ``resolve_caller_org`` makes the principal decide.
    """
    org_id = resolve_caller_org(principal.org_id, body.organization_id)
    try:
        row = await create_principal(
            session, org_id=org_id, name=body.name, kind=body.kind,
            email=body.email, organization_name=body.organization_name,
        )
    except ValueError as exc:  # unknown ``kind`` — a vocabulary error, not a server fault
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    await session.commit()
    return {"id": row.id, "kind": row.kind, "name": row.name, "email": row.email,
            "organization_name": row.organization_name}


class EngagementIn(BaseModel):
    organization_id: int
    system_id: int
    assessor_principal_id: int
    period_from: datetime
    period_to: datetime
    authorized_by: str | None = None


def _engagement_out(row: Any) -> dict[str, Any]:
    """Every column of ``assessment_engagements``, across the HTTP boundary.

    Listed explicitly rather than serialized from the ORM row so that adding a
    column is a visible decision here — and
    ``tests/test_3pao_engagements.py::test_every_engagement_field_crosses_the_http_boundary``
    compares these keys against the model's own columns, so a field dropped
    from this dict fails rather than quietly disappearing from the API.
    """
    return {
        "id": row.id,
        "organization_id": row.organization_id,
        "system_id": row.system_id,
        "assessor_principal_id": row.assessor_principal_id,
        "period_from": row.period_from,
        "period_to": row.period_to,
        "authorized_by": row.authorized_by,
        "independence_note": row.independence_note,
        "revoked_at": row.revoked_at,
        "created_at": row.created_at,
    }


@router.post("/engagements")
async def create_engagement_endpoint(
    body: EngagementIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> dict[str, Any]:
    org_id = resolve_caller_org(principal.org_id, body.organization_id)
    # The engagement names a system rather than reading one, so RLS never sees
    # a query to refuse and a foreign ``system_id`` would land in the row. The
    # canonical guard gives this route the same answer every other
    # system-taking route gives: 404 for another tenant's system, and for a
    # soft-deleted one. (The service re-checks system-vs-``org_id`` for callers
    # that have no Principal, and for a global principal, whose org is whatever
    # the body named.)
    await require_system_in_scope(session, body.system_id, principal)
    try:
        row = await create_engagement(
            session, org_id=org_id, system_id=body.system_id,
            assessor_principal_id=body.assessor_principal_id,
            period_from=body.period_from, period_to=body.period_to,
            authorized_by=body.authorized_by or principal.email, actor=principal.email,
        )
    except ValueError as exc:  # unknown principal, or one that is not an assessor
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    await session.commit()
    return _engagement_out(row)


@router.get("/engagements")
async def list_engagements_endpoint(
    organization_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> list[dict[str, Any]]:
    """List one org's 3PAO engagements — the caller's own. See
    ``resolve_caller_org``: the query parameter may confirm the principal's
    org, never name another."""
    org_id = resolve_caller_org(principal.org_id, organization_id)
    return [_engagement_out(row) for row in await list_engagements(session, org_id=org_id)]


@router.post("/engagements/{engagement_id}/revoke")
async def revoke_engagement_endpoint(
    engagement_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> dict[str, Any]:
    """End the engagement, and with it every grant issued under it.

    ``require_role("admin")`` is not an org gate -- ``admin`` is a tenant role,
    and only a global principal short-circuits it -- so one org's admin could
    revoke another org's 3PAO engagement. 404, not 403: the id's existence is
    itself a disclosure.
    """
    if principal.org_id is not None:
        row = await session.get(AssessmentEngagement, engagement_id)
        if row is None or row.organization_id != principal.org_id:
            raise HTTPException(status_code=404, detail="engagement not found")
    ok = await revoke_engagement(session, engagement_id, actor=principal.email)
    await session.commit()
    if not ok:
        raise HTTPException(status_code=404, detail="engagement not found")
    return {"revoked": True}


class GrantIn(BaseModel):
    organization_id: int
    principal_name: str = ""
    kind: str = "customer"
    email: str | None = None
    organization_name: str | None = None
    package_ids: list[int] = []
    evidence_ids: list[int] = []
    ttl_days: int | None = 30
    label: str | None = None
    engagement_id: int | None = None
    principal_id: int | None = None


@router.post("/grants")
async def create_grant_endpoint(
    body: GrantIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> dict[str, Any]:
    # A portal grant is a bearer credential into an org's authorization package
    # and evidence. Issuing one is exactly the operation that must not accept
    # its tenant from the request body — ``require_role("admin")`` is a tenant
    # role and does not gate the org. (Before this, the insert was refused by
    # the RLS WITH CHECK instead, surfacing as a 500, not an authorization
    # answer.) ``revoke`` was scoped at 2a2137f; this closes the issuing half.
    org_id = resolve_caller_org(principal.org_id, body.organization_id)
    try:
        grant = await create_grant(
            session, org_id=org_id, principal_name=body.principal_name,
            kind=body.kind, email=body.email, organization_name=body.organization_name,
            package_ids=body.package_ids, evidence_ids=body.evidence_ids,
            ttl_days=body.ttl_days, label=body.label,
            engagement_id=body.engagement_id, principal_id=body.principal_id,
            actor=principal.email,
        )
    except ValueError as exc:
        # A refusal the caller can fix by sending different input (an unknown
        # ``kind``; from §4, an engagement-backed grant with no TTL) — 422, not
        # a 500 that reads as a Concord fault.
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    await session.commit()
    # IA-09: the plaintext token is shown exactly once, here at issuance — it
    # is not persisted and cannot be recovered from `grant.token_hash`.
    return {"id": grant.id, "token": grant.token, "kind": grant.kind,
            "expires_at": grant.expires_at, "engagement_id": grant.engagement_id,
            # §4 rule 2: the caller asked for longer and the engagement's end
            # date won. Said out loud, not left to be noticed in ``expires_at``.
            "expiry_capped": grant.expiry_capped}


@router.get("/grants")
async def list_grants_endpoint(
    organization_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> list[dict[str, Any]]:
    """List one org's outstanding grants — the caller's own. See
    ``resolve_caller_org``."""
    org_id = resolve_caller_org(principal.org_id, organization_id)
    grants = await list_grants(session, org_id=org_id)
    return [
        {"id": g.id, "kind": g.kind, "label": g.label, "engagement_id": g.engagement_id,
         "revoked": g.revoked, "expires_at": g.expires_at, "created_at": g.created_at}
        for g in grants
    ]


@router.post("/grants/{grant_id}/revoke")
async def revoke_grant_endpoint(
    grant_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> dict[str, Any]:
    """Revoke one external-access grant. Role-gated AND org-scoped -- see
    ``revoke_engagement_endpoint`` for why the role alone is not enough."""
    if principal.org_id is not None:
        row = await session.get(ExternalAccessGrant, grant_id)
        if row is None or row.organization_id != principal.org_id:
            raise HTTPException(status_code=404, detail="grant not found")
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
    """Resolve the portal caller from EITHER credential channel.

    A grant arrives two ways: as a token (bearer header or ``?token=``) and, once
    the HTML entry point has exchanged that token, as a signed cookie. These used
    to be resolved by two separate functions, each wired to one surface, so a
    request could be authenticated for ``/portal`` and anonymous for
    ``/api/portal/*`` in the same browser, same second, same grant.

    That broke the external comment form outright: the HTML entry point strips
    ``token`` from the URL on redirect, so the page's fetch sent
    ``Authorization: Bearer `` (empty) and always got 401.

    The cookie is tried first: it is the fresher credential, and a stale
    ``?token=`` left in a bookmarked URL must not override it. Both paths
    re-validate the grant's live revoked/expiry state in the database.
    """
    grant = await _grant_from_cookie(request, session)
    if grant is None:
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
            secure=not is_dev_env(settings),
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
