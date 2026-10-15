"""Auth dependencies + gate middleware: resolve the Principal, enforce roles."""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from typing import Any, overload

from fastapi import Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.base import RequestResponseEndpoint

from ..auth import SYSTEM_PRINCIPAL, Principal, hash_token, read_session
from ..config import get_settings
from ..db import get_session_factory, set_session_tenant
from ..identity import mfa_service
from ..logging import get_logger
from ..models import System, User

SESSION_COOKIE = "concord_session"

#: The half-authenticated cookie set between a correct password and a correct
#: code. Named separately from ``SESSION_COOKIE`` so the two are never confused
#: in a template or a test -- though the real defence is that it is signed with
#: a derived key (``login_service._mfa_pending_secret``) and therefore does not
#: verify as a session however it is renamed.
MFA_PENDING_COOKIE = "concord_mfa_pending"

# Paths reachable without authentication even when auth is enabled. Matched on
# segment boundaries by ``is_public_path`` — never as a bare string prefix.
log = get_logger(__name__)

_PUBLIC_PREFIXES = (
    "/api/auth",
    "/auth/login",
    "/auth/callback",
    "/auth/piv",  # PIV/CAC sign-in: reached before a session exists
    "/auth/logout",
    "/api/scim",  # SCIM uses its own bearer token, not the user session
    "/api/portal",  # external portal API — the grant token is the credential
    "/portal",  # external portal UI — token supplied via ?token=
    "/login",
    "/logout",
    "/healthz",
    "/readyz",
    "/livez",
    "/static",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/favicon",
)

# Entries matched as a true string prefix rather than on a segment boundary:
# browsers request favicons as sibling files (/favicon.ico, /favicon-32x32.png),
# not as a /favicon/ subtree.
_PUBLIC_LITERAL_PREFIXES = ("/favicon",)


def is_public_path(path: str) -> bool:
    """True when ``path`` is reachable without authentication.

    Matches each public entry on a segment boundary — the path must equal the
    entry or continue with ``/``. A bare ``startswith`` would exempt unrelated
    routes that merely share a textual prefix (``/api/authorization-packages``
    silently inheriting the ``/api/auth`` exemption, for example).
    """
    if path == "/":
        return True
    if path == "/metrics":
        # AC-3: telemetry is authenticated by default; a scraper presents an API
        # token. CCF_METRICS_REQUIRE_AUTH=false restores the open endpoint for
        # deployments that restrict it at the network layer instead.
        return not get_settings().metrics_require_auth
    if any(path == p or path.startswith(p + "/") for p in _PUBLIC_PREFIXES):
        return True
    return path.startswith(_PUBLIC_LITERAL_PREFIXES)


async def _lookup_principal(request: Request, session: AsyncSession) -> Principal | None:
    """Resolve a Principal from a bearer token or signed session cookie (or None)."""
    settings = get_settings()
    user: User | None = None
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if token:
            user = (
                await session.execute(
                    select(User).where(
                        User.api_token_hash == hash_token(token), User.active.is_(True)
                    )
                )
            ).scalar_one_or_none()
    if user is None:
        cookie = request.cookies.get(SESSION_COOKIE)
        if cookie:
            claims = read_session(cookie, settings.auth_session_secret)
            if claims is not None:
                uid, sv = claims
                user = (
                    await session.execute(
                        select(User).where(
                            User.id == uid,
                            User.active.is_(True),
                            # AC-12: reject cookies minted before the user's
                            # session version was bumped (logout, password
                            # change) so revocation is effective server-side.
                            User.session_version == sv,
                        )
                    )
                ).scalar_one_or_none()
    if user is None:
        return None
    return Principal(
        user_id=user.id, email=user.email, org_id=user.organization_id, role=user.role
    )


async def get_principal_optional(request: Request) -> Principal | None:
    """Resolve the caller without forcing auth (returns ``None`` if anonymous).

    Used to bind the request session's tenant context. Resolution runs on its own
    short-lived, unscoped (bypass) session so it can read ``users`` across orgs
    *before* the tenant context is known. Pre-auth/public routes (e.g. login) get
    ``None`` and therefore an unscoped session; protected routes are already gated
    by ``auth_gate_middleware`` (which sets ``request.state.principal``).
    """
    if not get_settings().auth_enabled:
        request.state.principal = SYSTEM_PRINCIPAL
        return SYSTEM_PRINCIPAL
    existing = getattr(request.state, "principal", None)
    if isinstance(existing, Principal):
        return existing
    factory = get_session_factory()
    async with factory() as session:
        await set_session_tenant(session, None)
        principal = await _lookup_principal(request, session)
    if principal is not None:
        request.state.principal = principal
    return principal


async def get_principal(request: Request) -> Principal:
    """Dependency: the authenticated caller (open SYSTEM principal when auth off).

    Raises 401 when auth is enabled and the caller is anonymous.
    """
    principal = await get_principal_optional(request)
    if principal is None:
        raise HTTPException(401, "authentication required")
    return principal


def org_systems_subq(principal: Principal) -> Any:
    """Subquery of System ids in the principal's org. Callers apply it only when
    ``principal.org_id`` is set (global principals are unscoped).

    Excludes soft-deleted systems (DATA-04) so a deleted system's id can no
    longer be used to scope in new risks/scans/evidence/POA&Ms — its existing
    dependent rows are preserved, just no longer reachable through this scope.
    """
    return select(System.id).where(
        System.organization_id == principal.org_id, System.deleted_at.is_(None)
    )


@overload
def resolve_caller_org(principal_org: int | None, requested_org: int) -> int: ...


@overload
def resolve_caller_org(principal_org: int | None, requested_org: None) -> int | None: ...


@overload
def resolve_caller_org(principal_org: int | None, requested_org: int | None) -> int | None: ...


def resolve_caller_org(principal_org: int | None, requested_org: int | None) -> int | None:
    """The organization a request runs against, given the one the caller *named*.

    Tenant identity comes from the authenticated principal, never from a body
    field, query string, form field or header. Where the caller is bound to an
    org (``principal_org`` is set), a supplied ``organization_id`` may only
    *confirm* it: an equal value is accepted, an absent one defaults to the
    caller's own, and a **different** one is refused. Where the principal is
    global (``principal_org is None`` -- the CLI/ETL/scheduler path, and every
    request when ``CCF_AUTH_ENABLED=false``) the supplied value is honoured
    as-is: that is the superuser path ``require_role`` already short-circuits
    for, and the only way an operator names an org at all.

    **Refused, not silently substituted.** Quietly swapping in the caller's own
    org answers a 200 to a question nobody asked -- the request named org B and
    got org A's data back, with nothing in the response saying so. A caller
    naming another tenant is either a bug or an attack; a bug deserves to be
    told, and an attack deserves nothing. Every route that reads a
    caller-supplied organization now routes through here; there is no
    substitute-and-log path left.

    **403, not 404.** The repo's 404-vs-403 rule
    (``tests/test_waivers_api_rbac.py``) is about *resources*: another tenant's
    row is 404 because confirming its id exists is itself a disclosure. This
    refusal is decided from ``principal_org`` alone, before any lookup, so a
    real foreign org id and an invented one produce byte-identical responses --
    it discloses nothing about what exists. What it does report is exactly a
    permission the caller lacks: acting on behalf of an organization that is
    not its own. That is a 403.

    Overloaded so that a route whose ``organization_id`` is a *required*
    ``int`` keeps an ``int`` (never ``int | None``) out of this call: the only
    way ``None`` is returned is when ``None`` was passed in, and a required
    parameter cannot be. Without that, every such call site would need a cast,
    and a cast is where a real ``None`` would later hide.
    """
    if principal_org is None:
        return requested_org
    if requested_org is not None and requested_org != principal_org:
        raise HTTPException(
            403, "organization_id does not match the authenticated organization"
        )
    return principal_org


def require_role(*roles: str) -> Callable[..., Awaitable[Principal]]:
    """Dependency factory enforcing one of ``roles`` (SYSTEM principal bypasses)."""

    async def _dep(principal: Principal = Depends(get_principal)) -> Principal:
        if principal.is_global or principal.role in roles:
            return principal
        raise HTTPException(403, f"requires role: {', '.join(roles)}")

    return _dep


def require_platform_admin() -> Callable[..., Awaitable[Principal]]:
    """Dependency for operations on **Concord's own** boundary, not a tenant's.

    ``require_role("admin")`` is the wrong gate for these: it admits any
    customer's administrator, because being an admin *of a tenant* says nothing
    about authority over the platform.

    It also fails in a way that reads as a bug rather than a refusal. A
    tenant-scoped session has its RLS tenant bound to that customer, so a lookup
    of a platform-owned row returns nothing; code that then tries to create the
    row is refused by the same policy, and the caller gets a 500. That is what
    ``GET /api/admin/self-assurance/package`` did.

    So the precondition is explicit: an unscoped (global) principal, which is
    also the only session that can read and write platform-owned rows at all.
    """

    async def _dep(principal: Principal = Depends(get_principal)) -> Principal:
        if not principal.is_global:
            raise HTTPException(
                403,
                "this operates on Concord's own assurance boundary and requires a "
                "platform-wide (unscoped) administrator, not a tenant administrator",
            )
        return principal

    return _dep


#: Reachable while a required authenticator is still outstanding. Everything
#: here is either how you enrol or how you leave -- an allowlist that missed
#: the enrolment page would lock an organization out of itself the moment an
#: admin set the policy, with no way back in.
_MFA_ENROLMENT_PATHS = (
    "/settings/security",   # the page and its enrol/activate/disable posts
    "/api/auth/mfa",        # the same three steps over the API
    "/logout",
    "/api/auth/logout",
)


#: Mutating requests a **viewer** may still make. docs/HANDBOOK.md promises a
#: viewer can "Read everything in your organization" and change nothing of it,
#: and docs/THREAT_MODEL.md rates the role "Reads only" -- but most write routes
#: (165 by a scan of route signatures in 764e87e) carried no role check, so a
#: viewer could create risks, tasks, evidence, POA&Ms and more. Rather than gate
#: each route (and keep auditing every new one), the auth gate refuses a
#: viewer's mutating request outright, except exactly these (method, path):
#:
#: * the viewer's own MFA enrolment (each handler acts on ``principal.user_id``
#:   only), and their own notification read-state -- per user since migration
#:   0096 (``ccf.governance.inbox``), so it changes no one else's inbox;
#: * POST endpoints that only read -- a query run or CSV export, and two
#:   validators that check a posted document without storing it;
#: * logging a trust-portal access request: it records that someone asked,
#:   cannot set its own status, and only an admin can decide it
#:   ("logging that someone asked is not an approval", tests/test_trust_rbac.py).
#:
#: Deliberately NOT here, after independent review: pack-source registration
#: (it starts scheduled server-side fetches of a caller-chosen URL).
#: Notification read-state was excluded until 0096 made it per user: before,
#: ``read_at`` was one column on an org-wide row and "mark read" silenced
#: every member's alerts.
#:
#: Each entry is one method and a fully anchored path (``\Z``, not ``$``, which
#: also matches before a trailing newline), so a new route -- or a new method on
#: an allowlisted path -- is refused until someone adds it here on purpose.
_VIEWER_WRITE_ALLOWLIST: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("POST", re.compile(r"/settings/security/(enroll|activate|disable)\Z")),
    ("POST", re.compile(r"/api/queries/[^/]+/(run|export)\Z")),
    ("POST", re.compile(r"/api/notifications/\d+/read\Z")),
    ("POST", re.compile(r"/api/notifications/read-all\Z")),
    ("POST", re.compile(r"/api/oscal/validate\Z")),
    ("POST", re.compile(r"/api/packs/validate\Z")),
    ("POST", re.compile(r"/api/trust/access-requests\Z")),
    ("POST", re.compile(r"/trust/access-requests\Z")),
)
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
VIEWER_ROLE = "viewer"


def viewer_may_write(path: str, method: str = "POST") -> bool:
    """True if a viewer may make this mutating ``method`` request to ``path``."""
    m = method.upper()
    return any(m == allowed and pattern.match(path) for allowed, pattern in _VIEWER_WRITE_ALLOWLIST)


def is_mfa_enrolment_path(path: str) -> bool:
    return any(path == p or path.startswith(p + "/") for p in _MFA_ENROLMENT_PATHS)


def _viewer_refusal(request: Request, principal: Principal, path: str) -> Response | None:
    """A 403 for a viewer's mutating request off the allowlist, else ``None``."""
    method = request.method.upper()
    if (
        principal.role != VIEWER_ROLE
        or principal.is_global
        or method not in _MUTATING_METHODS
        or viewer_may_write(path, method)
    ):
        return None
    # Logged: a refused write otherwise leaves no trace (the audit middleware
    # records only successful mutations), and a viewer probing writes is
    # exactly what someone reviewing access would want to see.
    log.info(
        "auth.viewer_write_refused",
        method=method,
        path=path,
        user_id=principal.user_id,
        org_id=principal.org_id,
    )
    detail = "the viewer role is read-only; ask an administrator for a role that can change this"
    if path.startswith("/api"):
        return JSONResponse({"detail": detail}, status_code=403)
    return PlainTextResponse(detail, status_code=403)


async def auth_gate_middleware(
    request: Request, call_next: RequestResponseEndpoint
) -> Response:
    """When auth is enabled, require a valid principal for non-public paths.

    API paths get a 401; browser paths are redirected to ``/login``. Sets
    ``request.state.principal`` so downstream deps/audit reuse it.
    """
    if not get_settings().auth_enabled:
        return await call_next(request)
    path = request.url.path
    refused: Response | None = None
    if not is_public_path(path):
        factory = get_session_factory()
        # ONE session for both questions. The gate below used to sit outside
        # this block and query a session whose context manager had already
        # exited, so every gated request took a fresh connection per query --
        # connection churn that cost far more than the queries did.
        async with factory() as session:
            await set_session_tenant(session, None)
            principal = await _lookup_principal(request, session)
            if principal is None:
                if path.startswith("/api"):
                    return JSONResponse(
                        {"detail": "authentication required"}, status_code=401
                    )
                return RedirectResponse("/login", status_code=303)
            request.state.principal = principal

            # IA-2(1): an organization that requires a second factor gets one.
            #
            # Session cookies only. An API token is not interactive -- there is
            # no human present to challenge -- and the MFA design excluded it
            # deliberately; gating it here would break every integration the
            # day a policy changed.
            #
            # The user is NOT refused, they are routed to enrolment. Refusing
            # would let an organization lock every one of its own users out by
            # changing a dropdown, which is why this was left unbuilt before.
            if (
                request.cookies.get(SESSION_COOKIE)
                and not is_mfa_enrolment_path(path)
                and await mfa_service.enrolment_outstanding(
                    session,
                    principal.user_id,
                    organization_id=principal.org_id,
                    role=principal.role,
                )
            ):
                if path.startswith("/api"):
                    return JSONResponse(
                        {
                            "detail": "your organization requires a second "
                            "factor; enrol at /settings/security before using "
                            "this API with a session cookie"
                        },
                        status_code=403,
                    )
                return RedirectResponse(
                    "/settings/security?enrol=required", status_code=303
                )

            refused = _viewer_refusal(request, principal, path)
    return refused if refused is not None else await call_next(request)
