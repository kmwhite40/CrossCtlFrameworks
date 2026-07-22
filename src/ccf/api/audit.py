"""Audit-trail middleware — tamper-evident record of mutations in ``ccf.audit_log``.

Records every successful state-changing request (POST/PUT/PATCH/DELETE) with the
authenticated principal (or the ``X-Actor`` header when auth is disabled), the
action, the affected entity, the (redacted) request body, and a SHA-256 hash
chain: each row's ``row_hash`` covers its content plus the previous row's hash,
so any later edit or deletion breaks the chain (verify via ``/api/audit/verify``).
Best-effort: failures here never break the request.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import TYPE_CHECKING, Any

from fastapi import Request, Response
from sqlalchemy import select

from ..config import get_settings
from ..db import get_session_factory, set_session_tenant
from ..logging import get_logger
from ..models import AuditLog

if TYPE_CHECKING:  # pragma: no cover
    from starlette.middleware.base import RequestResponseEndpoint

log = get_logger(__name__)

_MUTATING = {"POST", "PUT", "PATCH", "DELETE"}
_ACTION = {"POST": "create", "PUT": "update", "PATCH": "update", "DELETE": "delete"}
_SKIP_PREFIXES = ("/metrics", "/healthz", "/readyz", "/livez", "/static", "/api/audit")
_ID_RE = re.compile(r"\d+")
_REDACT = ("password", "token", "secret", "api_token", "key", "credential", "private")
_GENESIS = "0" * 64
_MAX_BODY = 8_192


def _entity(path: str) -> tuple[str, str | None]:
    """Derive (entity_type, entity_id) from a request path.

    ``/api/ssp/projects/3/entries/AC.L2-3.1.1`` → ``("ssp", "3")``.
    """
    parts = [p for p in path.strip("/").split("/") if p]
    if parts and parts[0] == "api":
        parts = parts[1:]
    entity_type = parts[0] if parts else "root"
    entity_id = next((p for p in parts[1:] if _ID_RE.fullmatch(p)), None)
    return entity_type, entity_id


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: ("***" if any(s in k.lower() for s in _REDACT) else _redact(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


def row_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    """Deterministic content hash chaining onto ``prev_hash``."""
    canonical = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(f"{prev_hash}\n{canonical}".encode()).hexdigest()


async def record_event(
    session: Any,
    *,
    actor: str,
    action: str,
    entity_type: str,
    entity_id: str | None,
    diff: dict[str, Any],
) -> None:
    """Append one entry to the tamper-evident audit chain within ``session``.

    For events that don't originate from an auto-audited mutating HTTP request
    (e.g. OIDC/JIT provisioning during a GET callback, or role changes). Uses the
    same ``prev_hash``/``row_hash`` chaining as the middleware. Caller owns commit.
    """
    content = {
        "actor": actor,
        "action": action,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "diff": _redact(diff),
    }
    prev = (
        await session.execute(select(AuditLog.row_hash).order_by(AuditLog.id.desc()).limit(1))
    ).scalar_one_or_none() or _GENESIS
    session.add(AuditLog(**content, prev_hash=prev, row_hash=row_hash(prev, content)))


async def _capture_body(request: Request, method: str) -> Any:
    """Read + redact a JSON request body (cached so the route can still read it)."""
    if method not in _MUTATING:
        return None
    if not request.headers.get("content-type", "").startswith("application/json"):
        return None
    try:
        raw = await request.body()
        if not raw or len(raw) > _MAX_BODY:
            return None
        return _redact(json.loads(raw))
    except Exception:  # pragma: no cover - never let capture break the request
        return None


async def audit_middleware(
    request: Request, call_next: RequestResponseEndpoint
) -> Response:
    method = request.method.upper()
    path = request.url.path
    body = (
        await _capture_body(request, method)
        if (method in _MUTATING and not path.startswith(_SKIP_PREFIXES))
        else None
    )

    response = await call_next(request)
    if not (
        method in _MUTATING
        and 200 <= response.status_code < 400
        and not path.startswith(_SKIP_PREFIXES)
    ):
        return response

    # Idempotency guard (exception-safety hardening): Starlette's
    # BaseHTTPMiddleware can, under certain exception/re-entry conditions,
    # invoke this dispatch function more than once for what is logically the
    # same client request — and because the ASGI ``scope`` (and therefore
    # ``request.state``) is shared across those re-entries, a second pass
    # would otherwise re-run the select-latest-hash + insert sequence below
    # and write a duplicate ``AuditLog`` row. Both rows would be computed
    # from the same ``prev_hash`` (whatever was latest before either insert),
    # forking the hash chain — not just for this request, but permanently for
    # every row appended afterwards, since ``/api/audit/verify`` walks a
    # single linear chain. Setting the flag *before* the write (not after
    # success) means a re-entrant pass never risks a duplicate, even if the
    # first pass's write is slow or itself fails.
    if getattr(request.state, "audit_recorded", False):
        return response
    request.state.audit_recorded = True

    try:
        principal = getattr(request.state, "principal", None)
        # A real authenticated user wins; the open SYSTEM principal (auth off,
        # user_id is None) must not shadow an explicit X-Actor header.
        principal_email = (
            principal.email if principal is not None and principal.user_id is not None else None
        )
        actor = (
            principal_email
            or request.headers.get("x-actor")
            or get_settings().audit_default_actor
        )
        # organization_id is a SCOPING column only (DATA-06) — resolved from the
        # request principal and NEVER folded into `content`/the hash payload
        # below, so existing chains and /api/audit/verify stay valid. NULL for
        # unauthenticated requests or a global/unscoped principal (system events).
        org_id = (
            principal.org_id if principal is not None and principal.user_id is not None else None
        )
        entity_type, entity_id = _entity(path)
        diff: dict[str, Any] = {"method": method, "path": path, "status": response.status_code}
        if body is not None:
            diff["body"] = body

        content = {
            "actor": actor,
            "action": _ACTION.get(method, method.lower()),
            "entity_type": entity_type,
            "entity_id": entity_id,
            "diff": diff,
        }
        factory = get_session_factory()
        async with factory() as session:
            # Reset the tenant/role context: this session may reuse a pooled
            # connection left scoped (SET ROLE ccf_app + tenant GUC) by a prior
            # request. The audit trail must write unscoped, never as a stale tenant.
            await set_session_tenant(session, None)
            prev = (
                await session.execute(
                    select(AuditLog.row_hash).order_by(AuditLog.id.desc()).limit(1)
                )
            ).scalar_one_or_none() or _GENESIS
            session.add(
                AuditLog(
                    **content,
                    organization_id=org_id,
                    prev_hash=prev,
                    row_hash=row_hash(prev, content),
                )
            )
            await session.commit()
    except Exception as exc:  # pragma: no cover - audit must never break requests
        log.warning("audit.record_failed", error=str(exc), path=path)
    return response
