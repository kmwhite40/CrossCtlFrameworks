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
from sqlalchemy import select, text

from ..config import get_settings
from ..db import get_engine, get_session_factory, set_session_tenant, unscoped_read
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

#: Advisory-lock key serializing appends to the audit hash chain. Arbitrary but
#: fixed; see :func:`_lock_chain`.
_CHAIN_LOCK_KEY = 0x0CCFA9D1


async def _lock_chain(session: Any) -> None:
    """Serialize appends to the global audit chain within this transaction.

    Appending is read-head-then-insert, and the chain is a single global linear
    invariant (``/api/audit/verify`` walks every row from genesis in id order).
    Two transactions that read the head before either commits both compute
    ``prev_hash`` from the *same* predecessor, so the second row is not linked
    to the row that precedes it by id — a permanent fork, and every row
    appended afterwards inherits it. Two tenants writing at the same time is
    ordinary traffic for a multi-tenant platform, not an edge case, so without
    this the chain forks in normal operation and ``ok=False`` stops meaning
    "tampered" (AU-9).

    ``pg_advisory_xact_lock`` releases at COMMIT or ROLLBACK, which is exactly
    the window needed: the next appender must not read the head until this
    transaction's row is durable (or gone). It is re-entrant, so a caller that
    records several events in one transaction takes it once.

    TRADE-OFF: for :func:`record_event` the lock is held by the *caller's*
    transaction until the caller commits, which serializes audited writes
    platform-wide and, if a transaction takes row locks after recording an
    event, can deadlock (Postgres detects it and aborts one side). Both are
    inherent to a single global chain; a per-organization chain or a
    chain-head row would trade them for a schema change.

    No-op on SQLite (Reader build), which has no advisory locks and no
    concurrent writers to serialize.
    """
    if get_engine().dialect.name != "postgresql":
        return
    await session.execute(
        text("SELECT pg_advisory_xact_lock(:k)"), {"k": _CHAIN_LOCK_KEY}
    )


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
    organization_id: int | None,
) -> None:
    """Append one entry to the tamper-evident audit chain within ``session``.

    For events that don't originate from an auto-audited mutating HTTP request
    (e.g. OIDC/JIT provisioning during a GET callback, or role changes). Uses the
    same ``prev_hash``/``row_hash`` chaining as the middleware. Caller owns commit.

    ``organization_id`` is the tenant the event belongs to, and it is a REQUIRED
    keyword with no default: every caller must classify its own event. Like the
    middleware's, it is a SCOPING column only (DATA-06) and never enters
    ``content``/the hash payload, so setting it leaves existing chains and
    ``/api/audit/verify`` valid.

    ``None`` does not mean "unknown" or "not set" -- it means **platform-wide**,
    and it is not a safe default. Migration 0044's ``tenant_isolation`` predicate
    is ``current_tenant() IS NULL OR organization_id IS NULL OR organization_id =
    current_tenant()``: the middle clause deliberately publishes a NULL-org row
    to *every* tenant, so that genuinely deployment-wide events (adopting a
    catalog revision, pruning posture detail across all orgs) stay readable
    everywhere. A tenant-scoped event that lands ``None`` is therefore not
    merely unscoped -- it is broadcast to every organization on the deployment,
    readable through ``/api/audit`` by any scoped admin or assessor. That was
    live for every caller of this function until this parameter existed.

    Deliberately NOT derived from the session's RLS tenant, tempting as that is
    (the clamp is right there, and it would make a forgotten call site harmless).
    It would be wrong in both directions. ``ccf.catalog.revisions.adopt_revision``
    runs on the adopting admin's *tenant-clamped* request session but changes the
    catalog for the whole deployment, so derivation would hide a platform-wide
    change from every other tenant; conversely OIDC/JIT provisioning and SCIM run
    on an *unscoped* session -- there is no principal yet -- while provisioning a
    user into a known org, so derivation would broadcast them. The tenant an
    event is *about* is not reliably the tenant its session is clamped to, and
    only the call site knows which.

    The chain-head lookup runs under :func:`ccf.db.unscoped_read`. Unlike the
    middleware, which opens its own session and resets it to unscoped, this
    function appends inside the *caller's* session — and a request session is
    tenant-clamped by ``ccf.api.deps.get_session``. Since migration 0044 put a
    ``tenant_isolation`` RLS policy on ``audit_log``, reading the head through
    that clamp returns the latest row *this tenant can see*, not the latest row
    overall: any row written for another org in between is invisible, so the
    new row claims a predecessor that is not its predecessor by id and the
    chain forks. ``/api/audit/verify`` walks one global chain ordered by id and
    reports that fork as ``ok=False`` — a false tamper report in ordinary
    multi-tenant traffic, which is worse than a missed one, because it makes a
    real tamper indistinguishable from routine interleaving (AU-9).

    The clamp is suspended for the SELECT only and restored before the insert,
    so the ``WITH CHECK`` half of the policy still applies to the row written.

    The new row is flushed before returning. ``session.add`` alone leaves it
    pending, and these sessions are ``autoflush=False``, so a second event
    recorded in the same transaction would re-read the head and see the row
    *before* the first one — two rows claiming the same predecessor. Flushing
    only this object leaves the caller's own pending state untouched.
    """
    content = {
        "actor": actor,
        "action": action,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "diff": _redact(diff),
    }
    await _lock_chain(session)
    async with unscoped_read(session):
        prev = (
            await session.execute(
                select(AuditLog.row_hash).order_by(AuditLog.id.desc()).limit(1)
            )
        ).scalar_one_or_none() or _GENESIS
    entry = AuditLog(
        **content,
        organization_id=organization_id,
        prev_hash=prev,
        row_hash=row_hash(prev, content),
    )
    session.add(entry)
    await session.flush([entry])


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
            # Serialize against every other appender (see _lock_chain): this
            # session is unscoped, so the head it reads is the global head —
            # but a concurrent request could still insert between this read and
            # this commit and fork the chain.
            await _lock_chain(session)
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
