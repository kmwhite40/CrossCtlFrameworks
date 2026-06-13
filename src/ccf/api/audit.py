"""Audit-trail middleware — persist mutations to ``ccf.audit_log``.

ARCHITECTURE.md noted the audit schema existed but was unwired. This records
every successful state-changing request (POST/PUT/PATCH/DELETE) with the actor
(from the ``X-Actor`` header, falling back to a configured default), the action,
the affected entity, and the request path. Best-effort: failures here never
break the request.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from fastapi import Request, Response

from ..config import get_settings
from ..db import get_session_factory
from ..logging import get_logger
from ..models import AuditLog

if TYPE_CHECKING:  # pragma: no cover
    from starlette.middleware.base import RequestResponseEndpoint

log = get_logger(__name__)

_MUTATING = {"POST", "PUT", "PATCH", "DELETE"}
_ACTION = {"POST": "create", "PUT": "update", "PATCH": "update", "DELETE": "delete"}
_SKIP_PREFIXES = ("/metrics", "/healthz", "/readyz", "/livez", "/static", "/api/audit")
_ID_RE = re.compile(r"\d+")


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


async def audit_middleware(
    request: Request, call_next: RequestResponseEndpoint
) -> Response:
    response = await call_next(request)
    method = request.method.upper()
    path = request.url.path
    if (
        method in _MUTATING
        and 200 <= response.status_code < 400
        and not path.startswith(_SKIP_PREFIXES)
    ):
        try:
            # Prefer the authenticated principal; fall back to the X-Actor header
            # (only meaningful when auth is disabled), then the configured default.
            principal = getattr(request.state, "principal", None)
            actor = (
                getattr(principal, "email", None)
                or request.headers.get("x-actor")
                or get_settings().audit_default_actor
            )
            entity_type, entity_id = _entity(path)
            factory = get_session_factory()
            async with factory() as session:
                session.add(
                    AuditLog(
                        actor=actor,
                        action=_ACTION.get(method, method.lower()),
                        entity_type=entity_type,
                        entity_id=entity_id,
                        diff={
                            "method": method,
                            "path": path,
                            "status": response.status_code,
                        },
                    )
                )
                await session.commit()
        except Exception as exc:  # pragma: no cover - audit must never break requests
            log.warning("audit.record_failed", error=str(exc), path=path)
    return response
