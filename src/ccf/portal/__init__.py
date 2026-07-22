"""External collaboration portal — scoped, expiring, audited external access.

Customers/assessors/vendors reach shared packages and evidence through a bearer
**token** grant (``ccf.models_portal``) — never an internal account. The service
is the single security boundary: it issues grants, validates tokens (rejecting
expired/revoked ones), clamps the session to the grant's tenant before any read,
and records every access in the immutable portal audit log.
"""

from __future__ import annotations

from .service import (
    add_comment,
    create_grant,
    grant_contents,
    list_grants,
    record_access,
    resolve_grant,
    resolve_grant_by_id,
    revoke_grant,
)

__all__ = [
    "add_comment",
    "create_grant",
    "grant_contents",
    "list_grants",
    "record_access",
    "resolve_grant",
    "resolve_grant_by_id",
    "revoke_grant",
]
