"""Enterprise identity — OIDC/SSO login, JIT provisioning, group→role, SCIM.

:mod:`ccf.identity.provisioning` holds the testable, transport-agnostic logic
(role resolution, JIT user creation, SCIM create/update/deactivate) and
:mod:`ccf.identity.oidc` the thin OIDC discovery + code-exchange client. Both
degrade safely: with OIDC disabled the app keeps its local session login.
"""

from __future__ import annotations

from .provisioning import (
    VALID_ROLES,
    domain_allowed,
    extract_groups,
    provision_from_oidc,
    resolve_role,
    scim_create_or_update_user,
    scim_deactivate_user,
    scim_user_resource,
)

__all__ = [
    "VALID_ROLES",
    "domain_allowed",
    "extract_groups",
    "provision_from_oidc",
    "resolve_role",
    "scim_create_or_update_user",
    "scim_deactivate_user",
    "scim_user_resource",
]
