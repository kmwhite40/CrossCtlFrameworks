"""Microsoft 365 / Entra posture checks.

Three checks spanning three resource shapes -- a per-user fleet, a tenant-level
singleton, and a per-user check with exclusions -- so the posture spine is
exercised across all of them rather than three variations of one.

Every evaluator here is pure: it takes the rows a Graph collection returned and
returns findings. No network, no clock, no database -- ``now`` is passed in --
so each is unit-testable against a recorded Graph shape, which matters because
no live tenant is reachable from the build environment.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

from ..types import PostureCheck, ResourceFinding

#: Inactivity threshold for the stale-account check. Wants to be an
#: organization-defined parameter -- the ODP machinery already exists for
#: exactly this -- but binding it is its own change, and a constant with a
#: recorded intent is honest where inventing configuration now is premature.
STALE_ACCOUNT_DAYS = 90

#: Graph client app types that mean legacy (pre-modern-auth) authentication.
_LEGACY_CLIENT_APP_TYPES = frozenset({"exchangeActiveSync", "other"})


MFA_REGISTERED = PostureCheck(
    key="m365.identity.mfa_registered",
    title="Every user has an MFA method registered",
    provider="msgraph",
    resource_type="entra_user",
    expected="every user has a multi-factor authentication method registered",
    control_ids=("IA-2", "IA-2(1)"),
    required_permissions=("AuditLog.Read.All",),
)

LEGACY_AUTH_BLOCKED = PostureCheck(
    key="m365.policy.legacy_auth_blocked",
    title="Legacy authentication is blocked",
    provider="msgraph",
    resource_type="m365_tenant",
    expected="an enabled Conditional Access policy blocks legacy authentication clients",
    control_ids=("IA-2", "AC-17"),
    required_permissions=("Policy.Read.All",),
)

STALE_ACCOUNTS = PostureCheck(
    key="m365.identity.stale_accounts",
    title="No enabled account is inactive past the threshold",
    provider="msgraph",
    resource_type="entra_user",
    expected=f"no enabled account has been inactive longer than {STALE_ACCOUNT_DAYS} days",
    control_ids=("AC-2", "AC-2(3)"),
    required_permissions=("AuditLog.Read.All", "User.Read.All"),
)

CHECKS: tuple[PostureCheck, ...] = (MFA_REGISTERED, LEGACY_AUTH_BLOCKED, STALE_ACCOUNTS)

#: Graph collection each check reads, relative to the Graph base URL.
ENDPOINTS: dict[str, str] = {
    MFA_REGISTERED.key: "/v1.0/reports/authenticationMethods/userRegistrationDetails",
    LEGACY_AUTH_BLOCKED.key: "/v1.0/identity/conditionalAccess/policies",
    STALE_ACCOUNTS.key: "/v1.0/users?$select=id,userPrincipalName,accountEnabled,signInActivity",
}


def _user_ref(row: dict[str, Any]) -> str:
    """UPN where Graph gave one, else the object id -- never empty."""
    upn = row.get("userPrincipalName")
    if isinstance(upn, str) and upn:
        return upn
    return str(row.get("id") or "unknown")


def evaluate_mfa_registered(rows: list[dict[str, Any]]) -> list[ResourceFinding]:
    """One finding per user: is an MFA method registered?

    Known limitation: ``userRegistrationDetails`` does not expose
    ``accountEnabled``, so every user Graph returns is assessed, disabled
    accounts included. ``userType`` and ``isAdmin`` are recorded in ``detail``
    so an operator can see what was counted. Joining ``/users`` to exclude
    disabled accounts is not something Graph supports cheaply, and inventing
    that join would trade a stated limitation for a hidden one.
    """
    findings: list[ResourceFinding] = []
    for row in rows:
        registered = bool(row.get("isMfaRegistered"))
        findings.append(
            ResourceFinding(
                resource_id=_user_ref(row),
                resource_type="entra_user",
                verdict="pass" if registered else "fail",
                observed=("MFA method registered" if registered else "no MFA method registered"),
                detail={"userType": row.get("userType"), "isAdmin": row.get("isAdmin")},
            )
        )
    return findings


def _blocks_legacy_auth(policy: dict[str, Any]) -> bool:
    """True when an *enforced* policy blocks legacy clients.

    ``state`` must be exactly ``enabled``: ``disabled`` enforces nothing, and
    ``enabledForReportingButNotEnforced`` reports without blocking, so neither
    may satisfy the check. The existing ``_map_mfa`` and
    ``_map_conditional_access`` mappers apply the same test.
    """
    if (policy.get("state") or "") != "enabled":
        return False
    app_types = set((policy.get("conditions") or {}).get("clientAppTypes") or [])
    if not (app_types & _LEGACY_CLIENT_APP_TYPES):
        return False
    controls = (policy.get("grantControls") or {}).get("builtInControls") or []
    return "block" in controls


def evaluate_legacy_auth_blocked(
    rows: list[dict[str, Any]], *, tenant_id: str
) -> list[ResourceFinding]:
    """Exactly one finding: the tenant is the resource.

    A tenant-level boolean still produces a ``ResourceFinding`` so one result
    model covers every shape, and so "which resource failed" has an answer
    here too.
    """
    blocking = next((p for p in rows if _blocks_legacy_auth(p)), None)
    if blocking is not None:
        return [
            ResourceFinding(
                resource_id=tenant_id,
                resource_type="m365_tenant",
                verdict="pass",
                observed=(
                    "blocked by Conditional Access policy "
                    f"{blocking.get('displayName') or blocking.get('id')!r}"
                ),
                detail={"policy_id": blocking.get("id")},
            )
        ]
    return [
        ResourceFinding(
            resource_id=tenant_id,
            resource_type="m365_tenant",
            verdict="fail",
            observed="no enabled Conditional Access policy blocks legacy authentication",
            detail={"policies_examined": len(rows)},
        )
    ]


def _parse_graph_datetime(value: Any) -> datetime | None:
    """Graph timestamps are ISO-8601 with a ``Z``; anything else is unusable."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def evaluate_stale_accounts(
    rows: list[dict[str, Any]], *, now: datetime
) -> list[ResourceFinding]:
    """One finding per user: has an enabled account gone inactive?

    ``now`` is a parameter so the evaluator stays pure and the threshold is
    testable without freezing the clock.

    Two cases are ``not_applicable`` rather than ``pass`` or ``fail``. A
    disabled account is not a stale-access risk. And Graph omits
    ``signInActivity`` without the right licence -- absence of a timestamp is
    not evidence of staleness, and calling it ``pass`` would assert something
    never observed.

    Uses ``lastSignInDateTime``, the *interactive* timestamp:
    ``lastNonInteractiveSignInDateTime`` moves on background token refresh, so
    an abandoned account looks active indefinitely under it.
    """
    findings: list[ResourceFinding] = []
    for row in rows:
        ref = _user_ref(row)
        if not row.get("accountEnabled", False):
            findings.append(
                ResourceFinding(
                    resource_id=ref,
                    resource_type="entra_user",
                    verdict="not_applicable",
                    observed="account disabled",
                )
            )
            continue
        activity = row.get("signInActivity") or {}
        last = _parse_graph_datetime(activity.get("lastSignInDateTime"))
        if last is None:
            findings.append(
                ResourceFinding(
                    resource_id=ref,
                    resource_type="entra_user",
                    verdict="not_applicable",
                    observed="no interactive sign-in activity reported",
                )
            )
            continue
        days = (now - last).days
        findings.append(
            ResourceFinding(
                resource_id=ref,
                resource_type="entra_user",
                verdict="fail" if days > STALE_ACCOUNT_DAYS else "pass",
                observed=f"last interactive sign-in {days} day(s) ago",
                detail={"last_sign_in": activity.get("lastSignInDateTime")},
            )
        )
    return findings


#: Check key -> its evaluator. ``scan`` dispatches through this rather than a
#: chain of conditionals, so adding a check is a registry entry.
EVALUATORS: dict[str, Callable[..., list[ResourceFinding]]] = {
    MFA_REGISTERED.key: evaluate_mfa_registered,
    LEGACY_AUTH_BLOCKED.key: evaluate_legacy_auth_blocked,
    STALE_ACCOUNTS.key: evaluate_stale_accounts,
}
