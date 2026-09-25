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
from datetime import datetime, timedelta
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

#: The one place the stale-account expectation is worded. A pack that
#: parameterizes the threshold re-renders this template, so the prose in an SSP
#: can never claim 90 days while the check enforces 60.
STALE_ACCOUNTS_EXPECTED = "no enabled account has been inactive longer than {threshold_days} days"

STALE_ACCOUNTS = PostureCheck(
    key="m365.identity.stale_accounts",
    title="No enabled account is inactive past the threshold",
    provider="msgraph",
    resource_type="entra_user",
    expected=STALE_ACCOUNTS_EXPECTED.format(threshold_days=STALE_ACCOUNT_DAYS),
    control_ids=("AC-2", "AC-2(3)"),
    required_permissions=("AuditLog.Read.All", "User.Read.All"),
)


#: Authentication methods that resist phishing: a hardware authenticator or a
#: certificate. IA-2(11) asks for one to be available, not for every other
#: method to be removed.
PHISHING_RESISTANT_METHODS = frozenset({"Fido2", "X509Certificate"})

#: Methods an attacker can intercept or socially engineer. SMS and voice are
#: interceptable via SIM swap and call forwarding; email is only as strong as
#: the mailbox, which is the thing being protected.
PHISHABLE_METHODS = frozenset({"Sms", "Voice", "Email"})

#: `allowInvitesFrom` values that let ordinary members invite external guests.
#: "everyone" additionally lets *guests* invite further guests.
UNRESTRICTED_INVITE_SETTINGS = frozenset({"everyone", "adminsGuestInvitersAndAllMembers"})

#: Default-user permissions that grant ordinary accounts privileged capability.
#: Wants to be an organization-defined parameter -- some tenants legitimately
#: let users register applications -- but a constant with a recorded intent is
#: honest where inventing configuration now is premature.
PRIVILEGED_DEFAULT_PERMISSIONS = (
    "allowedToCreateTenants",
    "allowedToCreateApps",
    "allowedToCreateSecurityGroups",
)


PHISHING_RESISTANT_MFA = PostureCheck(
    key="m365.identity.phishing_resistant_mfa",
    title="A phishing-resistant authentication method is enabled",
    provider="msgraph",
    resource_type="m365_tenant",
    expected="at least one of FIDO2 or certificate-based authentication is enabled",
    control_ids=("IA-2(11)",),
    required_permissions=("Policy.Read.All",),
)

PHISHABLE_METHODS_DISABLED = PostureCheck(
    key="m365.identity.phishable_methods_disabled",
    title="Interceptable authentication methods are disabled",
    provider="msgraph",
    resource_type="m365_tenant",
    expected="SMS, voice and email are not enabled as authentication methods",
    control_ids=("IA-2(1)", "IA-2(2)"),
    required_permissions=("Policy.Read.All",),
)

GUEST_INVITES_RESTRICTED = PostureCheck(
    key="m365.policy.guest_invites_restricted",
    title="Guest invitations are restricted to administrators",
    provider="msgraph",
    resource_type="m365_tenant",
    expected="inviting external guests is not open to all members",
    control_ids=("AC-3", "AC-6"),
    required_permissions=("Policy.Read.All",),
)

DEFAULT_USER_PERMISSIONS_RESTRICTED = PostureCheck(
    key="m365.policy.default_user_permissions_restricted",
    title="Default user permissions withhold privileged capability",
    provider="msgraph",
    resource_type="m365_tenant",
    expected=(
        "ordinary accounts cannot create tenants, register applications, or "
        "create security groups"
    ),
    control_ids=("AC-6", "AC-6(1)"),
    required_permissions=("Policy.Read.All",),
)

CHECKS: tuple[PostureCheck, ...] = (
    MFA_REGISTERED,
    LEGACY_AUTH_BLOCKED,
    STALE_ACCOUNTS,
    PHISHING_RESISTANT_MFA,
    PHISHABLE_METHODS_DISABLED,
    GUEST_INVITES_RESTRICTED,
    DEFAULT_USER_PERMISSIONS_RESTRICTED,
)

#: Graph collection each check reads, relative to the Graph base URL.
#:
#: STALE_ACCOUNTS carries ``$top=500``: with ``signInActivity`` selected,
#: Graph documents 500 (not the usual 999) as the maximum page size for
#: ``/users`` -- a higher ``$top`` is not rejected, it is just silently
#: clamped back down to 500, so asking for the true maximum is what actually
#: raises the ceiling. At ``_MAX_PAGES`` (50) that is ~25,000 users instead
#: of the ~5,000 the previous unpaged default page size (100) capped out at.
#: The other two endpoints are deliberately left without a ``$top``:
#: ``userRegistrationDetails`` documents only ``$filter`` as a supported
#: query parameter, no ``$top`` at all, so adding one would be a guess against
#: an endpoint that has never demonstrated it honors one. ``conditionalAccess/policies``
#: does document ``$top``, but a tenant's Conditional Access policy count is
#: nowhere near the page sizes that risk truncation here, so there is no
#: truncation this check is actually exposed to -- nothing to fix by adding one.
ENDPOINTS: dict[str, str] = {
    MFA_REGISTERED.key: "/v1.0/reports/authenticationMethods/userRegistrationDetails",
    LEGACY_AUTH_BLOCKED.key: "/v1.0/identity/conditionalAccess/policies",
    STALE_ACCOUNTS.key: (
        "/v1.0/users?$select=id,userPrincipalName,accountEnabled,signInActivity&$top=500"
    ),
    # Singleton resources: Graph returns the object itself with no `value`
    # envelope, which `_get_all` surfaces as a single row. Two checks share
    # each endpoint -- availability and absence are separate questions about
    # the same policy, and reporting them as one finding would hide whichever
    # half passed.
    PHISHING_RESISTANT_MFA.key: "/v1.0/policies/authenticationMethodsPolicy",
    PHISHABLE_METHODS_DISABLED.key: "/v1.0/policies/authenticationMethodsPolicy",
    GUEST_INVITES_RESTRICTED.key: "/v1.0/policies/authorizationPolicy",
    DEFAULT_USER_PERMISSIONS_RESTRICTED.key: "/v1.0/policies/authorizationPolicy",
}


def _user_ref(row: dict[str, Any]) -> str:
    """UPN where Graph gave one, else the object id -- never empty."""
    upn = row.get("userPrincipalName")
    if isinstance(upn, str) and upn:
        return upn
    return str(row.get("id") or "unknown")


def evaluate_mfa_registered(rows: list[dict[str, Any]]) -> list[ResourceFinding]:
    """One finding per user: can the user actually complete MFA?

    Known limitation: ``userRegistrationDetails`` does not expose
    ``accountEnabled``, so every user Graph returns is assessed, disabled
    accounts included. ``userType`` and ``isAdmin`` are recorded in ``detail``
    so an operator can see what was counted. Joining ``/users`` to exclude
    disabled accounts is not something Graph supports cheaply, and inventing
    that join would trade a stated limitation for a hidden one.
    """
    findings: list[ResourceFinding] = []
    for row in rows:
        # isMfaCapable, not isMfaRegistered, decides the verdict.
        # isMfaRegistered is true whenever the user registered *some* strong
        # auth method, even one the tenant's authentication methods policy no
        # longer allows (e.g. SMS after it was disallowed) -- that user is
        # registered but cannot actually complete MFA with an allowed method.
        # isMfaCapable is true only when the registered method is one the
        # policy currently allows, so it already implies registration; a
        # control asserting MFA must not count the former as compliant.
        capable = bool(row.get("isMfaCapable"))
        registered = bool(row.get("isMfaRegistered"))
        if capable:
            observed = "MFA-capable: a policy-allowed method is registered"
        elif registered:
            observed = (
                "not MFA-capable: a method is registered but not allowed by "
                "the current authentication methods policy"
            )
        else:
            observed = "not MFA-capable: no MFA method registered"
        findings.append(
            ResourceFinding(
                resource_id=_user_ref(row),
                resource_type="entra_user",
                verdict="pass" if capable else "fail",
                observed=observed,
                detail={
                    "userType": row.get("userType"),
                    "isAdmin": row.get("isAdmin"),
                    "isMfaRegistered": registered,
                },
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
    rows: list[dict[str, Any]], *, now: datetime, threshold_days: int = STALE_ACCOUNT_DAYS
) -> list[ResourceFinding]:
    """One finding per user: has an enabled account gone inactive?

    ``now`` is a parameter so the evaluator stays pure and the threshold is
    testable without freezing the clock. ``threshold_days`` defaults to the
    module constant, so every existing caller is unaffected; a pack supplies
    its own through :mod:`ccf.posture.parameters` (Form A), which is what the
    constant's own note above always wanted.

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
        elapsed = now - last
        # Compare the full-precision delta against the threshold, not
        # `elapsed.days`: `.days` truncates, so 90.9 days inactive would
        # report `90` and pass a 90-day threshold -- an effective threshold
        # of 91, not 90.
        findings.append(
            ResourceFinding(
                resource_id=ref,
                resource_type="entra_user",
                verdict="fail" if elapsed > timedelta(days=threshold_days) else "pass",
                observed=f"last interactive sign-in {elapsed.days} day(s) ago",
                detail={"last_sign_in": activity.get("lastSignInDateTime")},
            )
        )
    return findings


#: Check key -> its evaluator. ``scan`` dispatches through this rather than a
#: chain of conditionals, so adding a check is a registry entry.

def _enabled_methods(rows: list[dict[str, Any]]) -> set[str]:
    """Ids of authentication methods the tenant has enabled.

    The policy is one object with an ``authenticationMethodConfigurations``
    list, each entry carrying an ``id`` and a ``state`` of ``enabled`` or
    ``disabled``. An entry Graph omits is not enabled -- absence and
    ``disabled`` mean the same thing here.
    """
    policy = rows[0] if rows else {}
    configs = policy.get("authenticationMethodConfigurations") or []
    return {
        str(m.get("id"))
        for m in configs
        if isinstance(m, dict) and m.get("state") == "enabled"
    }


def evaluate_phishing_resistant_mfa(
    rows: list[dict[str, Any]], *, tenant_id: str
) -> list[ResourceFinding]:
    """IA-2(11): at least one phishing-resistant method is available."""
    enabled = _enabled_methods(rows)
    available = sorted(enabled & PHISHING_RESISTANT_METHODS)
    if available:
        return [
            ResourceFinding(
                resource_id=tenant_id,
                resource_type="m365_tenant",
                verdict="pass",
                observed=f"phishing-resistant method(s) enabled: {', '.join(available)}",
                detail={"enabled": available},
            )
        ]
    return [
        ResourceFinding(
            resource_id=tenant_id,
            resource_type="m365_tenant",
            verdict="fail",
            observed=(
                "no phishing-resistant method is enabled; expected one of "
                f"{', '.join(sorted(PHISHING_RESISTANT_METHODS))}"
            ),
            detail={"enabled_methods": sorted(enabled)},
        )
    ]


def evaluate_phishable_methods_disabled(
    rows: list[dict[str, Any]], *, tenant_id: str
) -> list[ResourceFinding]:
    """IA-2(1)/(2): SMS, voice and email are not accepted as factors.

    Separate from the check above because they are separate questions: a
    tenant can offer FIDO2 *and* still accept SMS, and an attacker only has
    to defeat the weakest method the tenant will accept.
    """
    enabled = _enabled_methods(rows)
    offending = sorted(enabled & PHISHABLE_METHODS)
    if not offending:
        return [
            ResourceFinding(
                resource_id=tenant_id,
                resource_type="m365_tenant",
                verdict="pass",
                observed="no interceptable authentication method is enabled",
                detail={"enabled_methods": sorted(enabled)},
            )
        ]
    return [
        ResourceFinding(
            resource_id=tenant_id,
            resource_type="m365_tenant",
            verdict="fail",
            observed=f"interceptable method(s) enabled: {', '.join(offending)}",
            detail={"offending": offending},
        )
    ]


def evaluate_guest_invites_restricted(
    rows: list[dict[str, Any]], *, tenant_id: str
) -> list[ResourceFinding]:
    """AC-3/AC-6: inviting external guests is not open to every member."""
    policy = rows[0] if rows else {}
    setting = policy.get("allowInvitesFrom")
    if setting is None:
        return [
            ResourceFinding(
                resource_id=tenant_id,
                resource_type="m365_tenant",
                verdict="not_applicable",
                observed="the tenant reported no guest-invitation setting",
                detail={},
            )
        ]
    if str(setting) in UNRESTRICTED_INVITE_SETTINGS:
        return [
            ResourceFinding(
                resource_id=tenant_id,
                resource_type="m365_tenant",
                verdict="fail",
                observed=f"guest invitations are open to {setting!r}",
                detail={"allowInvitesFrom": setting},
            )
        ]
    return [
        ResourceFinding(
            resource_id=tenant_id,
            resource_type="m365_tenant",
            verdict="pass",
            observed=f"guest invitations restricted to {setting!r}",
            detail={"allowInvitesFrom": setting},
        )
    ]


def evaluate_default_user_permissions(
    rows: list[dict[str, Any]], *, tenant_id: str
) -> list[ResourceFinding]:
    """AC-6: an ordinary account does not carry privileged capability."""
    policy = rows[0] if rows else {}
    permissions = policy.get("defaultUserRolePermissions")
    if not isinstance(permissions, dict):
        return [
            ResourceFinding(
                resource_id=tenant_id,
                resource_type="m365_tenant",
                verdict="not_applicable",
                observed="the tenant reported no default user-role permissions",
                detail={},
            )
        ]
    granted = [name for name in PRIVILEGED_DEFAULT_PERMISSIONS if permissions.get(name) is True]
    if not granted:
        return [
            ResourceFinding(
                resource_id=tenant_id,
                resource_type="m365_tenant",
                verdict="pass",
                observed="default users hold none of the privileged capabilities checked",
                detail={"checked": list(PRIVILEGED_DEFAULT_PERMISSIONS)},
            )
        ]
    return [
        ResourceFinding(
            resource_id=tenant_id,
            resource_type="m365_tenant",
            verdict="fail",
            observed=f"default users may: {', '.join(granted)}",
            detail={"granted": granted},
        )
    ]


EVALUATORS: dict[str, Callable[..., list[ResourceFinding]]] = {
    MFA_REGISTERED.key: evaluate_mfa_registered,
    LEGACY_AUTH_BLOCKED.key: evaluate_legacy_auth_blocked,
    STALE_ACCOUNTS.key: evaluate_stale_accounts,
    PHISHING_RESISTANT_MFA.key: evaluate_phishing_resistant_mfa,
    PHISHABLE_METHODS_DISABLED.key: evaluate_phishable_methods_disabled,
    GUEST_INVITES_RESTRICTED.key: evaluate_guest_invites_restricted,
    DEFAULT_USER_PERMISSIONS_RESTRICTED.key: evaluate_default_user_permissions,
}
