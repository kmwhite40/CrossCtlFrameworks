"""Microsoft 365 / Entra posture checks.

Checks across three resource shapes -- a per-user fleet, a per-device fleet, and
a tenant-level singleton -- so the posture spine is exercised on all of them
rather than on variations of one. ``CHECKS`` is the list; this sentence
deliberately does not restate its length, because the previous one said "three"
for as long as it took to reach fourteen.

Choosing the shape is the judgement that matters here. A per-resource verdict is
right when every resource is genuinely in scope for the question -- every user
should have an MFA method, every managed device should meet its assigned policy.
It is wrong when a resource can legitimately be silent: an Intune compliance
policy scoped to disk encryption configures no screen lock, and failing it for
that would manufacture a finding against a correctly-narrow policy. Those
questions are asked of the tenant, and the answer names the policy that
satisfied it.

Every evaluator here is pure: it takes the rows a Graph collection returned and
returns findings. No network, no clock, no database -- ``now`` is passed in --
so each is unit-testable against a recorded Graph shape, which matters because
no live tenant is reachable from the build environment.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
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


#: An audit trail is evidence only if it is current. Graph returns the most
#: recent records first, so a newest record older than this means the tenant
#: has stopped producing auditable events, the connector has lost the
#: permission, or retention has already expired them -- each worth a finding.
AUDIT_RECENCY_DAYS = 7

#: Intune compliance states that are not "this device meets the baseline".
#: `unknown` and `notApplicable` are excluded rather than failed: a device
#: Intune has not evaluated has not been shown to be non-compliant, and
#: scoring it as a failure would invent a finding.
DEVICE_NONCOMPLIANT_STATES = frozenset(
    {"noncompliant", "conflict", "error", "inGracePeriod"}
)
DEVICE_UNEVALUATED_STATES = frozenset({"unknown", "notApplicable", "configManager"})

#: Risk states meaning nobody has dealt with the user yet. `remediated`,
#: `dismissed` and `confirmedSafe` are all dispositions -- someone looked.
RISK_UNRESOLVED_STATES = frozenset({"atRisk", "confirmedCompromised"})


SIGNIN_AUDIT_CURRENT = PostureCheck(
    key="m365.audit.signin_records_current",
    title="Sign-in audit records are being produced",
    provider="msgraph",
    resource_type="m365_tenant",
    expected=f"a sign-in audit record exists within the last {AUDIT_RECENCY_DAYS} days",
    control_ids=("AU-2", "AU-12"),
    required_permissions=("AuditLog.Read.All",),
)

DIRECTORY_AUDIT_CURRENT = PostureCheck(
    key="m365.audit.directory_changes_recorded",
    title="Directory changes are recorded in the audit log",
    provider="msgraph",
    resource_type="m365_tenant",
    expected=f"a directory audit record exists within the last {AUDIT_RECENCY_DAYS} days",
    control_ids=("AU-2", "AU-3", "AU-12"),
    required_permissions=("AuditLog.Read.All",),
)

DEVICE_COMPLIANCE = PostureCheck(
    key="m365.device.compliance_enforced",
    title="Managed devices meet their compliance baseline",
    provider="msgraph",
    resource_type="managed_device",
    expected="every evaluated managed device is compliant with its assigned policy",
    control_ids=("CM-6", "CM-2", "SI-2"),
    required_permissions=("DeviceManagementManagedDevices.Read.All",),
)

RISKY_USERS_RESOLVED = PostureCheck(
    key="m365.identity.risky_users_resolved",
    title="Flagged risky users have been dealt with",
    provider="msgraph",
    resource_type="entra_user",
    expected="no user remains at risk without a disposition",
    control_ids=("AC-2(12)", "SI-4", "AU-6"),
    required_permissions=("IdentityRiskyUser.Read.All",),
)

#: Intune compliance-policy property names that configure an inactivity lock.
#: Every platform-specific policy type Graph returns spells it the same way, but
#: a policy that governs something else (encryption only, OS version only) does
#: not carry it -- which is why the question below is asked of the *tenant*
#: rather than of each policy. Per-policy verdicts would fail a
#: legitimately-narrow policy for not doing a job it was never given.
_LOCK_TIMEOUT_KEY = "passwordMinutesOfInactivityBeforeLock"
_LOCK_REQUIRED_KEY = "passwordRequired"

#: Upper bound on an inactivity lock, in minutes. FedRAMP and CMMC both leave
#: the period organization-defined; 15 minutes is the figure the DoD STIGs and
#: the CIS Microsoft 365 benchmark use, and it is recorded here rather than
#: invented per call site. Wants to be an ODP like STALE_ACCOUNT_DAYS.
SESSION_LOCK_MAX_MINUTES = 15

#: The one place this expectation is worded. A pack that parameterizes the
#: period re-renders this template, so an SSP statement can never claim 15
#: minutes while the check enforces 30 -- the same contract STALE_ACCOUNTS has.
SESSION_LOCK_EXPECTED = (
    "at least one device compliance policy requires a password and locks the screen "
    "after no more than {max_minutes} minutes of inactivity"
)

SESSION_LOCK_ENFORCED = PostureCheck(
    key="m365.device.session_lock_enforced",
    title="A device compliance policy locks the screen after inactivity",
    provider="msgraph",
    resource_type="m365_tenant",
    expected=SESSION_LOCK_EXPECTED.format(max_minutes=SESSION_LOCK_MAX_MINUTES),
    control_ids=("AC-11", "AC-11(1)"),
    required_permissions=("DeviceManagementConfiguration.Read.All",),
)

#: Default bound for 3.1.8. Organization-defined, so it is a parameter rather
#: than a constant -- DoD guidance commonly says three, FedRAMP Moderate says
#: not more than three in a fifteen-minute window, and a tenant may justify
#: another number. The check judges against whatever it is told.
LOCKOUT_MAX_ATTEMPTS = 10
LOCKOUT_EXPECTED = (
    "the tenant's sign-in lockout threshold is enabled and no greater than "
    "{max_attempts} failed attempts"
)

#: How long a high-severity alert may sit unactioned before it is a finding.
#: 3.14.3 asks for a response, and responding takes time; failing an alert
#: raised this morning would make every tenant fail permanently, which is
#: indistinguishable from having no check.
ALERT_TRIAGE_DAYS = 30
ALERT_TRIAGE_EXPECTED = (
    "no high or critical security alert has been left unresolved for more than "
    "{threshold_days} days"
)

#: Alert states that mean nobody has finished with it yet.
_ALERT_OPEN_STATES = frozenset({"new", "inprogress"})
#: Severities worth failing a control over. Informational and low alerts left
#: open are noise, not a control failure.
_ALERT_ACTIONABLE_SEVERITIES = frozenset({"high", "critical"})

#: The Graph directory-setting that carries the lockout threshold, and the key
#: inside it. Confirmed against a live tenant: `/beta/settings` returns a
#: "Password Rule Settings" object whose values include `LockoutThreshold`.
_PASSWORD_SETTINGS_NAME = "Password Rule Settings"
_LOCKOUT_THRESHOLD_KEY = "LockoutThreshold"
_LOCKOUT_DURATION_KEY = "LockoutDurationInSeconds"

#: The Intune general-configuration field that blocks removable storage.
_REMOVABLE_STORAGE_KEY = "storageBlockRemovableStorage"

LOCKOUT_THRESHOLD = PostureCheck(
    key="m365.identity.lockout_threshold_enforced",
    title="Sign-in lockout is enabled with a bounded threshold",
    provider="msgraph",
    resource_type="m365_tenant",
    expected=LOCKOUT_EXPECTED.format(max_attempts=LOCKOUT_MAX_ATTEMPTS),
    control_ids=("AC-7", "AC-7(1)"),
    required_permissions=("Directory.Read.All",),
)

SECURITY_ALERTS_TRIAGED = PostureCheck(
    key="m365.security.alerts_triaged",
    title="No high-severity security alert is left unactioned",
    provider="msgraph",
    resource_type="m365_security_alert",
    expected=ALERT_TRIAGE_EXPECTED.format(threshold_days=ALERT_TRIAGE_DAYS),
    control_ids=("SI-4", "SI-5", "IR-4"),
    required_permissions=("SecurityAlert.Read.All",),
)

REMOVABLE_STORAGE_BLOCKED = PostureCheck(
    key="m365.device.removable_storage_blocked",
    title="A device configuration blocks removable storage",
    provider="msgraph",
    resource_type="m365_tenant",
    expected="at least one device configuration profile blocks removable storage",
    control_ids=("MP-7", "AC-20(2)"),
    required_permissions=("DeviceManagementConfiguration.Read.All",),
)

STORAGE_ENCRYPTION_REQUIRED = PostureCheck(
    key="m365.device.storage_encryption_required",
    title="A device compliance policy requires storage encryption",
    provider="msgraph",
    resource_type="m365_tenant",
    expected="at least one device compliance policy requires device storage to be encrypted",
    # AC-19(5) is the mobile-device arm of the same requirement: it asks for
    # full-device or container encryption on the devices this policy governs.
    control_ids=("SC-28", "SC-28(1)", "AC-19(5)"),
    required_permissions=("DeviceManagementConfiguration.Read.All",),
)

#: Conditional Access session controls that force reauthentication.
_SIGNIN_FREQUENCY_KEY = "signInFrequency"

SESSION_REAUTHENTICATION_REQUIRED = PostureCheck(
    key="m365.policy.session_reauthentication_required",
    title="Conditional Access forces periodic reauthentication",
    provider="msgraph",
    resource_type="m365_tenant",
    expected=(
        "an enabled Conditional Access policy sets a sign-in frequency, so a session "
        "cannot continue indefinitely without reauthenticating"
    ),
    control_ids=("AC-12",),
    required_permissions=("Policy.Read.All",),
)


SYSTEM_USE_NOTIFICATION = PostureCheck(
    key="m365.identity.system_use_notification",
    title="A system use notification is displayed before access is granted",
    provider="msgraph",
    resource_type="m365_tenant",
    expected=(
        "at least one terms-of-use agreement that the user must be shown before "
        "accepting (isViewingBeforeAcceptanceRequired)"
    ),
    # AC-8 alone. The related controls an SSP author might reach for -- AC-14,
    # PL-4 -- are about what is permitted without identification and about rules
    # of behaviour; an agreement banner evidences neither, and declaring them
    # would put this check's verdict against controls it never observed.
    control_ids=("AC-8",),
    required_permissions=("Agreement.Read.All",),
)

CHECKS: tuple[PostureCheck, ...] = (
    MFA_REGISTERED,
    LEGACY_AUTH_BLOCKED,
    STALE_ACCOUNTS,
    PHISHING_RESISTANT_MFA,
    PHISHABLE_METHODS_DISABLED,
    GUEST_INVITES_RESTRICTED,
    DEFAULT_USER_PERMISSIONS_RESTRICTED,
    SIGNIN_AUDIT_CURRENT,
    DIRECTORY_AUDIT_CURRENT,
    DEVICE_COMPLIANCE,
    RISKY_USERS_RESOLVED,
    SESSION_LOCK_ENFORCED,
    STORAGE_ENCRYPTION_REQUIRED,
    SESSION_REAUTHENTICATION_REQUIRED,    LOCKOUT_THRESHOLD,
    SECURITY_ALERTS_TRIAGED,
    SYSTEM_USE_NOTIFICATION,
    REMOVABLE_STORAGE_BLOCKED,
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
    # `$top=1` deliberately: the question is whether a recent record exists,
    # not what happened. Graph returns these newest-first, so one row answers
    # it -- and a tenant's sign-in log is the largest collection in Graph.
    SIGNIN_AUDIT_CURRENT.key: "/v1.0/auditLogs/signIns?$top=1",
    DIRECTORY_AUDIT_CURRENT.key: "/v1.0/auditLogs/directoryAudits?$top=1",
    DEVICE_COMPLIANCE.key: (
        "/v1.0/deviceManagement/managedDevices"
        "?$select=id,deviceName,complianceState,operatingSystem&$top=500"
    ),
    RISKY_USERS_RESOLVED.key: (
        "/v1.0/identityProtection/riskyUsers"
        "?$select=id,userPrincipalName,riskLevel,riskState&$top=500"
    ),
    # Compliance *policies*, not devices -- a different collection from
    # DEVICE_COMPLIANCE's `managedDevices`, and a different question: whether
    # the tenant requires these things at all, rather than whether a given
    # device currently meets what it was assigned. No `$select`: the property
    # set differs per platform-specific policy type, and selecting a field a
    # type does not declare makes Graph reject the whole request.
    SESSION_LOCK_ENFORCED.key: "/v1.0/deviceManagement/deviceCompliancePolicies",
    STORAGE_ENCRYPTION_REQUIRED.key: "/v1.0/deviceManagement/deviceCompliancePolicies",
    SESSION_REAUTHENTICATION_REQUIRED.key: "/v1.0/identity/conditionalAccess/policies",
    # `/beta` deliberately: the lockout threshold lives in a directory-settings
    # object that v1.0 does not expose. Confirmed readable on a live tenant --
    # "Password Rule Settings" with LockoutThreshold and LockoutDurationInSeconds.
    LOCKOUT_THRESHOLD.key: "/beta/settings",
    SECURITY_ALERTS_TRIAGED.key: "/v1.0/security/alerts_v2",
    # Configuration profiles, not compliance policies: removable storage is a
    # device *restriction*, so it is set on windows10GeneralConfiguration rather
    # than on the compliance policies the lock and encryption checks read.
    REMOVABLE_STORAGE_BLOCKED.key: "/v1.0/deviceManagement/deviceConfigurations",
    # Verified against the live GCC High tenant, not only against Graph's
    # published $metadata: this returns agreements carrying
    # isViewingBeforeAcceptanceRequired on graph.microsoft.us.
    #
    # The AT-2 check that shipped beside this one has been removed, and the reason
    # is why this comment now says "verified against the tenant". It read
    # /v1.0/security/attackSimulation/simulations, which IS in the v1.0 model --
    # but the model published at graph.microsoft.com is the *commercial* one, and
    # graph.microsoft.us answers `400 BadRequest: Resource not found for the
    # segment 'attackSimulation'` on both v1.0 and beta while /v1.0/security
    # itself answers 200. A cloud capability gap, not a licensing one, which would
    # answer 403. The check would have reported manual_review_required forever on
    # every GCC High tenant and read as a tenant problem.
    SYSTEM_USE_NOTIFICATION.key: "/v1.0/identityGovernance/termsOfUse/agreements",
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



def _audit_recency(
    rows: list[dict[str, Any]], *, tenant_id: str, now: datetime, field: str, label: str
) -> list[ResourceFinding]:
    """Shared by both audit checks: is the newest record recent enough?

    An empty collection is a failure, not "nothing to assess". A tenant with
    no audit records in the window is either not producing them, has lost the
    permission, or has let retention expire them -- and every one of those is
    the finding AU-2 exists to catch. Treating it as not-applicable would turn
    the absence of an audit trail into silence.
    """
    newest = None
    for row in rows:
        stamp = _parse_graph_datetime(row.get(field))
        if stamp and (newest is None or stamp > newest):
            newest = stamp
    if newest is None:
        return [
            ResourceFinding(
                resource_id=tenant_id,
                resource_type="m365_tenant",
                verdict="fail",
                observed=f"no {label} record was returned",
                detail={"records_examined": len(rows)},
            )
        ]
    age = (now - newest).days
    verdict = "pass" if age <= AUDIT_RECENCY_DAYS else "fail"
    return [
        ResourceFinding(
            resource_id=tenant_id,
            resource_type="m365_tenant",
            verdict=verdict,
            observed=f"most recent {label} record is {age} day(s) old",
            detail={"newest": newest.isoformat(), "threshold_days": AUDIT_RECENCY_DAYS},
        )
    ]


def evaluate_signin_audit_current(
    rows: list[dict[str, Any]], *, tenant_id: str, now: datetime
) -> list[ResourceFinding]:
    return _audit_recency(
        rows, tenant_id=tenant_id, now=now, field="createdDateTime", label="sign-in"
    )


def evaluate_directory_audit_current(
    rows: list[dict[str, Any]], *, tenant_id: str, now: datetime
) -> list[ResourceFinding]:
    return _audit_recency(
        rows, tenant_id=tenant_id, now=now, field="activityDateTime", label="directory audit"
    )


def evaluate_device_compliance(rows: list[dict[str, Any]]) -> list[ResourceFinding]:
    """CM-6: every device Intune has evaluated meets its assigned policy.

    A device in an unevaluated state is `not_applicable`, not a failure: it
    has not been shown to be non-compliant, and scoring it as one would invent
    a finding against a device nobody has assessed.
    """
    findings: list[ResourceFinding] = []
    for row in rows:
        state = str(row.get("complianceState") or "unknown")
        ref = str(row.get("deviceName") or row.get("id") or "unknown device")
        if state in DEVICE_UNEVALUATED_STATES:
            verdict, observed = "not_applicable", f"not evaluated ({state})"
        elif state in DEVICE_NONCOMPLIANT_STATES:
            verdict, observed = "fail", f"{state} against its assigned policy"
        else:
            verdict, observed = "pass", f"compliant ({row.get('operatingSystem') or 'unknown OS'})"
        findings.append(
            ResourceFinding(
                resource_id=str(row.get("id") or ref),
                resource_type="managed_device",
                verdict=verdict,
                observed=f"{ref}: {observed}",
                detail={"complianceState": state},
            )
        )
    return findings


def evaluate_risky_users_resolved(rows: list[dict[str, Any]]) -> list[ResourceFinding]:
    """AC-2(12): a flagged user has had a disposition, whatever it was.

    `remediated`, `dismissed` and `confirmedSafe` all mean somebody looked --
    the control is about responding to the signal, not about the verdict.
    Only a user still `atRisk` or `confirmedCompromised` is outstanding.
    """
    findings: list[ResourceFinding] = []
    for row in rows:
        state = str(row.get("riskState") or "unknown")
        level = str(row.get("riskLevel") or "unknown")
        ref = str(row.get("userPrincipalName") or row.get("id") or "unknown user")
        outstanding = state in RISK_UNRESOLVED_STATES
        findings.append(
            ResourceFinding(
                resource_id=str(row.get("id") or ref),
                resource_type="entra_user",
                verdict="fail" if outstanding else "pass",
                observed=(
                    f"{ref}: risk {level}, {state}"
                    if outstanding
                    else f"{ref}: {state}"
                ),
                detail={"riskState": state, "riskLevel": level},
            )
        )
    return findings


def _tenant_finding(
    tenant_id: str,
    *,
    passed: bool,
    observed: str,
    detail: dict[str, Any],
    unassessable: bool = False,
) -> list[ResourceFinding]:
    """One finding, the tenant as the resource.

    Several tenant-level checks share this shape. It was already written inline
    twice in `evaluate_legacy_auth_blocked`; a fourth and fifth copy is how the
    two halves come to word the same verdict differently.

    ``unassessable`` emits ``manual_review_required`` instead of ``fail``, for the
    case where the tenant did not report the setting at all. The two are
    genuinely different claims -- "this is configured wrongly" versus "this build
    could not read it" -- and `manual_review_required` ranks between `fail` and
    `warn`, so a check reporting it still fails the rollup rather than passing
    quietly. Saying `fail` for an unreadable setting is the overclaim; saying
    `pass` is the worse one.
    """
    return [
        ResourceFinding(
            resource_id=tenant_id,
            resource_type="m365_tenant",
            verdict="manual_review_required" if unassessable else ("pass" if passed else "fail"),
            observed=observed,
            detail=detail,
        )
    ]


def lock_minutes(policy: dict[str, Any]) -> int | None:
    """The inactivity lock a compliance policy sets, in minutes.

    ``None`` when the policy does not configure one at all, which is different
    from configuring zero: Intune treats 0 as "not configured" on some platform
    types, so both are reported as absent rather than as an immediate lock.
    """
    value = policy.get(_LOCK_TIMEOUT_KEY)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        return None
    return value


def evaluate_session_lock_enforced(
    rows: list[dict[str, Any]],
    *,
    tenant_id: str,
    max_minutes: int = SESSION_LOCK_MAX_MINUTES,
) -> list[ResourceFinding]:
    """Does any compliance policy lock an idle screen soon enough?

    Asked of the tenant, not of each policy. A compliance policy that governs
    only disk encryption does not set a lock timeout, and failing it for that
    would manufacture findings against correctly-scoped policies -- the
    per-resource shape misattributing the question, which is the mistake
    `DEVICE_UNEVALUATED_STATES` exists to avoid on the sibling check.

    ``max_minutes`` defaults to the module constant, so every existing caller is
    unaffected; a pack supplies its own through :mod:`ccf.posture.parameters`,
    which re-renders ``SESSION_LOCK_EXPECTED`` to match.
    """
    qualifying = [
        p
        for p in rows
        if p.get(_LOCK_REQUIRED_KEY) is True
        and (minutes := lock_minutes(p)) is not None
        and minutes <= max_minutes
    ]
    if qualifying:
        first = qualifying[0]
        return _tenant_finding(
            tenant_id,
            passed=True,
            observed=(
                f"{first.get('displayName') or first.get('id')!r} requires a password and "
                f"locks after {lock_minutes(first)} minute(s)"
            ),
            detail={
                "policy_id": first.get("id"),
                "lock_minutes": lock_minutes(first),
                "qualifying_policies": len(qualifying),
                "policies_examined": len(rows),
            },
        )
    # Say which of the two ways it failed: no policy at all is a different
    # remedy from policies that exist but lock too late.
    configured = [(p, m) for p in rows if (m := lock_minutes(p)) is not None]
    if configured:
        soonest = min(m for _p, m in configured)
        observed = (
            f"{len(configured)} policy/policies set a lock, the soonest at {soonest} minute(s), "
            f"longer than the {max_minutes} expected"
            if soonest > max_minutes
            else f"{len(configured)} policy/policies set a lock but do not require a password"
        )
    else:
        observed = (
            f"none of {len(rows)} device compliance policy/policies configures an "
            "inactivity lock"
            if rows
            else "no device compliance policy exists"
        )
    return _tenant_finding(
        tenant_id,
        passed=False,
        observed=observed,
        detail={
            "policies_examined": len(rows),
            "policies_with_a_lock": len(configured),
            "expected_max_minutes": max_minutes,
        },
    )


def evaluate_storage_encryption_required(
    rows: list[dict[str, Any]], *, tenant_id: str
) -> list[ResourceFinding]:
    """Does any compliance policy require the device's storage to be encrypted?

    Tenant-level for the same reason as the lock check: a policy about OS
    versions does not speak to encryption, and reading its silence as a refusal
    would be an invented finding.
    """
    requiring = [p for p in rows if p.get("storageRequireEncryption") is True]
    if requiring:
        first = requiring[0]
        return _tenant_finding(
            tenant_id,
            passed=True,
            observed=(
                f"{first.get('displayName') or first.get('id')!r} requires storage encryption"
            ),
            detail={
                "policy_id": first.get("id"),
                "requiring_policies": len(requiring),
                "policies_examined": len(rows),
            },
        )
    return _tenant_finding(
        tenant_id,
        passed=False,
        observed=(
            f"none of {len(rows)} device compliance policy/policies requires storage encryption"
            if rows
            else "no device compliance policy exists"
        ),
        detail={"policies_examined": len(rows)},
    )


def _sets_signin_frequency(policy: dict[str, Any]) -> dict[str, Any] | None:
    """The sign-in frequency an enabled CA policy sets, if it sets one.

    ``state`` must be ``enabled``: a policy in report-only mode reauthenticates
    nobody, and counting it would report a control as operating on the strength
    of a policy deliberately not in force. The same rule the legacy-auth check
    applies.
    """
    if policy.get("state") != "enabled":
        return None
    controls = policy.get("sessionControls")
    if not isinstance(controls, dict):
        return None
    frequency = controls.get(_SIGNIN_FREQUENCY_KEY)
    if not isinstance(frequency, dict) or frequency.get("isEnabled") is not True:
        return None
    return frequency


def evaluate_session_reauthentication_required(
    rows: list[dict[str, Any]], *, tenant_id: str
) -> list[ResourceFinding]:
    """Is there an enabled Conditional Access policy that bounds a session?"""
    for policy in rows:
        frequency = _sets_signin_frequency(policy)
        if frequency is None:
            continue
        # Graph expresses this either as value+type (e.g. 4 hours) or as
        # `frequencyInterval: everyTime`. Both bound the session; the observed
        # string reports whichever the tenant chose rather than assuming one.
        interval = frequency.get("frequencyInterval")
        if interval == "everyTime":
            described = "reauthentication on every use"
        elif frequency.get("value") is not None:
            described = f"{frequency.get('value')} {frequency.get('type') or 'unit(s)'}"
        else:
            described = "an enabled sign-in frequency with no stated period"
        return _tenant_finding(
            tenant_id,
            passed=True,
            observed=(
                f"{policy.get('displayName') or policy.get('id')!r} requires {described}"
            ),
            detail={"policy_id": policy.get("id"), "sign_in_frequency": frequency},
        )
    return _tenant_finding(
        tenant_id,
        passed=False,
        observed=(
            f"none of {len(rows)} Conditional Access policy/policies sets a sign-in frequency"
            if rows
            else "no Conditional Access policy exists"
        ),
        detail={"policies_examined": len(rows)},
    )


#: Checks whose question is answered by the first page. Graph returns audit
#: collections newest-first, so "is there a recent record" needs one row --
#: and following the nextLink walked a tenant's whole sign-in log and earned
#: a 429 on a $top=1 query, which the per-check isolation then reported as
#: manual_review_required: a rate limit wearing the costume of a finding.
FIRST_PAGE_ONLY: dict[str, int] = {
    SIGNIN_AUDIT_CURRENT.key: 1,
    DIRECTORY_AUDIT_CURRENT.key: 1,
}


def _password_setting(rows: list[dict[str, Any]], key: str) -> str | None:
    """One value out of Graph's "Password Rule Settings" directory setting."""
    for setting in rows:
        if (setting.get("displayName") or "") != _PASSWORD_SETTINGS_NAME:
            continue
        for value in setting.get("values") or []:
            if value.get("name") == key:
                raw = value.get("value")
                return None if raw is None else str(raw)
    return None


def evaluate_lockout_threshold(
    rows: list[dict[str, Any]],
    *,
    tenant_id: str,
    max_attempts: int = LOCKOUT_MAX_ATTEMPTS,
) -> list[ResourceFinding]:
    """Is sign-in lockout on, and bounded?

    Zero is the trap. Entra reads ``LockoutThreshold = 0`` as "never lock out",
    so the arithmetic that matters is not ``threshold <= max_attempts`` -- which
    zero satisfies -- but whether a threshold is in force at all. A check that
    passed a tenant with lockout disabled would be reporting the strongest
    possible failure of 3.1.8 as compliance.

    A tenant with no password-rule settings is ``manual_review_required`` rather
    than a fail: Entra applies its own default, and the honest answer is that this
    build could not read the tenant's own value, not that the default is
    acceptable.
    """
    raw = _password_setting(rows, _LOCKOUT_THRESHOLD_KEY)
    if raw is None or not raw.strip():
        return _tenant_finding(
            tenant_id,
            passed=False,
            observed=(
                "the tenant did not report a password-rule lockout threshold, so "
                "its value could not be read"
            ),
            detail={"settings_examined": len(rows)},
            unassessable=True,
        )
    try:
        threshold = int(raw)
    except ValueError:
        return _tenant_finding(
            tenant_id,
            passed=False,
            observed=f"the reported lockout threshold {raw!r} is not a number",
            detail={"raw": raw},
            unassessable=True,
        )
    duration = _password_setting(rows, _LOCKOUT_DURATION_KEY)
    if threshold <= 0:
        return _tenant_finding(
            tenant_id,
            passed=False,
            observed="sign-in lockout is disabled (threshold 0)",
            detail={"threshold": threshold, "max_attempts": max_attempts},
        )
    within = threshold <= max_attempts
    return _tenant_finding(
        tenant_id,
        passed=within,
        observed=(
            f"lockout after {threshold} failed attempt(s)"
            + (f", for {duration}s" if duration else "")
            + ("" if within else f", longer than the {max_attempts} expected")
        ),
        detail={
            "threshold": threshold,
            "lockout_duration_seconds": duration,
            "max_attempts": max_attempts,
        },
    )


def evaluate_security_alerts_triaged(
    rows: list[dict[str, Any]],
    *,
    tenant_id: str,
    threshold_days: int = ALERT_TRIAGE_DAYS,
) -> list[ResourceFinding]:
    """One finding per stale alert, so a failure names what to go and work.

    An empty list **passes**, unlike the configuration checks in this module. The
    difference is deliberate: an empty configuration response means the call did
    not answer, while no alerts is a real and clean state. Reporting a quiet
    tenant as unassessable would manufacture a finding out of nothing having
    happened.

    Only high and critical alerts count, and only once older than
    ``threshold_days``. 3.14.3 asks for a response, and responding takes time --
    failing an alert raised this morning would make every tenant fail forever.
    """
    cutoff = datetime.now(UTC) - timedelta(days=threshold_days)
    stale: list[ResourceFinding] = []
    for alert in rows:
        status = str(alert.get("status") or "").strip().lower()
        severity = str(alert.get("severity") or "").strip().lower()
        if status not in _ALERT_OPEN_STATES or severity not in _ALERT_ACTIONABLE_SEVERITIES:
            continue
        created = _parse_graph_datetime(alert.get("createdDateTime"))
        if created is None or created > cutoff:
            continue
        age = (datetime.now(UTC) - created).days
        stale.append(
            ResourceFinding(
                resource_id=str(alert.get("id") or "unknown"),
                resource_type="m365_security_alert",
                verdict="fail",
                observed=(
                    f"{severity} alert {alert.get('title') or alert.get('id')!r} has been "
                    f"{status} for {age} days"
                ),
                detail={
                    "severity": severity,
                    "status": status,
                    "age_days": age,
                    "threshold_days": threshold_days,
                },
            )
        )
    if stale:
        return stale
    return [
        ResourceFinding(
            resource_id=tenant_id,
            resource_type="m365_tenant",
            verdict="pass",
            observed=(
                f"no high or critical alert has been open longer than {threshold_days} days"
                if rows
                else "the tenant reported no security alerts"
            ),
            detail={"alerts_examined": len(rows), "threshold_days": threshold_days},
        )
    ]


def evaluate_removable_storage_blocked(
    rows: list[dict[str, Any]], *, tenant_id: str
) -> list[ResourceFinding]:
    """Does any configuration profile block removable storage?

    Asked of the tenant rather than of each profile, for the reason
    `evaluate_session_lock_enforced` gives: a profile scoped to kiosks does not
    express an opinion about removable storage, and failing it for that would
    manufacture findings against correctly-scoped policies.

    Profiles that all leave the field unset are ``manual_review_required``, not a
    fail -- none of them said anything, so the tenant's posture is unknown rather
    than known-bad. The live tenant this was written against sets it to ``False``
    on one profile, which is a genuine fail.
    """
    opinions = [row for row in rows if _REMOVABLE_STORAGE_KEY in row]
    blocking = [row for row in opinions if row.get(_REMOVABLE_STORAGE_KEY) is True]
    if blocking:
        first = blocking[0]
        return _tenant_finding(
            tenant_id,
            passed=True,
            observed=(
                f"{first.get('displayName') or first.get('id')!r} blocks removable storage"
            ),
            detail={
                "blocking_profiles": len(blocking),
                "profiles_with_a_setting": len(opinions),
                "profiles_examined": len(rows),
            },
        )
    if opinions:
        return _tenant_finding(
            tenant_id,
            passed=False,
            observed=(
                f"{len(opinions)} configuration profile(s) set removable storage and none "
                "blocks it"
            ),
            detail={
                "profiles_with_a_setting": len(opinions),
                "profiles_examined": len(rows),
            },
        )
    return _tenant_finding(
        tenant_id,
        passed=False,
        observed=(
            f"none of {len(rows)} configuration profile(s) configures removable storage"
            if rows
            else "no device configuration profile exists"
        ),
        detail={"profiles_examined": len(rows)},
        unassessable=True,
    )


def evaluate_system_use_notification(
    rows: list[dict[str, Any]], *, tenant_id: str
) -> list[ResourceFinding]:
    """AC-8: is a notification displayed before access is granted?

    The property that decides it is ``isViewingBeforeAcceptanceRequired``. An
    agreement a user accepts *without* being shown is a record of consent, which
    is a different thing from a system use notification -- crediting it would put
    a value that validates and is wrong into an SSP.

    An empty collection is a real answer: Graph listed the tenant's agreements and
    there are none, so no notification is configured. That is a finding.

    An agreement that omits the property is ``manual_review_required`` rather than
    a failure. Terms of use requires Entra ID P1/P2, and a tenant without it can
    return a different property set; "configured wrongly" would send an operator
    to fix something that is not broken.
    """
    if not rows:
        return _tenant_finding(
            tenant_id,
            passed=False,
            observed="no terms-of-use agreement is configured for this tenant",
            detail={"agreements": 0},
        )
    unreadable: list[str] = []
    not_shown: list[str] = []
    for row in rows:
        name = str(row.get("displayName") or row.get("id") or "unnamed")
        shown = row.get("isViewingBeforeAcceptanceRequired")
        if not isinstance(shown, bool):
            unreadable.append(name)
            continue
        if shown:
            return _tenant_finding(
                tenant_id,
                passed=True,
                observed=(
                    f"{name!r} must be viewed before acceptance, so it is displayed "
                    "before access is granted"
                ),
                detail={"agreement": name, "agreements": len(rows)},
            )
        not_shown.append(name)
    if not_shown:
        return _tenant_finding(
            tenant_id,
            passed=False,
            observed=(
                f"{len(not_shown)} agreement(s) can be accepted without being shown "
                f"({', '.join(not_shown[:5])}), so none is a system use notification"
            ),
            detail={"agreements": len(rows), "not_shown": not_shown[:20]},
        )
    return _tenant_finding(
        tenant_id,
        passed=False,
        observed=(
            f"{len(unreadable)} agreement(s) did not report "
            "isViewingBeforeAcceptanceRequired, which Entra ID P1/P2 governs"
        ),
        detail={"agreements": len(rows), "unreadable": unreadable[:20]},
        unassessable=True,
    )


EVALUATORS: dict[str, Callable[..., list[ResourceFinding]]] = {
    MFA_REGISTERED.key: evaluate_mfa_registered,
    LEGACY_AUTH_BLOCKED.key: evaluate_legacy_auth_blocked,
    STALE_ACCOUNTS.key: evaluate_stale_accounts,
    PHISHING_RESISTANT_MFA.key: evaluate_phishing_resistant_mfa,
    PHISHABLE_METHODS_DISABLED.key: evaluate_phishable_methods_disabled,
    GUEST_INVITES_RESTRICTED.key: evaluate_guest_invites_restricted,
    DEFAULT_USER_PERMISSIONS_RESTRICTED.key: evaluate_default_user_permissions,
    SIGNIN_AUDIT_CURRENT.key: evaluate_signin_audit_current,
    DIRECTORY_AUDIT_CURRENT.key: evaluate_directory_audit_current,
    DEVICE_COMPLIANCE.key: evaluate_device_compliance,
    RISKY_USERS_RESOLVED.key: evaluate_risky_users_resolved,
    SESSION_LOCK_ENFORCED.key: evaluate_session_lock_enforced,
    STORAGE_ENCRYPTION_REQUIRED.key: evaluate_storage_encryption_required,
    SESSION_REAUTHENTICATION_REQUIRED.key: evaluate_session_reauthentication_required,
    LOCKOUT_THRESHOLD.key: evaluate_lockout_threshold,
    SECURITY_ALERTS_TRIAGED.key: evaluate_security_alerts_triaged,
    REMOVABLE_STORAGE_BLOCKED.key: evaluate_removable_storage_blocked,
    SYSTEM_USE_NOTIFICATION.key: evaluate_system_use_notification,
}
