"""Acceptance: a deliberately broken tenant produces the findings it should.

The first acceptance criterion of
``docs/superpowers/plans/2026-09-26-live-audit-compliance-plan.md``:

    A test environment with known misconfigurations produces matching failed
    resource rows and control failures.

Nothing had exercised it. Every layer of the chain was unit- and
integration-tested in isolation, which establishes that each part does what its
own tests say -- not that a misconfiguration at the provider ends up as the
right control failing, the right resource named, a POA&M an analyst can act on,
and an SSP that declines to call the control implemented.

So this drives **one** tenant fixture through the **real** pipeline and asserts
the whole chain:

    provider payload -> scan -> per-resource rows -> control verdict
                     -> POA&M -> framework posture -> SSP statement

Everything between the payload and the conclusion is production code, including
``resolve_checks``: the fixture answers all fourteen m365 platform checks, not a
convenient subset, so a new check that nothing feeds is a failure here rather
than a silent hole. The only substitution is the connector's HTTP call.

**What this does not prove.** The environment is recorded payloads, not a live
tenant somebody misconfigured. It proves Concord turns a given Graph response
into the right compliance conclusion; it does not prove Graph returns that
response for a tenant in that state. Closing that half needs a tenant to break,
and it is the remaining work behind this criterion.

An earlier version of this file recorded, as asserted behaviour, that a scan
credited only ``control_ids[0]`` -- so the MFA check, which declares ``IA-2``
and ``IA-2(1)``, was evidence about ``IA-2`` alone. Writing the understatement
down is what made it worth fixing; it now attributes a non-passing verdict to
every control its check declares (``ccf.posture.evidence``), and this file
asserts the wider, correct set.

Every expectation below is derived from the fixture by hand and written as a
literal -- including the crosswalk rows, which are copied from the loaded
catalog. Computing an expectation from the code under test is how an end-to-end
test comes to assert nothing.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, select

from ccf.analytics.framework_posture import system_framework_posture
from ccf.analytics.gaps import compliance_gaps
from ccf.catalog.crosswalk import CROSSWALK_COLUMN, CROSSWALK_FRAMEWORK
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance import automation as automation_engine
from ccf.models import (
    POAM,
    Control,
    Framework,
    FrameworkMapping,
    Organization,
    SSPControlEntry,
    SSPProject,
    System,
    SystemProfile,
)
from ccf.models_grc import ControlTest, ControlTestResourceResult, ControlTestResult
from ccf.posture import scan as scan_mod
from ccf.posture.checks import CheckOutcome
from ccf.posture.providers import m365
from ccf.posture.scan import scan_for_system
from ccf.scoring.seed import seed_scoring_controls

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()
NOW = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)
TENANT = "d0529da6-0000-0000-0000-000000000000"


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _stamp(days_ago: int) -> str:
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# The environment, one deliberate misconfiguration at a time
# ---------------------------------------------------------------------------

#: IA-2 -- two of four users cannot complete MFA. `isMfaCapable`, not
#: `isMfaRegistered`, is what the evaluator reads.
MFA_ROWS = [
    {"id": "u1", "userPrincipalName": "ao@x.gov", "isMfaCapable": True},
    {"id": "u2", "userPrincipalName": "isso@x.gov", "isMfaCapable": True},
    {"id": "u3", "userPrincipalName": "contractor@x.gov", "isMfaCapable": False},
    {"id": "u4", "userPrincipalName": "svc-backup@x.gov", "isMfaCapable": False},
]
MFA_FAILING = {"contractor@x.gov", "svc-backup@x.gov"}

#: AC-2 -- one enabled account dormant past 90 days; one disabled (not a
#: stale-access risk) and one unlicensed with no `signInActivity` (absence of
#: evidence), both of which must be `not_applicable` rather than either verdict.
STALE_ROWS = [
    {
        "id": "u1",
        "userPrincipalName": "ao@x.gov",
        "accountEnabled": True,
        "signInActivity": {"lastSignInDateTime": _stamp(3)},
    },
    {
        "id": "u4",
        "userPrincipalName": "svc-backup@x.gov",
        "accountEnabled": True,
        "signInActivity": {"lastSignInDateTime": _stamp(400)},
    },
    {
        "id": "u5",
        "userPrincipalName": "departed@x.gov",
        "accountEnabled": False,
        "signInActivity": {"lastSignInDateTime": _stamp(900)},
    },
    {"id": "u6", "userPrincipalName": "unlicensed@x.gov", "accountEnabled": True},
]
STALE_FAILING = {"svc-backup@x.gov"}

#: Two Conditional Access policies, and the pair is the misconfiguration.
#: The enforced one bounds the session (AC-12 passes), and the one that *would*
#: block legacy authentication was left in report-only mode, so it enforces
#: nothing (IA-2 fails). This is the shape that reads as configured on a
#: screenshot and blocks nothing in production.
CONDITIONAL_ACCESS = [
    {
        "id": "ca-1",
        "displayName": "Require sign-in every 4 hours",
        "state": "enabled",
        "conditions": {"clientAppTypes": ["browser", "mobileAppsAndDesktopClients"]},
        "sessionControls": {
            "signInFrequency": {"isEnabled": True, "value": 4, "type": "hours"}
        },
    },
    {
        "id": "ca-2",
        "displayName": "Block legacy authentication",
        "state": "enabledForReportingButNotEnforced",
        "conditions": {"clientAppTypes": ["exchangeActiveSync", "other"]},
        "grantControls": {"builtInControls": ["block"]},
    },
]

#: IA-2(11) / IA-2(1) -- SMS is enabled (interceptable) and no
#: phishing-resistant method is.
AUTH_METHODS_POLICY = [
    {
        "id": "authenticationMethodsPolicy",
        "authenticationMethodConfigurations": [
            {"id": "Sms", "state": "enabled"},
            {"id": "MicrosoftAuthenticator", "state": "enabled"},
            {"id": "Fido2", "state": "disabled"},
            {"id": "X509Certificate", "state": "disabled"},
        ],
    }
]

#: AC-3 / AC-6 -- anyone may invite guests, and default users may register
#: applications.
AUTHZ_POLICY = [
    {
        "id": "authorizationPolicy",
        "allowInvitesFrom": "everyone",
        "defaultUserRolePermissions": {
            "allowedToCreateApps": True,
            "allowedToCreateTenants": False,
            "allowedToCreateSecurityGroups": False,
        },
    }
]

#: AC-11 / SC-28 -- one compliance policy, two separate misconfigurations: it
#: locks after 60 minutes (later than the 15 expected) and does not require
#: storage encryption.
DEVICE_COMPLIANCE_POLICIES = [
    {
        "id": "dcp-1",
        "displayName": "Windows baseline",
        "passwordRequired": True,
        "passwordMinutesOfInactivityBeforeLock": 60,
        "storageRequireEncryption": False,
    }
]

#: CM-6 -- one noncompliant device, one compliant, one never evaluated.
MANAGED_DEVICES = [
    {"id": "d1", "deviceName": "LAPTOP-01", "complianceState": "noncompliant"},
    {
        "id": "d2",
        "deviceName": "LAPTOP-02",
        "complianceState": "compliant",
        "operatingSystem": "Windows",
    },
    {"id": "d3", "deviceName": "KIOSK-01", "complianceState": "unknown"},
]

#: AC-2(12) -- one user left at risk.
RISKY_USERS = [
    {
        "id": "u3",
        "userPrincipalName": "contractor@x.gov",
        "riskLevel": "high",
        "riskState": "atRisk",
    },
    {
        "id": "u1",
        "userPrincipalName": "ao@x.gov",
        "riskLevel": "low",
        "riskState": "remediated",
    },
]

#: AU-2 -- the audit trail is current. Two of the fourteen checks that pass,
#: so "everything fails" cannot be what makes this test green.
SIGNIN_AUDIT = [{"createdDateTime": _stamp(1)}]
DIRECTORY_AUDIT = [{"activityDateTime": _stamp(2)}]

#: AC-7 -- lockout IS configured correctly here, at three attempts. One of the
#: things this tenant gets right, so the suite cannot pass by failing everything.
PASSWORD_RULE_SETTINGS = [
    {
        "displayName": "Password Rule Settings",
        "values": [
            {"name": "LockoutThreshold", "value": "3"},
            {"name": "LockoutDurationInSeconds", "value": "900"},
        ],
    },
    {"displayName": "Consent Policy Settings", "values": [{"name": "X", "value": "1"}]},
]

#: SI-5 -- a high-severity alert nobody has touched in sixty days, beside a
#: resolved one and a fresh one. Only the stale high is a finding: the other two
#: are what distinguishes "left unactioned" from "an alert exists".
SECURITY_ALERTS = [
    {
        "id": "al-stale",
        "title": "Suspicious sign-in from anonymous IP",
        "status": "new",
        "severity": "high",
        "createdDateTime": _stamp(60),
    },
    {
        "id": "al-done",
        "title": "Malware detected",
        "status": "resolved",
        "severity": "critical",
        "createdDateTime": _stamp(120),
    },
    {
        "id": "al-fresh",
        "title": "Impossible travel",
        "status": "new",
        "severity": "high",
        "createdDateTime": _stamp(1),
    },
]

#: MP-7 -- one configuration profile sets removable storage and allows it. The
#: second sets nothing, which must not be read as a refusal.
DEVICE_CONFIGURATIONS = [
    {
        "id": "cfg-1",
        "displayName": "Windows restrictions",
        "@odata.type": "#microsoft.graph.windows10GeneralConfiguration",
        "storageBlockRemovableStorage": False,
    },
    {
        "id": "cfg-2",
        "displayName": "Kiosk",
        "@odata.type": "#microsoft.graph.windows10GeneralConfiguration",
    },
]


#: check key -> (rows, the evaluator's extra keyword arguments).
#: Every m365 platform check appears. A check added without a fixture entry
#: fails this test rather than quietly scanning nothing -- see `_FakeGraph`.
FIXTURE: dict[str, tuple[list[dict[str, Any]], dict[str, Any]]] = {
    m365.MFA_REGISTERED.key: (MFA_ROWS, {}),
    m365.LEGACY_AUTH_BLOCKED.key: (CONDITIONAL_ACCESS, {"tenant_id": TENANT}),
    m365.STALE_ACCOUNTS.key: (STALE_ROWS, {"now": NOW}),
    m365.PHISHING_RESISTANT_MFA.key: (AUTH_METHODS_POLICY, {"tenant_id": TENANT}),
    m365.PHISHABLE_METHODS_DISABLED.key: (AUTH_METHODS_POLICY, {"tenant_id": TENANT}),
    m365.GUEST_INVITES_RESTRICTED.key: (AUTHZ_POLICY, {"tenant_id": TENANT}),
    m365.DEFAULT_USER_PERMISSIONS_RESTRICTED.key: (AUTHZ_POLICY, {"tenant_id": TENANT}),
    m365.SIGNIN_AUDIT_CURRENT.key: (SIGNIN_AUDIT, {"tenant_id": TENANT, "now": NOW}),
    m365.DIRECTORY_AUDIT_CURRENT.key: (DIRECTORY_AUDIT, {"tenant_id": TENANT, "now": NOW}),
    m365.DEVICE_COMPLIANCE.key: (MANAGED_DEVICES, {}),
    m365.RISKY_USERS_RESOLVED.key: (RISKY_USERS, {}),
    m365.SESSION_LOCK_ENFORCED.key: (DEVICE_COMPLIANCE_POLICIES, {"tenant_id": TENANT}),
    m365.STORAGE_ENCRYPTION_REQUIRED.key: (
        DEVICE_COMPLIANCE_POLICIES,
        {"tenant_id": TENANT},
    ),
    m365.SESSION_REAUTHENTICATION_REQUIRED.key: (
        CONDITIONAL_ACCESS,
        {"tenant_id": TENANT},
    ),
    m365.LOCKOUT_THRESHOLD.key: (PASSWORD_RULE_SETTINGS, {"tenant_id": TENANT}),
    m365.SECURITY_ALERTS_TRIAGED.key: (SECURITY_ALERTS, {"tenant_id": TENANT}),
    m365.REMOVABLE_STORAGE_BLOCKED.key: (DEVICE_CONFIGURATIONS, {"tenant_id": TENANT}),
}

#: What a person reading the fixture says each check must conclude.
EXPECTED_VERDICTS = {
    m365.MFA_REGISTERED.key: "fail",
    m365.LEGACY_AUTH_BLOCKED.key: "fail",
    m365.STALE_ACCOUNTS.key: "fail",
    m365.PHISHING_RESISTANT_MFA.key: "fail",
    m365.PHISHABLE_METHODS_DISABLED.key: "fail",
    m365.GUEST_INVITES_RESTRICTED.key: "fail",
    m365.DEFAULT_USER_PERMISSIONS_RESTRICTED.key: "fail",
    m365.SIGNIN_AUDIT_CURRENT.key: "pass",
    m365.DIRECTORY_AUDIT_CURRENT.key: "pass",
    m365.DEVICE_COMPLIANCE.key: "fail",
    m365.RISKY_USERS_RESOLVED.key: "fail",
    m365.SESSION_LOCK_ENFORCED.key: "fail",
    m365.STORAGE_ENCRYPTION_REQUIRED.key: "fail",
    m365.SESSION_REAUTHENTICATION_REQUIRED.key: "pass",
    m365.LOCKOUT_THRESHOLD.key: "pass",
    m365.SECURITY_ALERTS_TRIAGED.key: "fail",
    m365.REMOVABLE_STORAGE_BLOCKED.key: "fail",
}
FAILING_CHECKS = {k for k, v in EXPECTED_VERDICTS.items() if v == "fail"}

#: A scan records ONE ``ControlTest`` per check, whose ``control_id`` is
#: ``control_ids[0]``. These are the primary controls -- the row identity, what
#: the POA&M and waiver paths key on. The controls a check *additionally*
#: declares are recorded in ``ControlTest.control_ids`` and reach the rollups
#: through ``ccf.posture.evidence``; they are asserted separately, below.
EXPECTED_FAILING_CONTROLS = {
    "IA-2",  # mfa_registered, legacy_auth_blocked
    "AC-2",  # stale_accounts
    "IA-2(11)",  # phishing_resistant_mfa
    "IA-2(1)",  # phishable_methods_disabled
    "AC-3",  # guest_invites_restricted
    "AC-6",  # default_user_permissions_restricted
    "CM-6",  # device compliance
    "AC-2(12)",  # risky_users_resolved
    "AC-11",  # session_lock_enforced
    "SC-28",  # storage_encryption_required
    "SI-4",  # alerts_triaged -- a stale high-severity alert nobody actioned
    "MP-7",  # removable_storage_blocked
}
#: AC-7 joins these: lockout is one of the things this tenant has configured
#: correctly, and a fixture where every check fails would prove far less.
EXPECTED_PASSING_CONTROLS = {"AU-2", "AC-12", "AC-7"}


class _FakeGraph:
    """The msgraph connector with its HTTP call replaced by the fixture.

    Everything else is real: the production evaluators decide every verdict,
    and a check with no fixture entry raises rather than being skipped.
    """

    key = "msgraph"

    def is_configured(self) -> bool:
        return True

    async def scan(self, checks: Any = None) -> list[CheckOutcome]:
        outcomes: list[CheckOutcome] = []
        for resolved in checks or ():
            key = resolved.check.key
            if key not in FIXTURE:
                raise AssertionError(
                    f"{key} has no fixture: this acceptance test covers every m365 "
                    "platform check, so a new one needs a known-bad payload here"
                )
            rows, kwargs = FIXTURE[key]
            evaluator = m365.EVALUATORS[key]
            outcomes.append(
                CheckOutcome.from_findings(resolved.check, tuple(evaluator(rows, **kwargs)))
            )
        return outcomes


@pytest.fixture
def broken_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _connector(*_a: object, **_k: object) -> _FakeGraph:
        return _FakeGraph()

    monkeypatch.setattr(scan_mod, "_connector_for_org", _connector)


# ---------------------------------------------------------------------------
# The crosswalk, copied from the loaded catalog rather than reasoned out
# ---------------------------------------------------------------------------
#
# ``practices_for_controls`` reads ``framework_mappings`` under the
# ``NIST_800_171_R2`` framework and the ``NIST 800-171 Rev. 2`` column key. The
# rows below are that catalog's own rows for the controls these checks record.
# The identifiers are verbatim, including their zero-padded spelling; the values
# carry the requirement number the catalog attributes to that control, with the
# requirement text abbreviated (only the leading number is read). Both were read
# out of the loaded catalog, not inferred from control families: a crosswalk
# guess is indistinguishable from a citation until somebody checks, and checking
# is what this test is for.
#
# ``AC-06#row337`` and ``AC-06-02-01`` are the catalog's literal identifiers;
# both canonicalize to ``AC-6``, which is why AC-6 reaches two requirements.
# ``AC-2(12)`` and ``IA-2(11)`` carry no Rev. 2 mapping of their own and fall
# back to their base control, which is the behaviour being exercised.
CROSSWALK_ROWS = [
    (
        "AC-02",
        "3.1.1 Limit system access to authorized users, processes acting on behalf of"
        " authorized users, and devices (including other systems).",
    ),
    ("AC-02(03)", "03-01-01:"),
    (
        "AC-03",
        "3.1.1 Limit system access to authorized users, processes acting on behalf of"
        " authorized users, and devices (including other systems).",
    ),
    (
        "AC-06#row337",
        "3.1.5 Employ the principle of least privilege, including for specific security"
        " functions and privileged accounts.",
    ),
    (
        "AC-06(01)",
        "3.1.5 Employ the principle of least privilege, including for specific security"
        " functions and privileged accounts.",
    ),
    (
        "AC-06-02-01",
        "3.1.6 Use non-privileged accounts or roles when accessing nonsecurity"
        " functions.",
    ),
    (
        "AC-11",
        "3.1.10 Use session lock with pattern-hiding displays to prevent access and"
        " viewing of data after a period of inactivity",
    ),
    (
        "AC-11(01)",
        "3.1.10 Use session lock with pattern-hiding displays to prevent access and"
        " viewing of data after a period of inactivity",
    ),
    ("AC-12", "3.1.11 Terminate (automatically) a user session after a defined condition."),
    (
        "AC-17",
        "3.1.1 Limit system access to authorized users, processes acting on behalf of"
        " authorized users, and devices (including other systems).",
    ),
    ("AC-19(05)", "3.1.19 Encrypt CUI on mobile devices and mobile computing platforms."),
    ("AU-02", "3.3.1 Create and retain system audit logs and records to the extent needed."),
    ("AU-06", "3.3.1 Create and retain system audit logs and records to the extent needed."),
    (
        "CM-02",
        "3.4.1 Establish and maintain baseline configurations and inventories of"
        " organizational systems.",
    ),
    (
        "CM-06",
        "3.4.1 Establish and maintain baseline configurations and inventories of"
        " organizational systems.",
    ),
    ("IA-02", "3.5.1 Identify system users, processes acting on behalf of users, and devices."),
    (
        "IA-02(01)",
        "3.5.3 Use multifactor authentication for local and network access to"
        " privileged accounts.",
    ),
    (
        "IA-02(02)",
        "3.5.3 Use multifactor authentication for local and network access to"
        " privileged accounts.",
    ),
    ("SC-28", "3.13.16 Protect the confidentiality of CUI at rest."),
    ("SI-02", "3.14.1 Identify, report, and correct system flaws in a timely manner."),
    (
        "SI-04",
        "3.14.6 Monitor organizational systems, including inbound and outbound"
        " communications traffic.",
    ),
]

#: Every requirement the failing checks reach, traced through
#: ``ccf.posture.practices.CHECK_PRACTICES``.
#:
#: These used to be traced through the catalog crosswalk instead, and the set was
#: wider: it also held 3.1.6, 3.4.1, 3.5.1, 3.14.1 and 3.14.6. Those came from
#: *relatedness* -- ``IA-2`` relates to 3.5.1 ("Identify system users"), so a
#: failing MFA-registration check marked 3.5.1 failing, a requirement it never
#: observed. The crosswalk is no longer an attribution source for a registered
#: check; it still answers ``unreachable``, which is a different question.
#:
#: guest_invites -> 3.1.1; default_user_permissions -> 3.1.5; session_lock ->
#: 3.1.10; storage_encryption -> 3.1.19 and 3.13.16; compliance_enforced ->
#: 3.4.2; mfa_registered, legacy_auth_blocked and phishing_resistant_mfa ->
#: 3.5.3; phishing_resistant_mfa and phishable_methods -> 3.5.4; stale_accounts
#: -> 3.5.6; removable_storage -> 3.8.7; alerts_triaged -> 3.14.3.
EXPECTED_FAILING_REQUIREMENTS = {
    "3.1.1",
    "3.1.5",
    "3.1.10",
    "3.1.19",
    "3.4.2",
    "3.5.3",
    "3.5.4",
    "3.5.6",
    "3.8.7",
    "3.13.16",
    "3.14.3",
}
#: Both audit checks pass and declare 3.3.1 and 3.3.2; a pass credits the
#: **primary** practice only, so 3.3.1 is reported and 3.3.2 is not. That
#: asymmetry is the rule in ``ccf.posture.evidence``, applied to practices.
#:
#: 3.3.1 reads clean here, and under the old crosswalk attribution it did not:
#: the risky-user check failed and related to AU-6, which the crosswalk placed on
#: 3.3.1, so the audit requirement was reported failing. That check is now one of
#: the two deliberate exclusions in ``practices.UNMAPPED`` -- Identity Protection
#: risk detections are not a named 800-171 practice -- so it reaches nothing and
#: is named in ``unmapped_checks`` instead of dragging a requirement down with a
#: relationship nobody asserted.
#:
#: 3.1.11 was also here, from AC-12 through the crosswalk. Its check
#: (session_reauthentication_required) is the other exclusion: sign-in frequency
#: forces re-authentication, it does not terminate a session.
#: 3.1.8 joins it: the lockout threshold is three, which is one of the things
#: this tenant has right.
EXPECTED_PASSING_REQUIREMENTS = {"3.1.8", "3.3.1"}


@dataclass
class _SeededCatalog:
    """Exactly the global rows one test created, so it can remove exactly those.

    ``controls`` and ``framework_mappings`` are global tables that unscoped
    queries read -- ``catalog.impact._dangling_mappings`` walks every mapping
    row in the database. Rows left behind here are not this module's problem
    alone: they turn up as findings in another module's catalog-adoption test.
    So every row is tracked and deleted, and a row that was already there (some
    other test's ``AC-02``) is reused and left alone.
    """

    framework_id: int | None = None
    control_ids: list[int] = field(default_factory=list)
    mapping_ids: list[int] = field(default_factory=list)


async def _seed_crosswalk() -> _SeededCatalog:
    """Get-or-create the catalog rows the 800-171 denominator needs."""
    seeded = _SeededCatalog()
    async with session_scope() as s:
        framework = (
            await s.execute(select(Framework).where(Framework.code == CROSSWALK_FRAMEWORK))
        ).scalar_one_or_none()
        if framework is None:
            framework = Framework(code=CROSSWALK_FRAMEWORK, name="NIST SP 800-171 Rev. 2")
            s.add(framework)
            await s.flush()
            seeded.framework_id = framework.id
        for identifier, value in CROSSWALK_ROWS:
            control = (
                await s.execute(select(Control).where(Control.identifier == identifier))
            ).scalar_one_or_none()
            if control is None:
                control = Control(identifier=identifier)
                s.add(control)
                await s.flush()
                seeded.control_ids.append(control.id)
            existing = (
                await s.execute(
                    select(FrameworkMapping).where(
                        FrameworkMapping.control_id == control.id,
                        FrameworkMapping.framework_id == framework.id,
                        FrameworkMapping.column_key == CROSSWALK_COLUMN,
                    )
                )
            ).scalars().first()
            if existing is None:
                mapping = FrameworkMapping(
                    control_id=control.id,
                    framework_id=framework.id,
                    column_key=CROSSWALK_COLUMN,
                    value=value,
                )
                s.add(mapping)
                await s.flush()
                seeded.mapping_ids.append(mapping.id)
    return seeded


async def _unseed_crosswalk(seeded: _SeededCatalog) -> None:
    async with session_scope() as s:
        if seeded.mapping_ids:
            await s.execute(
                delete(FrameworkMapping).where(FrameworkMapping.id.in_(seeded.mapping_ids))
            )
        if seeded.control_ids:
            await s.execute(delete(Control).where(Control.id.in_(seeded.control_ids)))
        if seeded.framework_id is not None:
            await s.execute(delete(Framework).where(Framework.id == seeded.framework_id))


async def _environment() -> tuple[int, int, int, _SeededCatalog]:
    """An org, a system declaring 800-171, and an SSP project over three controls."""
    tag = f"{next(_SEQ)}"
    async with session_scope() as s:
        # The 110-requirement matrix is the 800-171 denominator.
        await seed_scoring_controls(s)
    seeded = await _seed_crosswalk()
    async with session_scope() as s:
        org = Organization(name=f"Acceptance Org {tag}")
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name=f"Acceptance Sys {tag}")
        s.add(system)
        await s.flush()
        s.add(
            SystemProfile(
                system_id=system.id,
                answers={},
                environment_type="cloud",
                cloud_platform="m365_gcc_high",
                frameworks=["NIST_800_171"],
                derivation={},
            )
        )
        project = SSPProject(
            organization_id=org.id,
            system_id=system.id,
            customer_name=f"Acceptance {tag}",
            platform="m365",
        )
        s.add(project)
        await s.flush()
        # AC-17 is declared ONLY as the second control of the legacy-auth check.
        # Before `ccf.posture.evidence` it could not appear in this document at
        # all, so it is seeded claiming Implemented like the rest.
        for control_id in ("IA-2", "AC-2", "AU-2", "AC-17"):
            s.add(
                SSPControlEntry(
                    project_id=project.id,
                    control_id=control_id,
                    nist_id=control_id,
                    domain=control_id.split("-")[0],
                    requirement="manage system access",
                    implementation_status=["Implemented"],
                )
            )
        await s.flush()
        return org.id, system.id, project.id, seeded


async def _cleanup(org_id: int, seeded: _SeededCatalog) -> None:
    async with session_scope() as s:
        # `ssp_projects.organization_id` is not ON DELETE CASCADE, so deleting
        # the organization alone leaves the project and its control entries
        # behind. They then answer another module's unscoped query for an
        # entry on `AC-2` -- which is how this was found.
        await s.execute(delete(SSPProject).where(SSPProject.organization_id == org_id))
        await s.execute(delete(Organization).where(Organization.id == org_id))
    await _unseed_crosswalk(seeded)


async def _scan(system_id: int) -> dict[str, Any]:
    async with session_scope() as s:
        return await scan_for_system(s, system_id=system_id, connector_key="msgraph")


# ---------------------------------------------------------------------------
# Link 0: the whole tenant is scanned, not a convenient corner of it
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_every_platform_check_runs_against_the_fixture(broken_tenant) -> None:
    org_id, system_id, _project, seeded = await _environment()
    try:
        out = await _scan(system_id)
        assert out["checks_expected"] == len(m365.CHECKS) == len(FIXTURE)
        assert out["checks_run"] == len(FIXTURE)
        assert out["skipped_checks"] == []
    finally:
        await _cleanup(org_id, seeded)


# ---------------------------------------------------------------------------
# Link 1: the misconfiguration becomes per-resource rows
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_failing_resources_are_the_ones_that_are_broken(broken_tenant) -> None:
    """Named, not counted. "2 of 4 failing" without the names is not actionable."""
    org_id, system_id, _project, seeded = await _environment()
    try:
        await _scan(system_id)

        async with session_scope() as s:
            rows = (
                await s.execute(
                    select(
                        ControlTest.check_key,
                        ControlTestResourceResult.resource_id,
                        ControlTestResourceResult.verdict,
                    )
                    .join(
                        ControlTestResult,
                        ControlTestResult.control_test_id == ControlTest.id,
                    )
                    .join(
                        ControlTestResourceResult,
                        ControlTestResourceResult.result_id == ControlTestResult.id,
                    )
                    .where(ControlTest.system_id == system_id)
                )
            ).all()

        def verdicts(check_key: str) -> dict[str, str]:
            return {r: v for k, r, v in rows if k == check_key}

        mfa = verdicts(m365.MFA_REGISTERED.key)
        assert {r for r, v in mfa.items() if v == "fail"} == MFA_FAILING
        assert len(mfa) == len(MFA_ROWS), "every user is accounted for, not just the failures"

        stale = verdicts(m365.STALE_ACCOUNTS.key)
        assert {r for r, v in stale.items() if v == "fail"} == STALE_FAILING
        # A disabled account is not a stale-access risk, and a missing
        # `signInActivity` is absence of evidence, not evidence of dormancy.
        # Both must be `not_applicable` -- calling either one `pass` would
        # assert something never observed.
        assert stale["departed@x.gov"] == "not_applicable"
        assert stale["unlicensed@x.gov"] == "not_applicable"
        assert stale["ao@x.gov"] == "pass"

        devices = verdicts(m365.DEVICE_COMPLIANCE.key)
        assert devices == {"d1": "fail", "d2": "pass", "d3": "not_applicable"}

        risky = verdicts(m365.RISKY_USERS_RESOLVED.key)
        assert risky == {"u3": "fail", "u1": "pass"}

        # Tenant-wide settings still name a resource, so "which resource
        # failed" has an answer for them too.
        assert verdicts(m365.GUEST_INVITES_RESTRICTED.key) == {TENANT: "fail"}
        assert verdicts(m365.SESSION_LOCK_ENFORCED.key) == {TENANT: "fail"}
    finally:
        await _cleanup(org_id, seeded)


# ---------------------------------------------------------------------------
# Link 2: the rows become control verdicts
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_each_check_gets_the_verdict_the_fixture_implies(broken_tenant) -> None:
    org_id, system_id, _project, seeded = await _environment()
    try:
        await _scan(system_id)
        async with session_scope() as s:
            verdicts = dict(
                (
                    await s.execute(
                        select(ControlTest.check_key, ControlTest.last_status).where(
                            ControlTest.system_id == system_id
                        )
                    )
                ).all()
            )
        assert verdicts == EXPECTED_VERDICTS
    finally:
        await _cleanup(org_id, seeded)


@pytest.mark.asyncio
async def test_the_recorded_control_ids_are_the_declared_ones(broken_tenant) -> None:
    """Guards the claim the posture assertions rest on."""
    org_id, system_id, _project, seeded = await _environment()
    try:
        await _scan(system_id)
        async with session_scope() as s:
            recorded = (
                await s.execute(
                    select(ControlTest.control_id, ControlTest.last_status).where(
                        ControlTest.system_id == system_id
                    )
                )
            ).all()
        assert {c for c, v in recorded if v == "fail"} == EXPECTED_FAILING_CONTROLS
        assert {c for c, v in recorded if v == "pass"} == EXPECTED_PASSING_CONTROLS
    finally:
        await _cleanup(org_id, seeded)


# ---------------------------------------------------------------------------
# Link 3: a failing control becomes an actionable POA&M
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_every_failing_check_opens_a_poam_with_guidance(broken_tenant) -> None:
    """The plan's third acceptance criterion, on the same fixture."""
    org_id, system_id, _project, seeded = await _environment()
    try:
        await _scan(system_id)
        async with session_scope() as s:
            poams = (
                (await s.execute(select(POAM).where(POAM.system_id == system_id)))
                .scalars()
                .all()
            )

        assert len(poams) == len(FAILING_CHECKS), (
            f"expected one POA&M per failing check, got {[p.title for p in poams]}"
        )
        for poam in poams:
            assert poam.status == "open"
            assert poam.remediation_plan, f"{poam.title} has no remediation guidance"
            assert poam.remediation_plan_source == "generated"
            for section in ("Remediation objective", "Observed condition", "SSP impact"):
                assert section in poam.remediation_plan, (section, poam.title)

        # The observed condition carries the real count, not a placeholder.
        mfa_poam = next(p for p in poams if "MFA" in (p.weakness or ""))
        assert "2 of 4" in (mfa_poam.weakness or "")
    finally:
        await _cleanup(org_id, seeded)


# ---------------------------------------------------------------------------
# Link 4: the verdicts become framework posture
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_framework_posture_names_the_failing_requirements(broken_tenant) -> None:
    """The verdicts, re-expressed in the units the system is actually held to.

    The system declares 800-171 and carries no FIPS-199 baseline, so the
    denominator is the 110 requirements -- not the fourteen checks that
    happened to run.
    """
    org_id, system_id, _project, seeded = await _environment()
    try:
        await _scan(system_id)
        async with session_scope() as s:
            posture = await system_framework_posture(s, org_id=org_id, system_id=system_id)
            gaps = await compliance_gaps(s, org_id)

        assert posture["framework"] == "nist_800_171"
        assert posture["framework_source"] == "profile.frameworks"
        assert posture["unit"] == "requirement"
        assert posture["total"] == 110, "the denominator is the framework, not the scan"

        assert set(posture["failing"]) == EXPECTED_FAILING_REQUIREMENTS
        assert set(posture["passing"]) == EXPECTED_PASSING_REQUIREMENTS
        assert posture["unmappable_controls"] == []
        # The two checks `practices.UNMAPPED` excludes, named rather than silently
        # contributing nothing.
        assert set(posture["unmapped_checks"]) == {
            "m365.identity.risky_users_resolved",
            "m365.policy.session_reauthentication_required",
        }

        # 13 of 110 assessed -- 11 failing plus 3.1.8 and 3.3.1. It was 13 while a
        # relatedness crosswalk spread each verdict across neighbouring
        # requirements; the smaller number is the one the evidence supports, and
        # it is still a percentage of the framework rather than of what was
        # checked.
        assert posture["assessed_pct"] == 11.8

        # The gap report, on the same scan, still answers its own question.
        assert gaps["failing"] == len(FAILING_CHECKS)
        assert gaps["passing"] == len(EXPECTED_VERDICTS) - len(FAILING_CHECKS)
        assert gaps["open"] == len(FAILING_CHECKS), "nothing accepted, so all are open"
        assert gaps["accepted"] == 0
        # 2 MFA users + 1 stale user + 1 device + 1 risky user + 1 stale security
        # alert, plus the eight tenant-wide failures: those share one resource id
        # but are eight separate rows, one per check, so the tenant is not counted
        # once. The alert is its own resource because the check judges alerts
        # individually -- a failure names the one to go and work.
        assert gaps["resources_failing"] == 14
    finally:
        await _cleanup(org_id, seeded)


# ---------------------------------------------------------------------------
# Link 5: the SSP declines to call a failing control implemented
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_ssp_discloses_the_findings_and_stops_claiming_implemented(
    broken_tenant,
) -> None:
    """The plan's fourth acceptance criterion, on the same fixture.

    Each entry was seeded claiming "Implemented". Three of the four controls
    are failing, and the document must say so rather than let the claim stand.

    ``AC-17`` is the one that matters most here. No check names it as a primary
    control -- it is reachable only as the second control the legacy-auth check
    declares. An SSP that disclosed the report-only Conditional Access policy
    under ``IA-2`` while ``AC-17`` (remote access) kept reading "Implemented"
    is precisely the document that gets an assessor to the wrong conclusion.
    """
    org_id, system_id, project_id, seeded = await _environment()
    try:
        await _scan(system_id)

        async with session_scope() as s:
            project = await s.get(SSPProject, project_id)
            profile = (
                await s.execute(
                    select(SystemProfile).where(SystemProfile.system_id == system_id)
                )
            ).scalar_one()
            result = await automation_engine.generate_statements(
                s, project=project, profile=profile, mark_draft=False
            )

        async with session_scope() as s:
            entries = {
                e.control_id: e
                for e in (
                    (
                        await s.execute(
                            select(SSPControlEntry).where(
                                SSPControlEntry.project_id == project_id
                            )
                        )
                    )
                    .scalars()
                    .all()
                )
            }

        for control_id in ("IA-2", "AC-2", "AC-17"):
            text = entries[control_id].part_narratives[0]["text"]
            assert "Open finding" in text, control_id
            assert "POA&M #" in text, f"{control_id} cites no POA&M"
            assert entries[control_id].implementation_status == ["Partially Implemented"], (
                f"{control_id} still claims Implemented beside an open finding"
            )

        au2 = entries["AU-2"].part_narratives[0]["text"]
        assert "Verified by automated testing" in au2
        assert "Open finding" not in au2
        assert entries["AU-2"].implementation_status == ["Implemented"]

        assert result["controls_with_open_findings"] == 3
        assert result["status_downgraded_by_findings"] == 3
    finally:
        await _cleanup(org_id, seeded)
