"""Platform-specific sample SSP control statements.

Lets an SSP project target a deployment platform — Microsoft 365, Microsoft
Azure (Gov), or AWS GovCloud (US) — and seed each control's narrative with a
tailorable draft that references the services that platform actually uses for
that CMMC domain. The drafts remain fully editable in the SSP editor.

:data:`NO_PLATFORM` is the fourth, equally real member: the intake
questionnaire offers "none" as one of its four answers to "Primary cloud
platform?", and a customer who picks it has *told us something*, not left a
field blank. It carries an honest label and an **empty** service catalog, so a
statement generator asking "what services implement AC here" gets nothing and
must say so rather than borrow another platform's answer.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import TYPE_CHECKING

from . import constants

if TYPE_CHECKING:  # pragma: no cover
    from ..models import ScoringControl

#: The platform code meaning "this customer declared no cloud platform".
#:
#: A *value*, not an absence: it is one of the four answers the intake
#: questionnaire offers, and the column stays ``NOT NULL`` because of it. Never
#: use it for "we do not know what they have" — see :func:`normalize_platform`.
NO_PLATFORM = "none"

# code → human label shown in the UI / document.
PLATFORMS: dict[str, str] = {
    "m365": "Microsoft 365 (Entra ID / Purview / Intune)",
    "azure": "Microsoft Azure (Gov)",
    "aws_govcloud": "AWS GovCloud (US)",
    # Worded so no reader could mistake it for a product. Everything about this
    # entry exists to remove the pressure that made a default look reasonable:
    # ``normalize_platform`` used to have to return *something*, and the only
    # somethings available were real product names.
    NO_PLATFORM: "No cloud platform declared",
}

#: The platforms that are an actual cloud product — everything in
#: :data:`PLATFORMS` except :data:`NO_PLATFORM`. Anything asserting a property
#: every *product* has (a service catalog, a FIPS-validated module, a
#: government environment) must iterate this, not ``PLATFORMS``.
CLOUD_PLATFORMS: tuple[str, ...] = tuple(p for p in PLATFORMS if p != NO_PLATFORM)

# Government-cloud environment names used in customer-responsibility drafts.
#
# "m365" deliberately does NOT assert a specific Government tier here: Microsoft
# 365 spans commercial, GCC, GCC High, and DoD tenants, and this module only
# ever sees the SSP authoring platform code ("m365") — never the customer's
# actual tenant. Asserting "GCC High" without confirming that's the real tenant
# is a factual claim this code cannot make (FR-07); use ``environment_for``
# below when the caller *does* have the confirmed intake ``cloud_platform``
# code (see ccf.governance.automation.PLATFORM_TO_SSP), which is the only
# place "GCC High" language may be rendered. Azure and AWS GovCloud each have
# exactly one government offering in PLATFORMS/the intake questionnaire, so
# their labels are safe to assert outright regardless of caller context.
GOV_ENVIRONMENTS: dict[str, str] = {
    "m365": "Microsoft 365 (tenant tier not confirmed)",
    "azure": "Microsoft Azure Government",
    "aws_govcloud": "AWS GovCloud (US)",
    # Not a government cloud, and not a blank: the customer said there is no
    # cloud platform. Phrased to read correctly in the sentences that embed it
    # ("... implements Control AC-2 on {environment} by configuring ...").
    NO_PLATFORM: "an environment with no declared cloud platform",
}

# The one intake questionnaire cloud_platform code (see
# ccf.governance.automation.QUESTIONNAIRE / PLATFORM_TO_SSP) that confirms the
# customer's Microsoft 365 tenant is specifically GCC High. Any other value
# (None, "none", "aws_govcloud", "azure_gov", or simply absent because the SSP
# project was authored directly without a derived profile) leaves the tier
# unconfirmed, so "GCC High" must not be rendered.
M365_GCC_HIGH_CLOUD_CODE = "m365_gcc_high"

# SSP platform code → the ``ccf.connectors`` registry key that can capture it.
#
# THE single source for this correspondence. The two name spaces are NOT the
# same — SSP platform "m365" is captured by the connector registered under
# "msgraph" — and before this mapping existed that fact was written down
# nowhere, with a second hand-maintained set of platform codes to drift against.
# ``CONNECTOR_PLATFORMS`` is derived from it rather than maintained beside it.
#
# Only SSP platforms belong here: a registry key with no PLATFORMS entry (e.g.
# "puppetdb") is a connector for something that is not a deployment platform.
# ``tests/test_connector_backed_claim.py`` asserts every value here is a real
# key in :func:`ccf.connectors.connector_keys`, so renaming or removing a
# connector fails loudly instead of silently making a platform look unbacked.
PLATFORM_CONNECTOR_KEYS: Mapping[str, str] = MappingProxyType(
    {
        "m365": "msgraph",
        "aws_govcloud": "aws_govcloud",
    }
)

# Platforms Concord *ships* a capture connector for. This is a fact about
# Concord's feature set — NOT about any particular tenant, which may have
# configured nothing. Deciding whether a statement is evidenced needs the
# tenant-aware check (``ccf.governance.automation.platform_capture_is_live``).
CONNECTOR_PLATFORMS: frozenset[str] = frozenset(PLATFORM_CONNECTOR_KEYS)

# Appended to every auto-composed statement for a platform Concord ships no
# capture connector for at all (Azure today), so a reviewer — and
# ccf.governance.automation's coverage rollup — can tell the claim was never
# technically verified and needs a human to attach evidence before the control
# counts as covered.
MANUAL_EVIDENCE_NOTE = (
    "[MANUAL-EVIDENCE-REQUIRED — NO CONNECTOR: no automated capture connector "
    "exists for this platform; a human must attach evidence before this control "
    "is considered evidenced.]"
)

# The same flag for the other reason: Concord *does* ship a connector for this
# platform, but THIS organization has none that has actually captured anything.
# Rendering the NO CONNECTOR wording here would itself be a false statement, so
# the reason is stated accurately while the reviewer-facing requirement is
# identical.
#
# The wording has to stay true of EVERY way
# ``ccf.governance.control_tests.organization_capture_is_live`` can answer no —
# no connector row; one that is not configured, never synced, stale, or
# discovered nothing; no capture artifact or only a stale one; and a capture
# made under a host profile rather than this tenant's own credential. It used
# to name a single rung ("has completed a recent, non-empty sync"), which a
# profile-backed connector that HAS synced recently and non-emptily falsifies:
# the caveat would be correctly added and then given a false reason for it.
NO_TENANT_CAPTURE_NOTE = (
    "[MANUAL-EVIDENCE-REQUIRED — NO TENANT CAPTURE: this organization has no "
    "capture connector for this platform that has recently captured "
    "configuration under the organization's own credential; a human must "
    "attach evidence before this control is considered evidenced.]"
)

# The substring common to both notes — what a reader/report keys off to find a
# statement that is flagged as needing manual evidence, whatever the reason.
MANUAL_EVIDENCE_MARKER = "[MANUAL-EVIDENCE-REQUIRED"

PLATFORM_CHOICES = tuple(PLATFORMS)

# What a drafted statement may say in place of a service name when there is no
# catalog to read one from — either because the customer declared no cloud
# platform, or because the platform they declared is one Concord does not know.
# Never "the platform's native security services": for a system with no
# platform there are none, and for an unrecognized one Concord cannot say what
# they are. The bracket convention is ssp/odp.py's, so ssp/completeness.py
# already counts it as unresolved and a human is asked to resolve it.
NO_SERVICES_TEXT = "[ORGANIZATION-DEFINED: the mechanisms that implement this requirement]"

# The sentence a drafted statement carries instead of a mechanism, whenever
# there is no service catalog behind it. It exists so the absence is *stated*:
# a narrative that simply stops naming services is indistinguishable from one
# whose author thought none were needed.
NO_CATALOG_NOTE = (
    "Concord has no platform service catalog to draft from for this system, so no product "
    "or service is named here; the organization must describe the mechanisms that implement "
    "this requirement."
)

# The same absence for the other two reasons. Worded to match what the guided
# onboarding path already tells a customer at step 2 ("Concord does not
# recognize the declared platform ..."), so the two surfaces agree.
UNRECOGNIZED_PLATFORM_NOTE = (
    "Concord does not recognize the declared platform {declared!r}, so it cannot name the "
    "services that implement this requirement and names none here; the organization must "
    "describe the mechanisms it uses."
)
NO_PLATFORM_ON_RECORD_NOTE = (
    "No platform is on record for this system, so Concord cannot name the services that "
    "implement this requirement and names none here; the organization must describe the "
    "mechanisms it uses."
)

# Representative services / mechanisms per platform, per CMMC domain. Drafts are
# meant as a credible starting point an assessor edits — not authoritative.
_SERVICES: dict[str, dict[str, str]] = {
    "m365": {
        "AC": "Microsoft Entra ID Conditional Access, role-based access control, and Intune "
        "device compliance",
        "AT": "the organization's awareness program with Attack Simulation Training in "
        "Microsoft Defender for Office 365",
        "AU": "Microsoft Purview Audit (unified audit log), Entra ID sign-in logs, and "
        "Microsoft Sentinel",
        "CA": "Microsoft Secure Score and Compliance Manager assessments",
        "CM": "Intune configuration profiles and security baselines with Defender for Endpoint",
        "IA": "Entra ID multifactor authentication, FIDO2/certificate-based authentication, "
        "and password protection",
        "IR": "Microsoft Defender XDR and Microsoft Sentinel incident response",
        "MA": "Intune/Microsoft Endpoint Manager maintenance controls",
        "MP": "Microsoft Purview Information Protection sensitivity labels and Intune BitLocker",
        "PE": "physical safeguards inherited from Microsoft's FedRAMP-authorized datacenters, "
        "with customer-managed facility controls for endpoints",
        "PS": "Entra ID HR-driven provisioning and access reviews",
        "RA": "Microsoft Defender Vulnerability Management and Secure Score",
        "SC": "Microsoft Purview encryption, enforced TLS, and Defender for Cloud Apps",
        "SI": "Microsoft Defender for Endpoint/Office 365, Purview DLP, and Windows Update "
        "for Business",
    },
    "azure": {
        "AC": "Microsoft Entra ID with Azure RBAC, Conditional Access, and Privileged Identity "
        "Management",
        "AT": "the organization's awareness program, with completion evidence retained in "
        "Azure Monitor",
        "AU": "Azure Monitor, Log Analytics, the Azure Activity Log, and Microsoft Sentinel",
        "CA": "Microsoft Defender for Cloud regulatory compliance and Azure Policy",
        "CM": "Azure Policy, Azure Update Manager/Automation, and Bicep/ARM baselines",
        "IA": "Entra ID MFA and PIM, managed identities, and Azure Key Vault",
        "IR": "Microsoft Defender for Cloud and Microsoft Sentinel playbooks",
        "MA": "Azure Update Manager and Azure Automation",
        "MP": "Azure Storage Service Encryption, Azure Disk Encryption, and Key Vault",
        "PE": "physical safeguards inherited from the Azure Government FedRAMP High datacenters",
        "PS": "Entra ID access reviews and lifecycle workflows",
        "RA": "Microsoft Defender for Cloud and Defender Vulnerability Management",
        "SC": "Azure Firewall, network security groups, Application Gateway WAF, Key Vault, "
        "Private Link, and enforced TLS",
        "SI": "Microsoft Defender for Cloud, Defender for Servers, and Azure Update Manager",
    },
    # Deliberately empty: nothing platform-specific can be drafted for a system
    # that declared no cloud platform, and an empty table is what makes that
    # structurally true rather than a rule someone must remember.
    NO_PLATFORM: {},
    "aws_govcloud": {
        "AC": "AWS IAM and IAM Identity Center with service control policies and permission "
        "boundaries",
        "AT": "the organization's awareness program, with completion records retained in the "
        "AWS account",
        "AU": "AWS CloudTrail, Amazon CloudWatch Logs, AWS Config, and AWS Security Hub",
        "CA": "AWS Security Hub (NIST 800-171/CMMC standard) and AWS Audit Manager",
        "CM": "AWS Config, AWS Systems Manager (State Manager, Patch Manager), and CloudFormation",
        "IA": "AWS IAM MFA, IAM Identity Center, AWS Certificate Manager, and AWS Secrets Manager",
        "IR": "Amazon GuardDuty, AWS Security Hub, Amazon Detective, and documented runbooks",
        "MA": "AWS Systems Manager Maintenance Windows and Patch Manager",
        "MP": "Amazon EBS/S3 encryption with AWS KMS and S3 Object Lock",
        "PE": "physical safeguards inherited from the AWS GovCloud (US) FedRAMP High datacenters",
        "PS": "AWS IAM lifecycle management and IAM Access Analyzer reviews",
        "RA": "Amazon Inspector, AWS Security Hub, and Amazon GuardDuty",
        "SC": "security groups, network ACLs, AWS Network Firewall, AWS WAF, AWS KMS, "
        "AWS Certificate Manager, and enforced TLS",
        "SI": "Amazon Inspector, Amazon GuardDuty, AWS Systems Manager Patch Manager, and AWS WAF",
    },
}


# FIPS 140-2/140-3 validated-module + key-custody language appended to SC-family
# (System and Communications Protection) statements only. Per FR-08, generic
# "TLS/encryption" service names read as boilerplate to an assessor — the platform's
# validated cryptographic module and key custody must be named. The specific
# certificate number / KMS key ARN is never fabricated; it is left as an
# organization-defined placeholder using the same bracket convention completeness.py
# already treats as unresolved (see ssp/odp.py's "[ORGANIZATION-DEFINED: ...]").
_FIPS_KEY_CUSTODY: dict[str, str] = {
    "m365": (
        "Cryptographic protection relies on FIPS 140-2 validated cryptographic modules "
        "within Microsoft's FIPS 140 validated boundary (Microsoft Purview Information "
        "Protection / Azure RMS encryption); key custody is [ORGANIZATION-DEFINED: FIPS "
        "140-2 certificate number and key-custody owner (Microsoft-managed key vs. "
        "customer key)]."
    ),
    "azure": (
        "Cryptographic protection relies on Azure Key Vault backed by FIPS 140-2 "
        "validated hardware security modules; key custody is [ORGANIZATION-DEFINED: "
        "FIPS 140-2 certificate number and Key Vault/Managed HSM key-custody owner]."
    ),
    "aws_govcloud": (
        "Cryptographic protection relies on AWS KMS FIPS 140-2 validated endpoints; "
        "key custody is [ORGANIZATION-DEFINED: FIPS 140-2 certificate number and KMS "
        "customer-managed-key custody owner]."
    ),
}


def _fips_key_custody_note(platform: str | None, domain: str | None) -> str:
    """Return the platform's FIPS-validated-module/key-custody sentence for
    SC-family statements, or "" for every other control family."""
    if (domain or "").upper() != "SC":
        return ""
    return _FIPS_KEY_CUSTODY.get(platform or "", "")


def normalize_platform(platform: str | None) -> str | None:
    """The :data:`PLATFORMS` code for ``platform``, or ``None`` if there is none.

    ``None`` means *Concord does not recognize this* — a typo, a value from a
    future questionnaire, or a platform (GCP, Oracle, on-premises) Concord does
    not support. It is emphatically **not** :data:`NO_PLATFORM`, which means
    *the customer told us they have no cloud platform*. Collapsing the first
    into the second would repeat the defect this module was fixed for one layer
    over: silence presented as an answer.

    The return type is what makes that unavoidable. Every caller now has to
    decide what an unrecognized value means for it, and ``mypy`` fails the
    caller that forgets — the same reasoning as ``coverage``'s keyword-only
    ``connector_backed``: a forgotten caller should be an error, not a silent
    false claim. Callers divide into write paths, which must refuse the value
    (422) rather than store a platform nobody chose, and read paths, which must
    say what was declared and draft nothing platform-specific for it.
    """
    return platform if platform in PLATFORMS else None


def _declared(platform: str | None) -> str:
    return (platform or "").strip()


def catalog_absence_note(platform: str | None) -> str:
    """Why a drafted statement names no product or service, in this caller's case.

    Three distinct absences, never collapsed into one (spec §2.1): the customer
    declared no cloud platform; the customer declared one Concord does not
    recognize; nothing is on record at all. A narrative that merely stops
    naming services is indistinguishable from one whose author thought none
    were needed, so the reason is always stated.
    """
    plat = normalize_platform(platform)
    if plat == NO_PLATFORM:
        return NO_CATALOG_NOTE
    declared = _declared(platform)
    if declared:
        return UNRECOGNIZED_PLATFORM_NOTE.format(declared=declared)
    return NO_PLATFORM_ON_RECORD_NOTE


def platform_label(platform: str | None) -> str:
    """A human label for ``platform`` that never names a product it is not.

    An unrecognized code renders as itself, quoted — "say what was declared",
    never substitute. Before this, every unrecognized code rendered as
    "Microsoft 365 (Entra ID / Purview / Intune)".
    """
    plat = normalize_platform(platform)
    if plat is not None:
        return PLATFORMS[plat]
    declared = _declared(platform)
    return f"Unrecognized platform: {declared}" if declared else "No platform on record"


def connector_key_for_platform(platform: str | None) -> str | None:
    """The ``ccf.connectors`` registry key that can capture this SSP platform.

    ``None`` when Concord ships no connector for the platform at all (Azure
    today, and :data:`NO_PLATFORM`, which has nothing to connect to) — the
    platform's service catalog stays usable for drafting, but statements built
    from it can never be auto-evidenced.

    ``None`` is *also* what an unrecognized code yields, and the two are not
    the same fact: "Concord ships no connector for this platform" versus
    "Concord does not know what this platform is". A caller that must tell a
    customer *why* there is nothing to connect — ``ccf.onboarding``'s step 2 —
    must therefore resolve the platform itself and read
    :data:`PLATFORM_CONNECTOR_KEYS` directly rather than call this.

    A non-``None`` key answers only the *support* question: Concord has code
    that could capture this platform. It says nothing about whether any
    particular organization has configured it, so it must never on its own
    decide whether a statement carries the manual-evidence caveat. Use
    :func:`ccf.governance.automation.platform_capture_is_live` for that.
    """
    plat = normalize_platform(platform)
    if plat is None:
        return None
    return PLATFORM_CONNECTOR_KEYS.get(plat)


def environment_for(platform: str | None, cloud_platform: str | None = None) -> str:
    """Environment label for ``platform``, honoring the *confirmed* tenant tier.

    ``cloud_platform`` is the raw intake questionnaire code (e.g. "m365_gcc_high",
    "azure_gov", "aws_govcloud") when the caller has a SystemProfile to read it
    from. "GCC High" is only ever rendered when that exact code is present;
    otherwise the neutral ``GOV_ENVIRONMENTS`` default is used — "GCC High" is
    never asserted without confirmation (FR-07).
    """
    plat = normalize_platform(platform)
    if plat is None:
        declared = _declared(platform)
        return (
            f"an environment whose declared platform ({declared}) Concord does not recognize"
            if declared
            else "an environment with no platform on record"
        )
    if plat == "m365" and cloud_platform == M365_GCC_HIGH_CLOUD_CODE:
        return "Microsoft 365 Government (GCC High)"
    return GOV_ENVIRONMENTS.get(plat, PLATFORMS[plat])


def services_for(platform: str | None, domain: str | None) -> str:
    """The services that implement ``domain`` on ``platform``, as draft prose.

    A platform with an **empty** catalog (:data:`NO_PLATFORM`) yields the
    organization-defined placeholder, never the "the platform's native security
    services" fallback: that fallback means "this platform has services, we
    just have no per-domain entry for this one", which is false when there is
    no platform at all.
    """
    plat = normalize_platform(platform)
    table = _SERVICES.get(plat, {}) if plat is not None else {}
    if not table:
        return NO_SERVICES_TEXT
    return table.get((domain or "").upper(), "the platform's native security services")


def sample_statement(platform: str | None, rec: ScoringControl, part: dict[str, str]) -> str:
    """Compose a platform-specific narrative for one determination part.

    Prefixed with the draft indicator on every return path, like
    :func:`customer_responsibility_statement`: "sample" text is machine-composed
    by definition, and under CISO-02 :data:`~ccf.ssp.constants.DRAFT_PREFIX`
    in the stored text is the only durable record of that. This is the
    function ``ccf.ssp.seed._narratives`` calls for every control, so a path
    that omitted the marker made the seeder's text read as human-cleared to
    :func:`ccf.ssp.statements.is_draft_narrative` -- the AI-provenance badge
    and ``generate_statements``' preserve rule both key off it.
    """
    plat = normalize_platform(platform)
    obj = (part.get("text") or "").strip().rstrip(".")
    if plat is None or not _SERVICES.get(plat):
        # Nothing platform-specific may be drafted. Say the objective, say why
        # no mechanism is named, and stop — borrowing another platform's
        # catalog here is the whole defect this module was fixed for.
        lead = (
            f"The organization satisfies this objective by ensuring that {obj}."
            if obj
            else "The organization is responsible for meeting this objective."
        )
        return f"{constants.DRAFT_PREFIX}{lead} {catalog_absence_note(platform)}"
    label = PLATFORMS[plat]
    services = services_for(plat, rec.domain)
    if obj:
        body = (
            f"The organization satisfies this objective by ensuring that {obj}, "
            f"implemented through {services} on {label}."
        )
    else:
        body = f"The organization meets this objective using {services} on {label}."
    if plat == "m365" and rec.m365_implementation_statement:
        body += f" Microsoft 365 reference: {rec.m365_implementation_statement.strip()}"
    note = _fips_key_custody_note(plat, rec.domain)
    if note:
        body += f" {note}"
    return f"{constants.DRAFT_PREFIX}{body}"


def customer_responsibility_statement(platform: str | None, rec: ScoringControl) -> str:
    """Draft a customer-responsibility narrative for a Government-cloud environment.

    Used for controls the cloud provider does not fully cover, where the customer
    must configure and evidence the control in their own tenant/account. Prefixed
    with the draft indicator so a human reviews and finalizes it.
    """
    plat = normalize_platform(platform)
    obj = (rec.requirement or rec.title or "this requirement").strip().rstrip(".")
    if plat is None:
        # Unrecognized, which is not the same as none: Concord cannot say what
        # the provider covers, so it says that rather than assign the whole
        # requirement to the organization on a guess.
        return (
            f"{constants.DRAFT_PREFIX}The organization is responsible for satisfying {obj}, "
            f"except for any part a provider implements for it — which Concord cannot "
            f"determine for this system. {catalog_absence_note(platform)}"
        )
    if plat == NO_PLATFORM:
        # With no cloud platform there is no provider, so nothing is inherited
        # and the whole requirement falls to the organization — the same
        # reasoning ``ccf.governance.automation._platform_state`` applies when
        # it derives "customer" for this case.
        return (
            f"{constants.DRAFT_PREFIX}This system declared no cloud platform, so no provider "
            f"implements any part of this requirement for it: the organization is responsible "
            f"for satisfying {obj} in full. Organization-defined parameters and configuration "
            f"settings are established by the System Owner and evidenced in the system's own "
            f"configuration records. {NO_CATALOG_NOTE}"
        )
    env = GOV_ENVIRONMENTS[plat]
    services = services_for(plat, rec.domain)
    text = (
        f"{constants.DRAFT_PREFIX}As a customer responsibility within {env}, the organization "
        f"configures and maintains {services} to satisfy {obj}. Organization-defined parameters "
        f"and configuration settings are established by the System Owner and evidenced in the "
        f"{env} tenant/account configuration."
    )
    note = _fips_key_custody_note(plat, rec.domain)
    if note:
        text += f" {note}"
    return text
