"""Platform-specific sample SSP control statements.

Lets an SSP project target a deployment platform — Microsoft 365, Microsoft
Azure (Gov), or AWS GovCloud (US) — and seed each control's narrative with a
tailorable draft that references the services that platform actually uses for
that CMMC domain. The drafts remain fully editable in the SSP editor.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from . import constants

if TYPE_CHECKING:  # pragma: no cover
    from ..models import ScoringControl

DEFAULT_PLATFORM = "m365"

# code → human label shown in the UI / document.
PLATFORMS: dict[str, str] = {
    "m365": "Microsoft 365 (Entra ID / Purview / Intune)",
    "azure": "Microsoft Azure (Gov)",
    "aws_govcloud": "AWS GovCloud (US)",
}

# Government-cloud environment names used in customer-responsibility drafts.
GOV_ENVIRONMENTS: dict[str, str] = {
    "m365": "Microsoft 365 Government (GCC High)",
    "azure": "Microsoft Azure Government",
    "aws_govcloud": "AWS GovCloud (US)",
}

PLATFORM_CHOICES = tuple(PLATFORMS)

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


def normalize_platform(platform: str | None) -> str:
    return platform if platform in PLATFORMS else DEFAULT_PLATFORM


def platform_label(platform: str | None) -> str:
    return PLATFORMS.get(normalize_platform(platform), PLATFORMS[DEFAULT_PLATFORM])


def services_for(platform: str | None, domain: str | None) -> str:
    table = _SERVICES.get(normalize_platform(platform), {})
    return table.get((domain or "").upper(), "the platform's native security services")


def sample_statement(platform: str | None, rec: ScoringControl, part: dict[str, str]) -> str:
    """Compose a platform-specific narrative for one determination part."""
    plat = normalize_platform(platform)
    label = PLATFORMS[plat]
    obj = (part.get("text") or "").strip().rstrip(".")
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
    return body


def customer_responsibility_statement(platform: str | None, rec: ScoringControl) -> str:
    """Draft a customer-responsibility narrative for a Government-cloud environment.

    Used for controls the cloud provider does not fully cover, where the customer
    must configure and evidence the control in their own tenant/account. Prefixed
    with the draft indicator so a human reviews and finalizes it.
    """
    plat = normalize_platform(platform)
    env = GOV_ENVIRONMENTS[plat]
    services = services_for(plat, rec.domain)
    obj = (rec.requirement or rec.title or "this requirement").strip().rstrip(".")
    return (
        f"{constants.DRAFT_PREFIX}As a customer responsibility within {env}, the organization "
        f"configures and maintains {services} to satisfy {obj}. Organization-defined parameters "
        f"and configuration settings are established by the System Owner and evidenced in the "
        f"{env} tenant/account configuration."
    )
