"""Shared CMMC Level 2 / NIST SP 800-171 Rev.2 SSP vocabulary used by seeding,
the API, and the docx generator. This is not a FedRAMP or NIST SP 800-53
vocabulary; some field names (e.g. Control Origination) use FedRAMP-style
terminology adapted for CMMC, but the content is CMMC/800-171.
"""

from __future__ import annotations

# Prefix marking machine-drafted narrative content that a human must review.
DRAFT_PREFIX = "[DRAFT] "

# CMMC 2.0 Level 2 domain → (NIST 800-171 §, human name).
DOMAINS: dict[str, tuple[str, str]] = {
    "AC": ("3.1", "Access Control"),
    "AT": ("3.2", "Awareness and Training"),
    "AU": ("3.3", "Audit and Accountability"),
    "CM": ("3.4", "Configuration Management"),
    "IA": ("3.5", "Identification and Authentication"),
    "IR": ("3.6", "Incident Response"),
    "MA": ("3.7", "Maintenance"),
    "MP": ("3.8", "Media Protection"),
    "PS": ("3.9", "Personnel Security"),
    "PE": ("3.10", "Physical Protection"),
    "RA": ("3.11", "Risk Assessment"),
    "CA": ("3.12", "Security Assessment"),
    "SC": ("3.13", "System and Communications Protection"),
    "SI": ("3.14", "System and Information Integrity"),
}

# Order domains appear in the document (by section number).
DOMAIN_ORDER = sorted(DOMAINS, key=lambda d: [int(p) for p in DOMAINS[d][0].split(".")])

IMPLEMENTATION_STATUS_OPTIONS = (
    "Implemented",
    "Partially Implemented",
    "Planned",
    "Alternative Implementation",
    "Not Applicable",
)

CONTROL_ORIGINATION_OPTIONS = (
    "Organization Corporate",
    "Organization System Specific",
    "Organization Hybrid",
    "Configured by Customer / Business Owner",
    "Provided by Customer / External Provider",
    "Shared",
    "Inherited",
)

ORIGINATION_DEFINITIONS: tuple[tuple[str, str], ...] = (
    (
        "Organization Corporate",
        "Originates from organization-wide governance or shared enterprise services "
        "(corporate policy, identity, logging) that apply across systems.",
    ),
    (
        "Organization System Specific",
        "Specific to this system or CMMC enclave and not fully covered by corporate controls.",
    ),
    (
        "Organization Hybrid",
        "Implemented through both enterprise services and system-specific technical or "
        "procedural additions.",
    ),
    (
        "Configured by Customer / Business Owner",
        "A system owner, business owner, or tenant administrator must configure options to "
        "meet the requirement.",
    ),
    (
        "Provided by Customer / External Provider",
        "A customer, external provider, or managed service provider must provide hardware, "
        "software, or a service to meet the requirement.",
    ),
    (
        "Shared",
        "Managed and implemented partially by the organization and partially by a "
        "cloud/external service provider.",
    ),
    (
        "Inherited",
        "Inherited from another system or provider with an existing authorization "
        "(e.g., a FedRAMP-authorized cloud service).",
    ),
)

# Map the scoring matrix' Microsoft 365 coverage status to a default origination.
COVERAGE_TO_ORIGINATION: dict[str, list[str]] = {
    "Shared Coverage": ["Shared"],
    "Customer Responsibility": ["Configured by Customer / Business Owner"],
    "Microsoft Coverage": ["Inherited"],
    "Not Applicable": ["Organization System Specific"],
}

# Domain-level responsibility for platforms whose cloud coverage is only known
# per CMMC domain rather than per individual control (Microsoft 365 is the only
# platform with per-practice data — see COVERAGE_TO_ORIGINATION above). Keyed by
# the SSP authoring platform code (see ssp/platforms.py PLATFORMS), then CMMC
# domain, to a responsibility bucket. ``ccf.governance.automation`` derives its
# per-practice scoring responsibility from this same table (translating its
# intake-questionnaire ``cloud_platform`` code to this SSP platform code first)
# so a platform's SPRS-scoring responsibility and its SSP control origination
# never disagree.
#
# A domain not listed here has no known per-control *or* per-domain responsibility
# for that platform — origination must not be guessed; see
# ``needs_manual_responsibility_assignment``.
PLATFORM_DOMAIN_RESPONSIBILITY: dict[str, dict[str, str]] = {
    "azure": {
        "PE": "inherited",
        "MA": "shared",
        "SC": "shared",
        "AU": "shared",
        "CM": "shared",
        "SI": "shared",
    },
    "aws_govcloud": {
        "PE": "inherited",
        "MA": "shared",
        "SC": "shared",
        "AU": "shared",
        "CM": "shared",
        "SI": "shared",
    },
}

# Responsibility bucket -> control origination, reusing CONTROL_ORIGINATION_OPTIONS.
# Deliberately has no "system-specific"/"organization implemented" entry for
# "inherited"/"shared" — a provider-performed or provider-shared control must
# never render as purely organization/system-specific.
RESPONSIBILITY_TO_ORIGINATION: dict[str, list[str]] = {
    "inherited": ["Inherited"],
    "shared": ["Shared"],
    "customer": ["Configured by Customer / Business Owner"],
}

# Clear flag used (in ``responsible_role``, not ``control_origination`` — origination
# stays within CONTROL_ORIGINATION_OPTIONS) when a non-M365 platform has no
# per-control or per-domain responsibility data for a control, so an assessor must
# assign responsibility explicitly instead of the seed silently guessing one.
MANUAL_RESPONSIBILITY_FLAG = "Requires Manual Responsibility Assignment"


def platform_responsibility(platform: str, domain: str | None) -> str | None:
    """Responsibility bucket ('inherited' | 'shared') for a non-M365 platform's
    domain, from the domain-level coverage table, or ``None`` if this
    platform/domain combination has no per-control or per-domain data (see
    :func:`needs_manual_responsibility_assignment`)."""
    return PLATFORM_DOMAIN_RESPONSIBILITY.get(platform, {}).get((domain or "").upper())


def needs_manual_responsibility_assignment(platform: str, domain: str | None) -> bool:
    """True when a non-M365 platform has no per-control/per-domain responsibility
    data for this control, so origination can't be derived and must be flagged
    for a human to assign explicitly rather than silently defaulted."""
    return platform != "m365" and platform_responsibility(platform, domain) is None


def platform_origination(
    platform: str, coverage_status: str | None, domain: str | None
) -> list[str]:
    """Control origination for a control on the SSP project's *selected* platform.

    Microsoft 365 has per-practice coverage data (``coverage_status``, from the
    scoring matrix' M365 placemat) — see :func:`default_origination`. Every other
    platform only has the domain-level table above: a covered domain's origination
    reflects who actually performs the control on that platform (never copies the
    M365 split); a domain with no per-control/per-domain data is left unset here
    rather than silently defaulted (see :func:`needs_manual_responsibility_assignment`).
    """
    if platform == "m365":
        return default_origination(coverage_status)
    resp = platform_responsibility(platform, domain)
    return list(RESPONSIBILITY_TO_ORIGINATION.get(resp or "", []))


def section_number(domain: str) -> str:
    return DOMAINS.get(domain, ("3.x", domain))[0]


def domain_name(domain: str) -> str:
    return DOMAINS.get(domain, (domain, domain))[1]


def responsible_role_for(domain: str) -> str:
    return f"{domain_name(domain)} Lead / System Owner"


def default_origination(coverage_status: str | None) -> list[str]:
    return list(COVERAGE_TO_ORIGINATION.get(coverage_status or "", []))
