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


def section_number(domain: str) -> str:
    return DOMAINS.get(domain, ("3.x", domain))[0]


def domain_name(domain: str) -> str:
    return DOMAINS.get(domain, (domain, domain))[1]


def responsible_role_for(domain: str) -> str:
    return f"{domain_name(domain)} Lead / System Owner"


def default_origination(coverage_status: str | None) -> list[str]:
    return list(COVERAGE_TO_ORIGINATION.get(coverage_status or "", []))
