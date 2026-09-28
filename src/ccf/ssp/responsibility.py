"""Versioned shared-responsibility templates for SSP and live-audit planning.

The older SSP code had responsibility facts embedded in ``constants.py`` as a
domain table. This module makes them first-class template entries so the same
answer can be cited by SSP origination, readiness output, and the upcoming
audit-plan resolver.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal

Responsibility = Literal[
    "customer",
    "provider",
    "shared",
    "inherited",
    "not_applicable",
    "unknown",
]

TEMPLATE_VERSION = "2026-09-26.1"
FRAMEWORK_CMMC = "cmmc-800-171"
FRAMEWORK_80053 = "nist-800-53r5"
NO_PLATFORM = "none"

RESPONSIBILITY_TO_ORIGINATION: dict[str, list[str]] = {
    "provider": ["Inherited"],
    "inherited": ["Inherited"],
    "shared": ["Shared"],
    "customer": ["Configured by Customer / Business Owner"],
    "not_applicable": [],
    "unknown": [],
}


@dataclass(frozen=True)
class ResponsibilityEntry:
    """One shared-responsibility assertion from a provider template."""

    platform: str
    framework: str
    responsibility: Responsibility
    version: str = TEMPLATE_VERSION
    scope: str = "domain"
    domain: str | None = None
    control_id: str | None = None
    source: str = "concord-default"
    rationale: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return asdict(self)


def _entry(
    platform: str,
    domain: str,
    responsibility: Responsibility,
    *,
    framework: str = FRAMEWORK_CMMC,
    rationale: str | None = None,
) -> ResponsibilityEntry:
    return ResponsibilityEntry(
        platform=platform,
        framework=framework,
        domain=domain,
        responsibility=responsibility,
        rationale=rationale,
    )


_HYPERSCALER_DOMAIN_RESPONSIBILITY: dict[str, Responsibility] = {
    "PE": "inherited",
    "MA": "shared",
    "SC": "shared",
    "AU": "shared",
    "CM": "shared",
    "SI": "shared",
}

_M365_COVERAGE_TO_RESPONSIBILITY: dict[str, Responsibility] = {
    "Shared Coverage": "shared",
    "Customer Responsibility": "customer",
    "Microsoft Coverage": "inherited",
    "Not Applicable": "not_applicable",
}

_TEMPLATES: dict[tuple[str, str], tuple[ResponsibilityEntry, ...]] = {
    (platform, FRAMEWORK_CMMC): tuple(
        _entry(platform, domain, resp)
        for domain, resp in _HYPERSCALER_DOMAIN_RESPONSIBILITY.items()
    )
    for platform in ("azure", "aws_govcloud", "gcp")
}


def template_entries(
    platform: str, framework: str = FRAMEWORK_CMMC
) -> tuple[ResponsibilityEntry, ...]:
    """Responsibility entries for a platform/framework template."""
    if platform == NO_PLATFORM:
        return tuple(
            _entry(NO_PLATFORM, domain, "customer", framework=framework)
            for domain in (
                "AC",
                "AT",
                "AU",
                "CA",
                "CM",
                "IA",
                "IR",
                "MA",
                "MP",
                "PE",
                "PS",
                "RA",
                "SC",
                "SI",
            )
        )
    return _TEMPLATES.get((platform, framework), ())


def responsibility_for(
    platform: str,
    domain: str | None,
    *,
    framework: str = FRAMEWORK_CMMC,
    coverage_status: str | None = None,
) -> Responsibility:
    """Responsibility bucket for a platform/domain/control context."""
    normalized_domain = (domain or "").upper()
    if platform == "m365":
        return _M365_COVERAGE_TO_RESPONSIBILITY.get(coverage_status or "", "unknown")
    if platform == NO_PLATFORM:
        return "customer"
    for entry in template_entries(platform, framework):
        if entry.domain == normalized_domain:
            return entry.responsibility
    return "unknown"


def responsibility_entry_for(
    platform: str,
    domain: str | None,
    *,
    framework: str = FRAMEWORK_CMMC,
    coverage_status: str | None = None,
) -> ResponsibilityEntry:
    """The matching template entry, or an explicit unknown entry."""
    resp = responsibility_for(
        platform,
        domain,
        framework=framework,
        coverage_status=coverage_status,
    )
    return ResponsibilityEntry(
        platform=platform,
        framework=framework,
        domain=(domain or "").upper() or None,
        responsibility=resp,
        source="m365-coverage-status" if platform == "m365" else "concord-default",
    )


def origination_for(responsibility: str) -> list[str]:
    """SSP control origination values for a responsibility bucket."""
    return list(RESPONSIBILITY_TO_ORIGINATION.get(responsibility, []))


def scan_applicability(responsibility: str) -> str:
    """How a live audit should treat controls with this responsibility.

    ``scan`` means provider API checks may directly evaluate customer/shared
    implementation. ``inherited_evidence`` means the audit should ask for
    authorization/provider evidence instead of scanning customer configuration.
    ``manual_scope_review`` means the template has no safe answer yet.
    """
    if responsibility in {"customer", "shared"}:
        return "scan"
    if responsibility in {"provider", "inherited"}:
        return "inherited_evidence"
    if responsibility == "not_applicable":
        return "not_applicable"
    return "manual_scope_review"


def control_domain(control_id: str | None) -> str | None:
    """Best-effort family/domain from a CMMC or 800-53 style control id."""
    if not control_id:
        return None
    head = control_id.split(".", 1)[0].split("-", 1)[0]
    return head.upper() or None
