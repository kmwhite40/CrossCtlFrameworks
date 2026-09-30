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

# Domain-level fallback for Microsoft 365, for callers holding a control's
# domain but not its CMMC practice.
#
# M365 is the one platform with *per-practice* coverage data, so the per-practice
# answer above is always preferred. But the live-audit path reaches this module
# from a posture check, and a posture check carries NIST 800-53 control ids
# ("IA-2", "AC-2(3)") rather than CMMC practices. The 800-53 -> 800-171 crosswalk
# in ``framework_mappings`` cannot close that gap: its ``value`` is prose that
# happens to contain a requirement number, and only 4 of the 14 M365 check
# families resolve through it at all. The domain is the finest key both sides
# actually share.
#
# So: each domain takes the responsibility held by the *plurality* of its
# practices in the placemat, ties going to "shared" (the weaker claim, and the
# literal description of an even split). Derived from the committed scoring
# placemat, not composed by hand -- ``tests/test_m365_responsibility_is_answered
# .py`` recomputes it from ``ccf/scoring/seed.json`` and fails if the two drift.
#
# This is a summary, and a domain's minority practices are misdescribed by it.
# That is why it is only ever the fallback, never overrides a known coverage
# status, and reports a different ``source`` than the per-practice answer: a
# reader can tell which question was actually answered.
#
#     domain  practices  shared  customer  microsoft  n/a  -> plurality
#     AC      22         18      4         0          0       shared
#     AT       3          0      3         0          0       customer
#     AU       9          7      2         0          0       shared
#     CA       4          4      0         0          0       shared
#     CM       9          2      6         0          1       customer
#     IA      11         10      1         0          0       shared
#     IR       3          1      2         0          0       customer
#     MA       6          6      0         0          0       shared
#     MP       9          7      2         0          0       shared
#     PE       6          1      0         5          0       inherited
#     PS       2          1      1         0          0       shared (tie)
#     RA       3          3      0         0          0       shared
#     SC      16         11      3         1          1       shared
#     SI       7          4      3         0          0       shared
_M365_DOMAIN_RESPONSIBILITY: dict[str, Responsibility] = {
    "AC": "shared",
    "AT": "customer",
    "AU": "shared",
    "CA": "shared",
    "CM": "customer",
    "IA": "shared",
    "IR": "customer",
    "MA": "shared",
    "MP": "shared",
    "PE": "inherited",
    "PS": "shared",
    "RA": "shared",
    "SC": "shared",
    "SI": "shared",
}

_TEMPLATES: dict[tuple[str, str], tuple[ResponsibilityEntry, ...]] = {
    (platform, FRAMEWORK_CMMC): tuple(
        _entry(platform, domain, resp)
        for domain, resp in _HYPERSCALER_DOMAIN_RESPONSIBILITY.items()
    )
    for platform in ("azure", "aws_govcloud", "gcp")
}

# M365's domain summary is a template entry set like any other, so a caller
# asking "what does the template say about M365?" gets the same answer the
# resolver gives rather than an empty tuple beside a populated table.
_TEMPLATES[("m365", FRAMEWORK_CMMC)] = tuple(
    ResponsibilityEntry(
        platform="m365",
        framework=FRAMEWORK_CMMC,
        domain=domain,
        responsibility=resp,
        source="m365-placemat-domain",
        rationale=(
            "plurality of this domain's practices in the M365 placemat; "
            "a practice's own coverage status overrides it"
        ),
    )
    for domain, resp in _M365_DOMAIN_RESPONSIBILITY.items()
)


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
        if coverage_status:
            # A coverage status we do not recognise stays "unknown" rather than
            # falling through to the domain table: an unmapped status string is
            # a placemat change we need to see, and quietly answering it from
            # the domain summary would hide it.
            return _M365_COVERAGE_TO_RESPONSIBILITY.get(coverage_status, "unknown")
        return _M365_DOMAIN_RESPONSIBILITY.get(normalized_domain, "unknown")
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
    # ``source`` and ``scope`` describe the question that was actually answered.
    # This used to report "m365-coverage-status" for every M365 entry, including
    # the ones resolved with no coverage status at all -- an entry naming a
    # source it had never read, and calling a control-scoped answer "domain".
    if platform == "m365" and coverage_status:
        source, scope = "m365-coverage-status", "control"
    elif platform == "m365":
        source, scope = "m365-placemat-domain", "domain"
    else:
        source, scope = "concord-default", "domain"
    return ResponsibilityEntry(
        platform=platform,
        framework=framework,
        domain=(domain or "").upper() or None,
        responsibility=resp,
        source=source,
        scope=scope,
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
