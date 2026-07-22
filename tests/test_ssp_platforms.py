"""Unit tests for platform-specific SSP statement composition.

FR-08: SC-family (System and Communications Protection) statements must name a
FIPS 140-2/140-3 validated cryptographic module and a key-custody phrase instead
of reading as generic service-name boilerplate. Non-SC statements must be
unaffected. Pure functions — no DB required.
"""

from __future__ import annotations

import re

import pytest

from ccf.models import ScoringControl
from ccf.ssp.platforms import (
    PLATFORM_CHOICES,
    customer_responsibility_statement,
    sample_statement,
)

SC_PART = {"label": "a", "text": "cryptography is employed to protect the confidentiality of CUI"}
AC_PART = {"label": "a", "text": "authorized users are identified and access is limited"}

_NON_SC_DOMAINS = ["AC", "AT", "AU", "CA", "CM", "IA", "IR", "MA", "MP", "PE", "PS", "RA", "SI"]


def _rec(domain: str = "SC", **kw: object) -> ScoringControl:
    base: dict[str, object] = dict(
        control_id="SC.L2-3.13.11",
        nist_id="SC-13",
        domain=domain,
        title="Cryptographic Protection",
        requirement="employ FIPS-validated cryptography when used to protect CUI",
        m365_coverage_status="Customer Responsibility",
    )
    base.update(kw)
    return ScoringControl(**base)


@pytest.mark.parametrize("platform", PLATFORM_CHOICES)
def test_sc_statement_names_fips_module_and_key_custody(platform: str) -> None:
    text = sample_statement(platform, _rec(domain="SC"), SC_PART)
    assert "FIPS 140-2" in text
    assert "validated" in text.lower()
    assert "key custody" in text.lower() or "key-custody" in text.lower()


@pytest.mark.parametrize("platform", PLATFORM_CHOICES)
def test_sc_statement_does_not_fabricate_a_cert_number(platform: str) -> None:
    """No made-up FIPS certificate number — a clearly-marked placeholder instead,
    using the same bracket convention as unresolved ODPs (see ssp/odp.py /
    ssp/completeness.py's _ODP_PLACEHOLDER_TOKENS)."""
    text = sample_statement(platform, _rec(domain="SC"), SC_PART)
    assert "[ORGANIZATION-DEFINED:" in text
    assert "FIPS 140-2 certificate" in text
    # guard against accidentally-plausible fabricated cert numbers, e.g. "#1234" / "Cert 4407"
    assert not re.search(r"(?:cert(?:ificate)?\.?\s*#?\s*)\d{2,}", text, re.IGNORECASE)


@pytest.mark.parametrize("platform", PLATFORM_CHOICES)
def test_sc_customer_responsibility_statement_names_fips_module(platform: str) -> None:
    text = customer_responsibility_statement(platform, _rec(domain="SC"))
    assert "FIPS 140-2" in text
    assert "[ORGANIZATION-DEFINED:" in text
    assert text.startswith("[DRAFT] ")


@pytest.mark.parametrize("domain", _NON_SC_DOMAINS)
def test_non_sc_statement_has_no_fips_language(domain: str) -> None:
    text = sample_statement("aws_govcloud", _rec(domain=domain), AC_PART)
    assert "FIPS 140-2" not in text
    assert "[ORGANIZATION-DEFINED:" not in text


@pytest.mark.parametrize("domain", _NON_SC_DOMAINS)
def test_non_sc_customer_responsibility_statement_has_no_fips_language(domain: str) -> None:
    text = customer_responsibility_statement("azure", _rec(domain=domain))
    assert "FIPS 140-2" not in text


def test_non_sc_sample_statement_byte_identical_to_before() -> None:
    """Regression pin: an AC statement's text is exactly what platforms.py produced
    before the SC-only FIPS addition (no incidental whitespace/format changes)."""
    rec = _rec(domain="AC", m365_implementation_statement=None)
    text = sample_statement("aws_govcloud", rec, AC_PART)
    expected = (
        "The organization satisfies this objective by ensuring that authorized users are "
        "identified and access is limited, implemented through AWS IAM and IAM Identity Center "
        "with service control policies and permission boundaries on AWS GovCloud (US)."
    )
    assert text == expected


def test_non_sc_customer_responsibility_statement_byte_identical_to_before() -> None:
    """Regression pin, updated for FR-07: this call site only ever has the SSP
    authoring platform code ("m365"), never the customer's confirmed tenant
    tier, so it must render the neutral GOV_ENVIRONMENTS label rather than
    asserting "GCC High" (see ccf.ssp.platforms.environment_for, used by
    ccf.governance.automation.generate_statements when the confirmed tier
    *is* available)."""
    rec = _rec(domain="AC", requirement="limit system access to authorized users")
    text = customer_responsibility_statement("m365", rec)
    expected = (
        "[DRAFT] As a customer responsibility within Microsoft 365 (tenant tier not "
        "confirmed), the organization configures and maintains Microsoft Entra ID "
        "Conditional Access, role-based access control, and Intune device compliance to "
        "satisfy limit system access to authorized users. Organization-defined parameters "
        "and configuration settings are established by the System Owner and evidenced in "
        "the Microsoft 365 (tenant tier not confirmed) tenant/account configuration."
    )
    assert text == expected


def test_sc_domain_lowercase_still_triggers_fips_note() -> None:
    """Domain matching is case-insensitive, consistent with services_for()'s own
    ``(domain or "").upper()`` lookup."""
    text = sample_statement("azure", _rec(domain="sc"), SC_PART)
    assert "FIPS 140-2" in text


def test_fips_note_differs_per_platform() -> None:
    """Each platform names its own FIPS-validated module, not a generic string."""
    rec = _rec(domain="SC")
    aws_text = sample_statement("aws_govcloud", rec, SC_PART)
    azure_text = sample_statement("azure", rec, SC_PART)
    m365_text = sample_statement("m365", rec, SC_PART)
    assert "AWS KMS" in aws_text
    assert "Azure Key Vault" in azure_text
    assert "Microsoft" in m365_text
    assert aws_text != azure_text != m365_text
