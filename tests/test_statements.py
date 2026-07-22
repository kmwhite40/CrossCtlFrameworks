"""Unit tests for automatic implementation-statement composition."""

from __future__ import annotations

import pytest

from ccf.ssp.constants import GENERIC_ROLE_FLAG
from ccf.ssp.statements import STYLES, compose


def _c(**kw):
    base = dict(
        control_id="AC.L2-3.1.1",
        requirement="limit system access to authorized users",
        responsibility="customer",
        source="platform:m365_gcc_high",
        environment="Microsoft 365 Government (GCC High)",
        services="Entra ID Conditional Access",
    )
    base.update(kw)
    return compose(**base)


# --- FR-11: inherited statements need a real CRM/leveraged-authorization link ---


def test_inherited_without_crm_ref_needs_review_and_is_draft() -> None:
    """No leveraged-authorization/CRM reference supplied -> must NOT be
    auto-accepted; must read as a draft needing human review."""
    text, review = _c(responsibility="inherited", source="vendor:Acme FedRAMP SaaS")
    assert review is True
    assert text.startswith("[DRAFT]")
    assert "inherited from Acme FedRAMP SaaS" in text
    # Must not assert evidence is retained when nothing is actually linked.
    assert "retained as evidence" not in text
    assert "no leveraged-authorization" in text.lower() or "no crm" in text.lower()


def test_inherited_without_crm_ref_carries_customer_responsibility_line() -> None:
    text, _review = _c(responsibility="inherited", source="vendor:Acme FedRAMP SaaS")
    assert "customer responsibility" in text.lower()


def test_inherited_with_crm_ref_is_accepted_and_names_the_reference() -> None:
    """A real leveraged-authorization / CRM reference lets the statement be
    accepted without human review, and the reference itself is named."""
    text, review = _c(
        responsibility="inherited",
        source="vendor:Acme FedRAMP SaaS",
        crm_ref="Acme CRM v3.2 (2026-01-15)",
    )
    assert review is False
    assert not text.startswith("[DRAFT]")
    assert "Acme CRM v3.2 (2026-01-15)" in text
    assert "retained as evidence" in text
    # Even a fully-inherited, linked control still carries a customer-
    # responsibility line for the residual/hybrid portion.
    assert "customer responsibility" in text.lower()


@pytest.mark.parametrize("style", STYLES)
def test_inherited_names_who_and_evidence_in_every_style(style: str) -> None:
    text, _review = _c(responsibility="inherited", source="vendor:Acme FedRAMP SaaS", style=style)
    assert "responsible role" in text.lower()
    assert "evidence" in text.lower()


# --- FR-03: role/frequency/evidence must appear in every style, not just "detailed" ---


@pytest.mark.parametrize("style", STYLES)
@pytest.mark.parametrize("responsibility", ["customer", "shared"])
def test_who_frequency_evidence_present_in_every_style(style: str, responsibility: str) -> None:
    text, _review = _c(
        responsibility=responsibility,
        responsible_role="Jane Doe (System Owner)",
        frequency="continuously, reviewed quarterly",
        style=style,
    )
    assert "Jane Doe (System Owner)" in text
    assert "continuously, reviewed quarterly" in text
    assert "evidence" in text.lower()


def test_frequency_defaults_to_a_flagged_placeholder_when_not_supplied() -> None:
    """No fabricated cadence — an unresolved frequency renders using the same
    bracket convention ssp/completeness.py already treats as a draft
    placeholder, so it can't silently pass as filled in."""
    text, _review = _c(responsibility="customer")
    assert "[ORGANIZATION-DEFINED:" in text


def test_policy_ref_referenced_when_supplied() -> None:
    text, _review = _c(responsibility="customer", policy_ref="Access Control Policy v4")
    assert "Access Control Policy v4" in text


def test_no_policy_clause_when_not_supplied() -> None:
    text, _review = _c(responsibility="customer")
    assert "governing policy" not in text.lower()


# --- FR-13: responsible role prefers a named role, falls back to domain label ---


def test_named_responsible_role_is_used_verbatim() -> None:
    text, _review = _c(responsibility="customer", responsible_role="Jane Doe (System Owner)")
    assert "Jane Doe (System Owner)" in text
    assert "Lead / System Owner" not in text  # not the generic fallback


def test_falls_back_to_generic_domain_role_and_flags_it() -> None:
    """No named role supplied -> falls back to the domain label, but the
    fallback is flagged so it can't silently satisfy a named-responsible-
    party completeness gate (see ssp/constants.py GENERIC_ROLE_FLAG)."""
    text, _review = _c(responsibility="customer", control_id="AC.L2-3.1.1")
    assert "Access Control Lead / System Owner" in text
    assert GENERIC_ROLE_FLAG in text


# --- Existing behavior preserved ---


def test_not_applicable() -> None:
    text, review = _c(responsibility="not_applicable")
    assert "not applicable" in text.lower()
    assert review is False


def test_odp_and_captured_params_folded_in() -> None:
    text, _ = _c(
        odp_values={"inactivity_period": "15 minutes"},
        captured=[
            {"odp_key": "audit_retention_period", "value": "90 days", "connector": "aws_govcloud"}
        ],
    )
    assert "15 minutes" in text
    assert "captured from aws_govcloud" in text


def test_concise_style_drops_params_and_shortens() -> None:
    text, _ = _c(style="concise", odp_values={"x": "y"})
    assert "Organization-defined parameters" not in text
    assert "configures" in text.lower()


def test_mark_draft_false_omits_prefix() -> None:
    text, _ = _c(responsibility="customer", mark_draft=False)
    assert not text.startswith("[DRAFT]")
