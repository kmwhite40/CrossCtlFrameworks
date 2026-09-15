"""Capability-authored text is appended as an implementation sentence."""

from __future__ import annotations

from ccf.ssp.statements import STYLES, compose

CAP = "Entra ID Conditional Access enforces MFA on all interactive sign-ins"


def _c(**kw):
    base = dict(
        control_id="IA-2",
        requirement="uniquely identify and authenticate users",
        responsibility="customer",
        source="platform:m365_gcc_high",
        environment="Microsoft 365 Government (GCC High)",
        services="Entra ID Conditional Access",
    )
    base.update(kw)
    return compose(**base)


# ── The safety property ──────────────────────────────────────────────────────


def test_no_capability_is_byte_identical_to_not_passing_the_parameter() -> None:
    """The property that makes touching the SSP generator safe."""
    for responsibility in ("customer", "shared", "inherited", "not_applicable"):
        for style in STYLES:
            without, nr_without = _c(responsibility=responsibility, style=style)
            with_empty, nr_with = _c(
                responsibility=responsibility, style=style, capability_statements=()
            )
            assert without == with_empty, f"{responsibility}/{style}"
            assert nr_without == nr_with, f"{responsibility}/{style}"


# ── Where the text goes, per branch ──────────────────────────────────────────


def test_customer_branch_appends_the_capability_implementation() -> None:
    text, _ = _c(responsibility="customer", capability_statements=(CAP,))
    # The framing sentence survives; the capability follows it.
    assert "by configuring Entra ID Conditional Access" in text
    assert f"Implementation: {CAP}." in text


def test_shared_branch_appends_the_capability_implementation() -> None:
    text, _ = _c(responsibility="shared", capability_statements=(CAP,))
    assert "shared responsibility" in text
    assert f"Implementation: {CAP}." in text


def test_inherited_branch_frames_the_capability_as_residual() -> None:
    text, _ = _c(
        responsibility="inherited",
        source="vendor:AWS GovCloud",
        crm_ref="FedRAMP-1234",
        capability_statements=(CAP,),
    )
    assert "inherited from AWS GovCloud" in text
    assert f"The organization's residual implementation: {CAP}." in text


def test_not_applicable_ignores_capability_text() -> None:
    """Nothing is implemented, so there is nothing to describe."""
    text, _ = _c(responsibility="not_applicable", capability_statements=(CAP,))
    assert CAP not in text


# ── Many capabilities, deterministically ─────────────────────────────────────


def test_multiple_capabilities_are_joined() -> None:
    text, _ = _c(capability_statements=("alpha mechanism", "beta mechanism"))
    assert "alpha mechanism" in text
    assert "beta mechanism" in text


def test_ordering_is_stable_regardless_of_input_order() -> None:
    """Regenerating an SSP must produce identical prose."""
    a, _ = _c(capability_statements=("alpha", "beta", "gamma"))
    b, _ = _c(capability_statements=("gamma", "alpha", "beta"))
    assert a == b


# ── Exclusions ───────────────────────────────────────────────────────────────


def test_empty_and_whitespace_statements_are_dropped() -> None:
    """An empty clause would render "Implementation: ." ."""
    baseline, _ = _c()
    text, _ = _c(capability_statements=("", "   ", "\n"))
    assert text == baseline


def test_a_usable_statement_among_empty_ones_still_renders() -> None:
    text, _ = _c(capability_statements=("", CAP, "  "))
    assert CAP in text


# ── needs_review is untouched ────────────────────────────────────────────────


def test_needs_review_is_identical_with_and_without_capabilities() -> None:
    """Relaxing the review posture is out of scope; prove it did not drift."""
    for responsibility in ("customer", "shared", "not_applicable"):
        _, without = _c(responsibility=responsibility)
        _, with_cap = _c(responsibility=responsibility, capability_statements=(CAP,))
        assert without == with_cap, responsibility


def test_inherited_without_crm_still_needs_review_with_a_capability() -> None:
    """FR-11 must survive: a capability statement is not a CRM reference."""
    _, needs_review = _c(
        responsibility="inherited",
        source="vendor:AWS GovCloud",
        crm_ref=None,
        capability_statements=(CAP,),
    )
    assert needs_review is True


# ── The tails still appear ───────────────────────────────────────────────────


def test_tails_survive_a_capability_statement() -> None:
    text, _ = _c(
        capability_statements=(CAP,),
        odp_values={"mfa_enforced": "required"},
        responsible_role="ISSO",
        frequency="annually",
        policy_ref="Access Control Policy",
    )
    assert CAP in text
    assert "mfa enforced: required" in text
    assert "ISSO" in text
    assert "annually" in text
    assert "Access Control Policy" in text
