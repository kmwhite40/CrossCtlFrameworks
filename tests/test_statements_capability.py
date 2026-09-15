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


def test_no_capability_leaves_no_implementation_sentence() -> None:
    """Absolute, not relative -- the byte-identical test above cannot see this.

    With the empty-clause guard gone, ``" Implementation: ."`` is appended to
    *both* sides of every comparison in this file, so every equality assertion
    still holds while the prose is broken. Only an absolute assertion about
    the rendered text catches it.
    """
    for responsibility in ("customer", "shared", "inherited", "not_applicable"):
        for style in STYLES:
            text, _ = _c(responsibility=responsibility, style=style)
            assert "Implementation: ." not in text, f"{responsibility}/{style}"
            assert "implementation: ." not in text, f"{responsibility}/{style}"


def test_statements_render_in_sorted_order() -> None:
    """Sorted, not merely deduplicated.

    Set iteration order is hash-randomized per process, so dropping ``sorted``
    would still satisfy the input-order test above -- two calls with the same
    statements agree with each other while the prose changes between runs.
    Asserting the order itself is what pins it.
    """
    text, _ = _c(
        capability_statements=(
            "zulu", "mike", "alpha", "tango", "bravo", "kilo", "delta", "echo",
        )
    )
    assert (
        "Implementation: alpha; bravo; delta; echo; kilo; mike; tango; zulu." in text
    )


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


def test_a_statement_that_already_ends_in_a_period_does_not_double_it() -> None:
    """Authors write whole sentences, so most statements arrive punctuated.

    Found by rendering three real controls: every statement came out
    "...no legacy-auth exclusions.." -- the clause adds the sentence-ending
    period, so the statement must not bring its own.
    """
    text, _ = _c(capability_statements=("Conditional Access requires MFA.",))
    assert "Implementation: Conditional Access requires MFA." in text
    assert ".." not in text


def test_punctuated_statements_are_joined_without_stray_periods() -> None:
    text, _ = _c(capability_statements=("alpha mechanism.", "beta mechanism."))
    assert "Implementation: alpha mechanism; beta mechanism." in text
    assert ".." not in text


def test_the_residual_clause_is_punctuated_the_same_way() -> None:
    text, _ = _c(
        responsibility="inherited",
        source="vendor:AWS GovCloud",
        crm_ref="FedRAMP-1234",
        capability_statements=("residual hardening is applied.",),
    )
    assert "residual implementation: residual hardening is applied." in text
    assert ".." not in text


def test_the_same_statement_punctuated_and_not_is_one_statement() -> None:
    """Otherwise an author adding a period would render the sentence twice."""
    text, _ = _c(capability_statements=("alpha mechanism", "alpha mechanism."))
    assert "Implementation: alpha mechanism." in text
    assert text.count("alpha mechanism") == 1


# ── Exclusions ───────────────────────────────────────────────────────────────


def test_empty_and_whitespace_statements_are_dropped() -> None:
    """An empty clause would render "Implementation: ." ."""
    baseline, _ = _c()
    text, _ = _c(capability_statements=("", "   ", "\n"))
    assert text == baseline


def test_a_none_statement_is_dropped_not_crashed() -> None:
    """``Capability.statement`` is nullable, so None can reach a careless caller.

    Dropping it beats an AttributeError raised while rendering an
    authorization package.
    """
    baseline, _ = _c()
    text, _ = _c(capability_statements=(None,))  # type: ignore[arg-type]
    assert text == baseline


def test_a_statement_of_only_punctuation_is_dropped() -> None:
    """Normalization can empty a statement that was not empty on arrival.

    "." survives the incoming empty-string filter, then strips to nothing --
    so the filter has to be applied again after stripping, or the clause
    renders "Implementation: ." .
    """
    baseline, _ = _c()
    text, _ = _c(capability_statements=(".", "...", " . "))
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
