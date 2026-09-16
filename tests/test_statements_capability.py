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
                responsibility=responsibility,
                style=style,
                capability_statements=(),
                partial_capability_statements=(),
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


def test_statements_render_in_sorted_order_by_capability_key() -> None:
    """Sorted by capability key, not by statement text.

    Keys run alphabetically (cap-a < cap-b < cap-c) while their statement
    text runs the opposite way, so a text-based sort and a key-based sort
    disagree about the order -- only a key-based sort produces this one. A
    one-word edit to a capability's statement must never reorder the clause
    on every other control that capability shares with others.
    """
    text, _ = _c(
        capability_statements=(
            ("cap-a", "zulu"),
            ("cap-b", "mike"),
            ("cap-c", "alpha"),
        )
    )
    assert "Implementation: zulu; mike; alpha." in text


def test_input_order_does_not_affect_rendered_order() -> None:
    """Same (key, statement) pairs, shuffled call-argument order, identical
    output -- the resolution path may hand these in any order (e.g. however
    the DB returns rows) and the rendered clause must not depend on it."""
    pairs = (("cap-a", "alpha"), ("cap-b", "beta"), ("cap-c", "gamma"))
    a, _ = _c(capability_statements=pairs)
    b, _ = _c(capability_statements=tuple(reversed(pairs)))
    assert a == b


# ── Where the text goes, per branch ──────────────────────────────────────────


def test_customer_branch_appends_the_capability_implementation() -> None:
    text, _ = _c(responsibility="customer", capability_statements=(("cap-mfa", CAP),))
    # The framing sentence survives; the capability follows it.
    assert "by configuring Entra ID Conditional Access" in text
    assert f"Implementation: {CAP}." in text


def test_shared_branch_appends_the_capability_implementation() -> None:
    text, _ = _c(responsibility="shared", capability_statements=(("cap-mfa", CAP),))
    assert "shared responsibility" in text
    assert f"Implementation: {CAP}." in text


def test_inherited_branch_frames_the_capability_as_residual() -> None:
    text, _ = _c(
        responsibility="inherited",
        source="vendor:AWS GovCloud",
        crm_ref="FedRAMP-1234",
        capability_statements=(("cap-mfa", CAP),),
    )
    assert "inherited from AWS GovCloud" in text
    assert f"The organization's residual implementation: {CAP}." in text


def test_not_applicable_ignores_capability_text() -> None:
    """Nothing is implemented, so there is nothing to describe."""
    text, _ = _c(responsibility="not_applicable", capability_statements=(("cap-mfa", CAP),))
    assert CAP not in text


# ── Many capabilities, deterministically ─────────────────────────────────────


def test_multiple_capabilities_are_joined() -> None:
    text, _ = _c(
        capability_statements=(
            ("cap-a", "alpha mechanism"),
            ("cap-b", "beta mechanism"),
        )
    )
    assert "alpha mechanism" in text
    assert "beta mechanism" in text


def test_a_statement_that_already_ends_in_a_period_does_not_double_it() -> None:
    """Authors write whole sentences, so most statements arrive punctuated.

    Found by rendering three real controls: every statement came out
    "...no legacy-auth exclusions.." -- the clause adds the sentence-ending
    period, so the statement must not bring its own.
    """
    text, _ = _c(capability_statements=(("cap-mfa", "Conditional Access requires MFA."),))
    assert "Implementation: Conditional Access requires MFA." in text
    assert ".." not in text


def test_punctuated_statements_are_joined_without_stray_periods() -> None:
    text, _ = _c(
        capability_statements=(
            ("cap-a", "alpha mechanism."),
            ("cap-b", "beta mechanism."),
        )
    )
    assert "Implementation: alpha mechanism; beta mechanism." in text
    assert ".." not in text


def test_the_residual_clause_is_punctuated_the_same_way() -> None:
    text, _ = _c(
        responsibility="inherited",
        source="vendor:AWS GovCloud",
        crm_ref="FedRAMP-1234",
        capability_statements=(("cap-mfa", "residual hardening is applied."),),
    )
    assert "residual implementation: residual hardening is applied." in text
    assert ".." not in text


def test_the_same_statement_punctuated_and_not_is_one_statement() -> None:
    """Otherwise an author adding a period would render the sentence twice.

    Two distinct capabilities (different keys) whose statements normalize to
    the same text -- text-level de-duplication is independent of key-level
    de-duplication (the DB query already collapses one capability bound
    through two components; this is the separate case of two different
    capabilities that happen to say the same thing)."""
    text, _ = _c(
        capability_statements=(
            ("cap-a", "alpha mechanism"),
            ("cap-b", "alpha mechanism."),
        )
    )
    assert "Implementation: alpha mechanism." in text
    assert text.count("alpha mechanism") == 1


# ── Punctuation beyond a bare trailing period ────────────────────────────────


def test_a_trailing_question_mark_does_not_double_punctuate() -> None:
    text, _ = _c(capability_statements=(("cap-q", "Is legacy auth blocked?"),))
    assert "Implementation: Is legacy auth blocked." in text
    assert "?." not in text


def test_a_trailing_exclamation_does_not_double_punctuate() -> None:
    text, _ = _c(capability_statements=(("cap-e", "MFA is strictly enforced!"),))
    assert "Implementation: MFA is strictly enforced." in text
    assert "!." not in text


def test_a_trailing_ellipsis_does_not_double_punctuate() -> None:
    text, _ = _c(capability_statements=(("cap-el", "Rollout is nearly complete…"),))
    assert "Implementation: Rollout is nearly complete." in text
    assert "….." not in text
    assert "…." not in text


def test_a_multi_sentence_statement_is_not_semicolon_spliced_with_others() -> None:
    """Real bug: folding a whole second sentence into a semicolon list reads
    as a list item with an embedded sentence break."""
    text, _ = _c(
        capability_statements=(
            ("cap-a", "Disk encryption is on"),
            ("cap-b", "MFA is enforced. Legacy auth is blocked."),
        )
    )
    assert (
        "Implementation: Disk encryption is on. MFA is enforced. Legacy auth is blocked."
        in text
    )
    assert "on; MFA" not in text


def test_multiple_single_sentence_statements_still_use_a_semicolon_list() -> None:
    """The sentence-per-statement rendering only kicks in when it's needed --
    plain single-sentence statements still read as one semicolon-joined
    sentence, unchanged from before."""
    text, _ = _c(
        capability_statements=(
            ("cap-a", "Disk encryption is on"),
            ("cap-b", "MFA is enforced"),
        )
    )
    assert "Implementation: Disk encryption is on; MFA is enforced." in text


# ── Exclusions ───────────────────────────────────────────────────────────────


def test_empty_and_whitespace_statements_are_dropped() -> None:
    """An empty clause would render "Implementation: ." ."""
    baseline, _ = _c()
    text, _ = _c(
        capability_statements=(("cap-a", ""), ("cap-b", "   "), ("cap-c", "\n"))
    )
    assert text == baseline


def test_a_none_statement_is_dropped_not_crashed() -> None:
    """``Capability.statement`` is nullable, so None can reach a careless caller.

    Dropping it beats an AttributeError raised while rendering an
    authorization package.
    """
    baseline, _ = _c()
    text, _ = _c(capability_statements=(("cap-a", None),))  # type: ignore[arg-type]
    assert text == baseline


def test_a_statement_of_only_punctuation_is_dropped() -> None:
    """Normalization can empty a statement that was not empty on arrival.

    "." survives the incoming empty-string filter, then strips to nothing --
    so the filter has to be applied again after stripping, or the clause
    renders "Implementation: ." .
    """
    baseline, _ = _c()
    text, _ = _c(
        capability_statements=(("cap-a", "."), ("cap-b", "..."), ("cap-c", " . "))
    )
    assert text == baseline


def test_a_usable_statement_among_empty_ones_still_renders() -> None:
    text, _ = _c(
        capability_statements=(("cap-a", ""), ("cap-b", CAP), ("cap-c", "  "))
    )
    assert CAP in text


# ── Partial implementations render distinctly ───────────────────────────────


def test_partial_capability_renders_under_its_own_lead() -> None:
    text, _ = _c(
        partial_capability_statements=(
            ("cap-p", "Backup MFA rollout covers half of privileged roles"),
        )
    )
    assert (
        "Partial implementation: Backup MFA rollout covers half of privileged roles."
        in text
    )
    assert "Implementation:" not in text


def test_full_and_partial_capabilities_render_as_separate_clauses() -> None:
    text, _ = _c(
        capability_statements=(("cap-a", "alpha mechanism"),),
        partial_capability_statements=(("cap-b", "beta rollout is half done"),),
    )
    assert "Implementation: alpha mechanism." in text
    assert "Partial implementation: beta rollout is half done." in text


def test_inherited_partial_capability_uses_partial_residual_framing() -> None:
    text, _ = _c(
        responsibility="inherited",
        source="vendor:AWS GovCloud",
        crm_ref="FedRAMP-1234",
        partial_capability_statements=(("cap-p", "residual work is partly done"),),
    )
    assert (
        "The organization's partial residual implementation: residual work is partly done."
        in text
    )


# ── needs_review is untouched ────────────────────────────────────────────────


def test_needs_review_is_identical_with_and_without_capabilities() -> None:
    """Relaxing the review posture is out of scope; prove it did not drift."""
    for responsibility in ("customer", "shared", "not_applicable"):
        _, without = _c(responsibility=responsibility)
        _, with_cap = _c(
            responsibility=responsibility, capability_statements=(("cap-mfa", CAP),)
        )
        assert without == with_cap, responsibility
    # ``inherited`` is the one branch where ``needs_review`` is actually
    # data-dependent (True/False on whether a CRM reference is on file)
    # rather than a fixed constant per branch -- the loop above alone would
    # not catch a capability statement leaking into that computation, since
    # customer/shared/not_applicable never vary it regardless.
    for crm_ref in (None, "FedRAMP-1234"):
        kwargs = dict(responsibility="inherited", source="vendor:AWS GovCloud", crm_ref=crm_ref)
        _, without = _c(**kwargs)
        _, with_cap = _c(**kwargs, capability_statements=(("cap-mfa", CAP),))
        assert without == with_cap, f"inherited/crm_ref={crm_ref!r}"


def test_inherited_without_crm_still_needs_review_with_a_capability() -> None:
    """FR-11 must survive: a capability statement is not a CRM reference."""
    _, needs_review = _c(
        responsibility="inherited",
        source="vendor:AWS GovCloud",
        crm_ref=None,
        capability_statements=(("cap-mfa", CAP),),
    )
    assert needs_review is True


# ── The tails still appear ───────────────────────────────────────────────────


def test_tails_survive_a_capability_statement() -> None:
    text, _ = _c(
        capability_statements=(("cap-mfa", CAP),),
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
