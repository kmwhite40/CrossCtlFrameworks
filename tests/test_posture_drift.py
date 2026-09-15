"""Transition classification -- including the two kinds nothing notices today."""

from __future__ import annotations

from ccf.posture.drift import TRANSITION_KINDS, diff_resources
from ccf.posture.types import ResourceFinding


def _f(resource_id: str, verdict: str, observed: str = "observed") -> ResourceFinding:
    return ResourceFinding(
        resource_id=resource_id, resource_type="entra_user", verdict=verdict, observed=observed
    )


def _kinds(before: list, after: list) -> dict[str, str]:
    return {t.resource_id: t.kind for t in diff_resources(before, after)}


# ── the five kinds ───────────────────────────────────────────────────────────


def test_a_pass_to_fail_is_a_regression() -> None:
    assert _kinds([_f("r", "pass")], [_f("r", "fail")]) == {"r": "regressed"}


def test_a_fail_to_pass_is_a_recovery() -> None:
    assert _kinds([_f("r", "fail")], [_f("r", "pass")]) == {"r": "recovered"}


def test_a_new_resource_is_an_appearance_not_a_regression() -> None:
    """When a weakness began is a different fact from that it exists."""
    assert _kinds([], [_f("r", "fail")]) == {"r": "appeared"}


def test_a_vanished_resource_is_a_disappearance() -> None:
    """Nothing in the platform notices this today. A truncated collection
    currently looks like an improvement, because the failing row simply stops
    being returned."""
    assert _kinds([_f("r", "fail")], []) == {"r": "disappeared"}


def test_the_same_verdict_with_new_observed_text_is_changed() -> None:
    """A resource failing for a new reason is still news."""
    before = [_f("r", "fail", "no MFA method registered")]
    after = [_f("r", "fail", "legacy authentication permitted")]
    assert _kinds(before, after) == {"r": "changed"}


def test_an_unchanged_resource_produces_no_transition() -> None:
    assert diff_resources([_f("r", "pass")], [_f("r", "pass")]) == []


# ── the classifications that must be explicit, not incidental ────────────────


def test_fail_to_not_applicable_is_not_a_recovery() -> None:
    """It would assert a weakness cleared that was never re-observed."""
    kinds = _kinds([_f("r", "fail")], [_f("r", "not_applicable")])
    assert kinds["r"] != "recovered"
    assert kinds["r"] == "changed"


def test_not_applicable_to_fail_is_a_regression() -> None:
    """Chosen deliberately: the resource needs cover now and did not before."""
    assert _kinds([_f("r", "not_applicable")], [_f("r", "fail")]) == {"r": "regressed"}


def test_warn_to_fail_is_a_regression_not_unchanged() -> None:
    """Both need cover, but the posture got worse."""
    assert _kinds([_f("r", "warn")], [_f("r", "fail")]) == {"r": "regressed"}


def test_fail_to_warn_is_reported_not_silent() -> None:
    kinds = _kinds([_f("r", "fail")], [_f("r", "warn")])
    assert kinds["r"] == "recovered"


def test_manual_review_to_pass_is_a_recovery() -> None:
    assert _kinds([_f("r", "manual_review_required")], [_f("r", "pass")]) == {"r": "recovered"}


def test_pass_to_not_applicable_is_reported_as_changed() -> None:
    """Neither better nor worse, but the resource left scope -- worth seeing."""
    assert _kinds([_f("r", "pass")], [_f("r", "not_applicable")]) == {"r": "changed"}


# ── shape and determinism ────────────────────────────────────────────────────


def test_transitions_carry_both_verdicts_and_the_newer_observation() -> None:
    (t,) = diff_resources([_f("r", "pass", "was fine")], [_f("r", "fail", "now broken")])
    assert t.before == "pass"
    assert t.after == "fail"
    assert t.observed == "now broken"


def test_an_appearance_has_no_before_and_a_disappearance_no_after() -> None:
    (appeared,) = diff_resources([], [_f("r", "fail")])
    assert appeared.before is None and appeared.after == "fail"
    (gone,) = diff_resources([_f("r", "fail")], [])
    assert gone.before == "fail" and gone.after is None
    assert gone.observed is None, "there is no newer observation of an absent resource"


def test_transitions_are_sorted_by_resource_id() -> None:
    """Regenerating a drift report must not reorder it.

    Eight resources, not three: set iteration order is hash-dependent, so with
    three there is a one-in-six chance the unsorted order is coincidentally
    alphabetical -- which is exactly how this escaped mutation testing on the
    first pass.
    """
    names = ["zulu", "alpha", "mike", "tango", "bravo", "kilo", "delta", "echo"]
    before = [_f(n, "pass") for n in names]
    after = [_f(n, "fail") for n in names]
    assert [t.resource_id for t in diff_resources(before, after)] == sorted(names)


def test_both_sides_empty_yields_nothing() -> None:
    assert diff_resources([], []) == []


def test_every_produced_kind_is_declared() -> None:
    """A kind absent from TRANSITION_KINDS is one no consumer can interpret."""
    cases = [
        ([_f("a", "pass")], [_f("a", "fail")]),
        ([_f("b", "fail")], [_f("b", "pass")]),
        ([], [_f("c", "fail")]),
        ([_f("d", "fail")], []),
        ([_f("e", "fail", "x")], [_f("e", "fail", "y")]),
    ]
    produced = {t.kind for before, after in cases for t in diff_resources(before, after)}
    assert produced <= set(TRANSITION_KINDS)
    assert produced == set(TRANSITION_KINDS)


def test_a_duplicated_resource_id_takes_the_last_occurrence() -> None:
    """A provider returning a resource twice must not produce two transitions
    whose order decides the verdict."""
    before = [_f("r", "pass")]
    after = [_f("r", "pass"), _f("r", "fail")]
    assert _kinds(before, after) == {"r": "regressed"}
