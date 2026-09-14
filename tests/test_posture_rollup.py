"""Rolling per-resource verdicts into one check verdict."""

from __future__ import annotations

import pytest

from ccf.fedramp20x.validation import _VERDICT_RANK, VERDICT_RANK
from ccf.posture.rollup import roll_up_findings


def test_all_pass_is_pass() -> None:
    assert roll_up_findings(["pass", "pass", "pass"]) == "pass"


def test_one_failure_fails_the_check() -> None:
    """3 failing of 47 is a failing check."""
    assert roll_up_findings(["pass"] * 44 + ["fail"] * 3) == "fail"


def test_warn_among_passes_warns() -> None:
    assert roll_up_findings(["pass", "warn", "pass"]) == "warn"


def test_fail_outranks_warn() -> None:
    assert roll_up_findings(["warn", "fail"]) == "fail"


def test_not_applicable_is_excluded_not_ranked() -> None:
    """The trap: not_applicable ranks 0, BELOW fail at 1, because
    VERDICT_RANK exists for any_of's `max`. A naive `min` would report
    not_applicable for a failing check."""
    assert roll_up_findings(["fail", "not_applicable"]) == "fail"
    assert roll_up_findings(["pass", "not_applicable"]) == "pass"
    assert roll_up_findings(["warn", "not_tested"]) == "warn"


def test_no_resources_in_scope_is_not_applicable() -> None:
    """Zero resources is not a passing check."""
    assert roll_up_findings([]) == "not_applicable"
    assert roll_up_findings(["not_applicable", "not_applicable"]) == "not_applicable"
    assert roll_up_findings(["not_tested"]) == "not_applicable"


def test_manual_review_required_is_ranked() -> None:
    assert roll_up_findings(["pass", "manual_review_required"]) == "manual_review_required"
    assert roll_up_findings(["fail", "manual_review_required"]) == "fail"


def test_unknown_verdict_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown verdict"):
        roll_up_findings(["definitely_not_a_verdict"])


def test_rank_is_shared_with_the_20x_engine() -> None:
    """One ranking, not two."""
    assert VERDICT_RANK is _VERDICT_RANK
    assert VERDICT_RANK["fail"] > VERDICT_RANK["not_applicable"]
