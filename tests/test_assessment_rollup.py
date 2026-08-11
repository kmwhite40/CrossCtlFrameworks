"""Rollup policy — application code, not model output, decides the control finding."""

from __future__ import annotations

import pytest

from ccf.assessment.engine.rollup import roll_up
from ccf.models_assessment_engine import CONTROL_PROPOSAL_FINDINGS


def test_all_satisfied_proposes_satisfied() -> None:
    assert roll_up(["satisfied", "satisfied"]).finding == "satisfied"


def test_any_not_satisfied_proposes_other_than_satisfied() -> None:
    """800-53A is strict: a control is satisfied only when every objective is."""
    assert roll_up(["satisfied", "not_satisfied", "satisfied"]).finding == "other_than_satisfied"


def test_not_satisfied_outranks_insufficient() -> None:
    """A demonstrated failure is a stronger signal than an unanswered question."""
    result = roll_up(["not_satisfied", "insufficient_evidence"])
    assert result.finding == "other_than_satisfied"


def test_insufficient_without_failure_proposes_insufficient() -> None:
    assert roll_up(["satisfied", "insufficient_evidence"]).finding == "insufficient_evidence"


def test_not_applicable_objectives_are_ignored_when_others_are_satisfied() -> None:
    assert roll_up(["satisfied", "not_applicable"]).finding == "satisfied"


def test_all_not_applicable_proposes_not_applicable() -> None:
    assert roll_up(["not_applicable", "not_applicable"]).finding == "not_applicable"


def test_no_objectives_proposes_insufficient_not_satisfied() -> None:
    """A control with no objectives must never be proposed as passing."""
    assert roll_up([]).finding == "insufficient_evidence"


def test_every_outcome_is_in_the_declared_vocabulary() -> None:
    for verdicts in ([], ["satisfied"], ["not_satisfied"], ["not_applicable"],
                     ["insufficient_evidence"]):
        assert roll_up(verdicts).finding in CONTROL_PROPOSAL_FINDINGS


def test_rationale_names_the_deciding_counts() -> None:
    rationale = roll_up(["satisfied", "not_satisfied", "insufficient_evidence"]).rationale
    assert "not_satisfied" in rationale


def test_an_unknown_verdict_raises_rather_than_being_ignored() -> None:
    """Silently dropping an unrecognised verdict could turn a failure into a pass."""
    with pytest.raises(ValueError, match="unknown objective verdict"):
        roll_up(["satisfied", "probably_fine"])


# --- `failed` -- unevaluated objectives (CRITICAL 1) --------------------------


def test_any_failed_objective_forces_insufficient_evidence_even_if_rest_are_satisfied() -> None:
    """The bug this closes: a control where every *evaluated* objective looked
    satisfied but most objectives never evaluated at all must never roll up
    satisfied -- 1 real verdict out of 25 objectives is not "satisfied",
    regardless of what that one verdict was.
    """
    result = roll_up(["satisfied"], failed=24)
    assert result.finding == "insufficient_evidence"


def test_a_failed_objective_forces_insufficient_evidence_over_a_demonstrated_failure() -> None:
    """Even when the evaluated objectives already show a failure, a control
    with any unevaluated objective is not proposed at all -- the engine does
    not know what the missing objective would have shown, so it cannot
    responsibly land on other_than_satisfied either.
    """
    result = roll_up(["not_satisfied"], failed=1)
    assert result.finding == "insufficient_evidence"


def test_no_failures_is_unaffected_by_the_new_parameter() -> None:
    """failed=0 (the default) must reproduce the pre-existing policy exactly."""
    assert roll_up(["satisfied", "satisfied"], failed=0).finding == "satisfied"
    assert roll_up(["satisfied", "satisfied"]).finding == "satisfied"


def test_rationale_states_coverage_explicitly_when_objectives_failed() -> None:
    """The rationale must be readable by an assessor without cross-referencing
    objectives_total/objectives_evaluated columns by hand.
    """
    rationale = roll_up(["satisfied"], failed=24).rationale
    assert "1 of 25 objectives evaluated, 24 failed" in rationale


def test_negative_failed_count_raises() -> None:
    with pytest.raises(ValueError, match="failed must be >= 0"):
        roll_up(["satisfied"], failed=-1)
