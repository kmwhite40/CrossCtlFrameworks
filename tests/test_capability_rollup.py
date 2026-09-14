"""Deterministic rollup of capability statuses into one derived control status."""

from __future__ import annotations

import pytest

from ccf.capability.rollup import roll_up


def test_all_implemented_is_implemented() -> None:
    assert roll_up(["implemented", "implemented"]) == "implemented"


def test_worst_of_wins() -> None:
    """Conservative by design: over-claiming control status is the dangerous direction."""
    assert roll_up(["implemented", "planned"]) == "partial"
    assert roll_up(["implemented", "not_implemented"]) == "partial"
    assert roll_up(["partial", "implemented"]) == "partial"


def test_all_not_implemented_stays_not_implemented() -> None:
    assert roll_up(["not_implemented", "not_implemented"]) == "not_implemented"


def test_inherited_counts_as_satisfied() -> None:
    assert roll_up(["inherited"]) == "inherited"
    assert roll_up(["implemented", "inherited"]) == "implemented"


def test_not_applicable_is_excluded() -> None:
    assert roll_up(["implemented", "not_applicable"]) == "implemented"


def test_no_contributors_yields_none() -> None:
    """None means 'write nothing', not a misleading not_implemented."""
    assert roll_up([]) is None
    assert roll_up(["not_applicable", "not_applicable"]) is None


def test_unknown_status_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown capability status"):
        roll_up(["definitely_not_a_status"])


def test_single_planned_is_planned() -> None:
    assert roll_up(["planned"]) == "planned"
