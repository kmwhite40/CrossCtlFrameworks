# tests/test_accepted_weakness.py
"""CR26 Accepted Weakness: declared or elapsed.

The rule (Vulnerability Evaluation and Reporting) requires a provider to
categorize any vulnerability that "is not OR WILL NOT BE" fully mitigated or
remediated within 192 days of evaluation as an accepted vulnerability. Both
halves matter: "will not" is a forward-looking decision a provider can make on
day 3, which no elapsed-time arithmetic can represent.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta

from ccf.constants import POAM_ACTIVE_STATUSES
from ccf.patching.sla import ACCEPTED_WEAKNESS_DAYS, is_accepted_weakness

TODAY = date(2026, 9, 16)


@dataclass
class _Poam:
    """Only the fields the classification reads."""

    status: str = "open"
    identified_on: date | None = None
    closed_on: date | None = None


def _aged(days: int, **kw: object) -> _Poam:
    """A POA&M identified exactly ``days`` ago."""
    return _Poam(identified_on=TODAY - timedelta(days=days), **kw)  # type: ignore[arg-type]


def test_the_threshold_is_the_rule_s_number() -> None:
    assert ACCEPTED_WEAKNESS_DAYS == 192


def test_declared_is_accepted_at_any_age() -> None:
    """The "will not be remediated" half: a provider may accept on day 3."""
    assert is_accepted_weakness(_aged(3, status="risk_accepted"), today=TODAY) is True


def test_elapsed_past_the_threshold_is_accepted() -> None:
    assert is_accepted_weakness(_aged(258, status="open"), today=TODAY) is True


def test_the_boundary_is_inclusive_like_classify() -> None:
    """192 means 192 -- sla.classify's stated convention, reused verbatim."""
    assert is_accepted_weakness(_aged(ACCEPTED_WEAKNESS_DAYS), today=TODAY) is False
    assert is_accepted_weakness(_aged(ACCEPTED_WEAKNESS_DAYS + 1), today=TODAY) is True


def test_in_progress_counts_as_backlog() -> None:
    """Work underway past the window is still an accepted weakness -- the rule
    is about elapsed time, not effort."""
    assert is_accepted_weakness(_aged(258, status="in_progress"), today=TODAY) is True


def test_a_closed_weakness_is_not_accepted() -> None:
    done = _aged(600, status="completed", closed_on=date(2025, 3, 1))
    assert is_accepted_weakness(done, today=TODAY) is False


def test_a_stale_closed_on_does_not_make_a_reopened_weakness_look_resolved() -> None:
    """Status is consulted before any closure date.

    Shipping this backwards was a Critical in the flaw-remediation work: a
    reopened POA&M read as closed_on_time and counted toward compliance. Here
    the row is open and 258 days old, so it IS accepted -- by the elapsed rule,
    never dismissed because a stale closed_on made it look resolved.
    """
    reopened = _aged(258, status="open", closed_on=TODAY - timedelta(days=254))
    assert is_accepted_weakness(reopened, today=TODAY) is True


def test_no_identified_on_is_never_accepted_by_elapsed_time() -> None:
    """Never invent a date: unknown age cannot satisfy a 192-day rule."""
    assert is_accepted_weakness(_Poam(status="open"), today=TODAY) is False


def test_but_an_undated_declared_weakness_is_still_accepted() -> None:
    """The declared half does not depend on a date at all."""
    assert is_accepted_weakness(_Poam(status="risk_accepted"), today=TODAY) is True


def test_the_two_halves_are_disjoint() -> None:
    """risk_accepted is excluded from POAM_ACTIVE_STATUSES by design, so an old
    accepted row is reached by the declared half alone."""
    assert "risk_accepted" not in POAM_ACTIVE_STATUSES
    assert is_accepted_weakness(_aged(600, status="risk_accepted"), today=TODAY) is True
