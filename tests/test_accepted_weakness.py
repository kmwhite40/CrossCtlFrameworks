# tests/test_accepted_weakness.py
"""CR26 Accepted Weakness: declared, elapsed -- or not measurable at all.

The rule (Vulnerability Evaluation and Reporting) requires a provider to
categorize any vulnerability that "is not OR WILL NOT BE" fully mitigated or
remediated within 192 days of evaluation as an accepted vulnerability. Both
halves matter: "will not" is a forward-looking decision a provider can make on
day 3, which no elapsed-time arithmetic can represent.

A third answer matters too. Under a rule obliging a provider to *report* its
accepted weaknesses, "not accepted" is the favourable answer, so a row whose age
cannot be measured must say ``unknown`` rather than claim the favourable one --
the same doctrine ``sla.py``'s header states for its ``unknown`` bucket.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta

from ccf.constants import POAM_ACTIVE_STATUSES
from ccf.patching.sla import (
    ACCEPTED_WEAKNESS_DAYS,
    ACCEPTED_WEAKNESS_STATES,
    accepted_weakness_state,
    classify,
)

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


def test_the_state_vocabulary_is_closed_and_has_room_for_unknown() -> None:
    """A projection that cannot say "unknown" has to call an unmeasurable row
    something it is not, and the favourable answer is the wrong default here."""
    assert ACCEPTED_WEAKNESS_STATES == ("accepted", "not_accepted", "unknown")


def test_declared_is_accepted_at_any_age() -> None:
    """The "will not be remediated" half: a provider may accept on day 3."""
    assert (
        accepted_weakness_state(_aged(3, status="risk_accepted"), today=TODAY)
        == "accepted"
    )


def test_elapsed_past_the_threshold_is_accepted() -> None:
    assert accepted_weakness_state(_aged(258, status="open"), today=TODAY) == "accepted"


def test_the_boundary_is_inclusive_like_classify() -> None:
    """192 means 192 -- sla.classify's stated convention, reused verbatim."""
    assert (
        accepted_weakness_state(_aged(ACCEPTED_WEAKNESS_DAYS), today=TODAY)
        == "not_accepted"
    )
    assert (
        accepted_weakness_state(_aged(ACCEPTED_WEAKNESS_DAYS + 1), today=TODAY)
        == "accepted"
    )


def test_in_progress_counts_as_backlog() -> None:
    """Work underway past the window is still an accepted weakness -- the rule
    is about elapsed time, not effort."""
    assert (
        accepted_weakness_state(_aged(258, status="in_progress"), today=TODAY)
        == "accepted"
    )


def test_a_closed_weakness_is_not_accepted() -> None:
    done = _aged(600, status="completed", closed_on=date(2025, 3, 1))
    assert accepted_weakness_state(done, today=TODAY) == "not_accepted"


def test_a_reopened_weakness_with_a_stale_closed_on_is_unknown() -> None:
    """Status is consulted before any closure date, and the answer is neither.

    A row whose status is open but which still carries the ``closed_on`` a
    previous closure left behind is neither honestly closed nor cleanly open.
    Shipping this backwards was a Critical in the flaw-remediation work: a
    reopened POA&M read as closed_on_time and counted toward compliance. It is
    not dismissed as resolved -- and it is not asserted to be accepted either,
    because the record does not support either claim. ``sla.classify`` says
    ``unknown`` for the same row; the spec's scenario table calls it "not
    accepted, not resolved".
    """
    reopened = _aged(258, status="open", closed_on=TODAY - timedelta(days=254))
    assert accepted_weakness_state(reopened, today=TODAY) == "unknown"


def test_a_closure_that_predates_identification_is_unknown() -> None:
    """Negative latency is corrupt data, not a clean close -- ``_latency``
    already refuses it, and this must not read it as "not accepted"."""
    backwards = _Poam(
        status="completed",
        identified_on=TODAY - timedelta(days=100),
        closed_on=TODAY - timedelta(days=200),
    )
    assert accepted_weakness_state(backwards, today=TODAY) == "unknown"


def test_a_closed_status_with_no_closure_date_is_unknown() -> None:
    stale = _aged(600, status="completed")
    assert accepted_weakness_state(stale, today=TODAY) == "unknown"


def test_an_undated_active_weakness_is_unknown_not_a_clean_bill() -> None:
    """Never invent a date -- and never hand back the favourable answer for a
    row nobody can measure. An undated three-year-old open weakness reporting
    "not accepted" would be poor record-keeping improving the number, the exact
    inversion ``sla.py``'s header refuses.
    """
    assert accepted_weakness_state(_Poam(status="open"), today=TODAY) == "unknown"


def test_but_an_undated_declared_weakness_is_still_accepted() -> None:
    """The declared half does not depend on a date at all."""
    assert (
        accepted_weakness_state(_Poam(status="risk_accepted"), today=TODAY)
        == "accepted"
    )


def test_the_two_halves_are_disjoint() -> None:
    """risk_accepted is excluded from POAM_ACTIVE_STATUSES by design, so an old
    accepted row is reached by the declared half alone."""
    assert "risk_accepted" not in POAM_ACTIVE_STATUSES
    assert (
        accepted_weakness_state(_aged(600, status="risk_accepted"), today=TODAY)
        == "accepted"
    )


# --------------------------------------------------------------------------
# The two functions that decide what risk_accepted means, walked over one table
# --------------------------------------------------------------------------

#: One row per shape either function branches on. ``classify`` is asked with an
#: ``allowed_days`` deliberately unequal to ACCEPTED_WEAKNESS_DAYS, so a row
#: that agreed only because the two thresholds happened to coincide would show
#: up as a disagreement rather than hide.
_AGREEMENT_ROWS: tuple[tuple[str, _Poam], ...] = (
    ("declared young", _aged(3, status="risk_accepted")),
    ("declared old", _aged(600, status="risk_accepted")),
    ("declared undated", _Poam(status="risk_accepted")),
    ("active within window", _aged(10, status="open")),
    ("active past 192", _aged(258, status="in_progress")),
    ("active undated", _Poam(status="open")),
    (
        "reopened with a stale closed_on",
        _aged(258, status="open", closed_on=TODAY - timedelta(days=254)),
    ),
    (
        "cleanly closed",
        _aged(600, status="completed", closed_on=TODAY - timedelta(days=560)),
    ),
    (
        "closed before it was identified",
        _Poam(
            status="completed",
            identified_on=TODAY - timedelta(days=100),
            closed_on=TODAY - timedelta(days=200),
        ),
    ),
)

_ALLOWED_DAYS = 90


def test_the_two_functions_agree_on_which_rows_are_unmeasurable() -> None:
    """``unknown`` means the same thing in both, for every row.

    The branch orders are deliberately parallel, so a row one function can
    measure and the other cannot would mean one of them had grown a date
    comparison the other lacks -- the divergence this design exists to prevent.
    """
    saw_unknown = False
    for label, poam in _AGREEMENT_ROWS:
        bucket = classify(poam, allowed_days=_ALLOWED_DAYS, today=TODAY)
        state = accepted_weakness_state(poam, today=TODAY)
        if bucket == "unknown" or state == "unknown":
            saw_unknown = True
        assert (bucket == "unknown") == (state == "unknown"), (
            f"{label}: classify said {bucket!r} but accepted_weakness_state "
            f"said {state!r}"
        )
    assert saw_unknown, "the table lost its unmeasurable rows"


def test_the_two_functions_agree_on_declared_acceptance() -> None:
    """For a ``risk_accepted`` row -- and only there -- "accepted" is the same
    claim in both.

    The *elapsed* half is deliberately invisible to ``classify``: it measures an
    organization's own declared window, not FedRAMP's fixed 192 days, so an old
    open row is ``breached`` there and ``accepted`` here. That is the intended
    asymmetry, and the loop below asserts it rather than tolerating it.
    """
    saw_declared = False
    for label, poam in _AGREEMENT_ROWS:
        if poam.status != "risk_accepted":
            continue
        saw_declared = True
        bucket = classify(poam, allowed_days=_ALLOWED_DAYS, today=TODAY)
        state = accepted_weakness_state(poam, today=TODAY)
        assert (bucket == "accepted") == (state == "accepted"), (
            f"{label}: classify said {bucket!r} but accepted_weakness_state "
            f"said {state!r}"
        )
    assert saw_declared, "the table lost its risk_accepted rows"


def test_the_elapsed_half_is_invisible_to_classify() -> None:
    """The asymmetry named above, pinned so nobody wires the two together.

    An open row past 192 days is an Accepted Weakness under CR26 and a plain
    SLA breach against a 90-day organizational window. If these two ever agreed
    here, one function would have taken the other's threshold.
    """
    old_open = _aged(258, status="open")
    assert classify(old_open, allowed_days=_ALLOWED_DAYS, today=TODAY) == "breached"
    assert accepted_weakness_state(old_open, today=TODAY) == "accepted"
